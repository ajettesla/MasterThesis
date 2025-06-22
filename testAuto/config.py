#!/usr/bin/env python3

import os
import string
import random
import json
import threading
import logging
from datetime import datetime

# ---- Colors ----
RESET  = "\033[0m"
RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
BLUE   = "\033[34m"
CYAN   = "\033[36m"
MAGENTA= "\033[35m"
BOLD   = "\033[1m"

# State file path for persistence between script executions
STATE_FILE = "/tmp/auto_experiment_state.json"

# Default monitoring time in seconds
DEFAULT_MONITORING_TIME = 250

# Current date/time and user - hardcoded from your provided values
CURRENT_TIMESTAMP = "2025-06-22 12:35:39"  # UTC time
CURRENT_USER = "ajettesla"  # Current user

# Global variables for experiment state
class ExperimentState:
    def __init__(self):
        self.current_experiment_name = None
        self.current_experiment_id = None
        self.current_concurrency = None
        self.current_iteration = None
        self.monitoring_threads = []
        self.monitoring_stop_events = []
        self.original_stdout = None
        self.original_stderr = None
        self.log_file = None
        self.demon_mode = False

    def reset(self):
        """Reset the experiment state"""
        self.current_experiment_name = None
        self.current_experiment_id = None
        self.current_concurrency = None
        self.current_iteration = None
        self.monitoring_threads = []
        self.monitoring_stop_events = []

# Initialize global state
experiment_state = ExperimentState()

# Progress tracking class
class ProgressTracker:
    """Centralized progress tracking for all log monitors"""
    def __init__(self):
        self.file_stats = {}
        self.lock = threading.Lock()
        self.start_time = 0
        self.last_full_display = 0
        self.display_interval = 10  # Update display every 10 seconds

    def update_file_progress(self, filename, prev_size, current_size, line_count, total_bytes, update_display=False):
        with self.lock:
            self.file_stats[filename] = {
                'size': current_size,
                'prev_size': prev_size,
                'delta_size': current_size - prev_size,
                'lines': line_count,
                'total_bytes': total_bytes,
                'last_update': datetime.now(),
            }
            
            # Only display if enough time has passed AND update_display is True
            current_time = datetime.now().timestamp()
            if update_display and (current_time - self.last_full_display >= self.display_interval):
                self._display_full_progress()
                self.last_full_display = current_time
    
    def force_display_progress(self):
        """Force display progress now"""
        with self.lock:
            self._display_full_progress()
            self.last_full_display = datetime.now().timestamp()
    
    def _display_full_progress(self):
        """Display progress for ALL monitored files in a simplified format"""
        elapsed = datetime.now().timestamp() - self.start_time
        elapsed_minutes = elapsed / 60.0
        
        # Collect stats for the files we're monitoring
        stats_message = []
        total_size = 0
        total_delta = 0
        total_lines = 0
        
        for filepath, stats in self.file_stats.items():
            if stats.get('size', 0) > 0:
                filename = os.path.basename(filepath)
                size_mb = stats.get('size', 0) / (1024 * 1024)
                delta_mb = stats.get('delta_size', 0) / (1024 * 1024)
                lines = stats.get('lines', 0)
                
                stats_message.append(f"{filename:<25} | {size_mb:7.2f}MB | +{delta_mb:7.2f}MB | Lines: {lines:7d}")
                
                total_size += stats.get('size', 0)
                total_delta += stats.get('delta_size', 0)
                total_lines += lines
        
        # Print a simple progress report
        logging.info(f"\n[Progress] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Elapsed: {elapsed_minutes:.1f} minutes")
        logging.info("-" * 70)
        
        # Only show file stats and total if we have data
        if stats_message:
            for line in stats_message:
                logging.info(line)
            logging.info("-" * 70)
            
            total_size_mb = total_size / (1024 * 1024)
            total_delta_mb = total_delta / (1024 * 1024)
            logging.info(f"TOTAL: {total_size_mb:.2f}MB | +{total_delta_mb:.2f}MB | Lines: {total_lines}")

# Global progress tracker
progress_tracker = ProgressTracker()

def generate_experiment_id(length=5):
    """Generate a random alphanumeric identifier for the experiment"""
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def load_experiment_state():
    """Load experiment state from file"""
    if not os.path.exists(STATE_FILE):
        return None
    
    try:
        with open(STATE_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        logging.warning(f"Failed to load state file {STATE_FILE}")
        return None

def save_experiment_state(state):
    """Save experiment state to file"""
    try:
        with open(STATE_FILE, 'w') as f:
            json.dump(state, f, indent=2)
        # Make the file readable/writable by all users
        os.chmod(STATE_FILE, 0o666)
        logging.info(f"Saved experiment state to {STATE_FILE}")
        return True
    except IOError as e:
        logging.error(f"Failed to save state file {STATE_FILE}: {e}")
        return False

def clear_experiment_state():
    """Clear experiment state file"""
    if os.path.exists(STATE_FILE):
        try:
            os.remove(STATE_FILE)
            logging.info(f"Cleared experiment state file {STATE_FILE}")
            return True
        except IOError as e:
            logging.error(f"Failed to clear state file {STATE_FILE}: {e}")
            return False
    return True

def get_experiment_path(experiment_name, experiment_id, concurrency, iteration=None):
    """Get path for experiment with ID included"""
    base_path = f"/var/log/exp/{experiment_name}_{experiment_id}{concurrency}"
    if iteration:
        return f"{base_path}/{iteration}"
    return base_path

def colored(msg, color):
    """Return text with ANSI color codes"""
    return f"{color}{msg}{RESET}"
