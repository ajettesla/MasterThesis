#!/usr/bin/env python3

import os
import threading
import logging
from datetime import datetime
import yaml

# ---- Colors ----
RESET   = "\033[0m"
RED     = "\033[31m"
GREEN   = "\033[32m"
YELLOW  = "\033[33m"
BLUE    = "\033[34m"
CYAN    = "\033[36m"
MAGENTA = "\033[35m"
BOLD    = "\033[1m"

# Directory and filename template for state files (per experiment+concurrency)
STATE_DIR = "/tmp/exp"
STATE_FILENAME_TEMPLATE = "auto_state_{experiment_name}_{conc_str}.yaml"
# This global will be initialized at runtime via init_state_file()
STATE_FILE = None

# Default monitoring time in seconds
DEFAULT_MONITORING_TIME = 250

# Global constants for timestamp/user
CURRENT_TIMESTAMP = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
CURRENT_USER = os.getenv("USER", "unknown")

class ExperimentState:
    def __init__(self):
        self.current_experiment_name = None
        self.current_experiment_id   = None
        self.current_concurrency     = None
        self.current_iteration       = None
        self.monitoring_threads      = []
        self.monitoring_stop_events  = []
        self.original_stdout         = None
        self.original_stderr         = None
        self.log_file                = None
        self.demon_mode              = False
        self.quiet_mode = False  # Add this line

    def reset(self):
        """Reset the experiment state to initial values."""
        self.__init__()

# Global state instance
experiment_state = ExperimentState()

class ProgressTracker:
    """Centralized progress tracking for all monitored log files."""
    def __init__(self):
        self.file_stats        = {}
        self.lock              = threading.Lock()
        self.start_time        = 0
        self.last_full_display = 0
        self.display_interval  = 10  # seconds

    def update_file_progress(self, filename, prev_size, current_size,
                             line_count, total_bytes, update_display=False):
        with self.lock:
            self.file_stats[filename] = {
                'size': current_size,
                'prev_size': prev_size,
                'delta_size': current_size - prev_size,
                'lines': line_count,
                'total_bytes': total_bytes,
                'last_update': datetime.now(),
            }
            now_ts = datetime.now().timestamp()
            if update_display and (now_ts - self.last_full_display >= self.display_interval):
                self._display_full_progress()
                self.last_full_display = now_ts

    def force_display_progress(self):
        """Force an immediate display of all file progress."""
        with self.lock:
            self._display_full_progress()
            self.last_full_display = datetime.now().timestamp()

    def _display_full_progress(self):
        elapsed = datetime.now().timestamp() - self.start_time
        elapsed_min = elapsed / 60.0
        stats_lines = []
        total_size = total_delta = total_lines = 0

        for path, stats in self.file_stats.items():
            size = stats.get('size', 0)
            if size > 0:
                name     = os.path.basename(path)
                mb_size  = size / (1024 * 1024)
                mb_delta = stats['delta_size'] / (1024 * 1024)
                ln       = stats.get('lines', 0)
                stats_lines.append(
                    f"{name:<25} | {mb_size:7.2f}MB | +{mb_delta:7.2f}MB | Lines: {ln:7d}"
                )
                total_size  += size
                total_delta += stats['delta_size']
                total_lines += ln

        logging.info(f"\n[Progress] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | " +
                     f"Elapsed: {elapsed_min:.1f} minutes")
        logging.info("-" * 70)
        if stats_lines:
            for line in stats_lines:
                logging.info(line)
            logging.info("-" * 70)
            logging.info(
                f"TOTAL: {total_size/(1024*1024):.2f}MB | +" +
                f"{total_delta/(1024*1024):.2f}MB | Lines: {total_lines}"
            )

# Global progress tracker
progress_tracker = ProgressTracker()

def generate_experiment_id(length=5):
    """Generate a random alphanumeric identifier."""
    import string, random
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def init_state_file(experiment_name, concurrency_values):
    """
    Initialize the global STATE_FILE path based on experiment name and concurrency list.
    Must be called before load_experiment_state or save_experiment_state.
    """
    global STATE_FILE
    conc_str = "_".join(str(x) for x in concurrency_values)
    filename = STATE_FILENAME_TEMPLATE.format(
        experiment_name=experiment_name,
        conc_str=conc_str
    )
    STATE_FILE = os.path.join(STATE_DIR, filename)
    logging.info(f"[config] STATE_FILE set to: {STATE_FILE}")

def load_experiment_state():
    """
    Load experiment state from the YAML file.
    Returns a dict (possibly empty) if file missing or on error.
    """
    if not STATE_FILE:
        logging.error("load_experiment_state: STATE_FILE not initialized")
        return {}
    if not os.path.exists(STATE_FILE):
        return {}
    try:
        with open(STATE_FILE, 'r') as f:
            data = yaml.safe_load(f) or {}
        logging.info(f"[config] Loaded state from {STATE_FILE}: {data}")
        return data
    except Exception as e:
        logging.warning(f"[config] Failed to load state file {STATE_FILE}: {e}")
        return {}

def save_experiment_state(state):
    """
    Save experiment state dict to the YAML file.
    Returns True on success, False on failure.
    """
    if not STATE_FILE:
        logging.error("save_experiment_state: STATE_FILE not initialized")
        return False
    if 'name' not in state or 'concurrency' not in state:
        logging.error("save_experiment_state: Missing 'name' or 'concurrency' in state")
        return False
    try:
        with open(STATE_FILE, 'w') as f:
            yaml.safe_dump(state, f, default_flow_style=False)
        os.chmod(STATE_FILE, 0o666)
        logging.info(f"[config] Saved state to {STATE_FILE}")
        return True
    except Exception as e:
        logging.error(f"[config] Failed to save state file {STATE_FILE}: {e}")
        return False

def clear_experiment_state():
    """
    Remove the state file if it exists.
    Returns True if file removed or did not exist.
    """
    if not STATE_FILE:
        return True
    if os.path.exists(STATE_FILE):
        try:
            os.remove(STATE_FILE)
            logging.info(f"[config] Cleared state file {STATE_FILE}")
            return True
        except Exception as e:
            logging.error(f"[config] Failed to clear state file {STATE_FILE}: {e}")
            return False
    return True

def get_experiment_path(experiment_name, experiment_id, concurrency, iteration=None):
    """
    Get the directory path for logs of a given experiment, concurrency, and optional iteration.
    """
    base = f"/var/log/exp/{experiment_name}_{experiment_id}{concurrency}"
    return f"{base}/{iteration}" if iteration is not None else base

def colored(msg, color):
    """Wrap a message in ANSI color codes."""
    return f"{color}{msg}{RESET}"
