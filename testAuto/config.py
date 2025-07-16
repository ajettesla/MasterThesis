#!/usr/bin/env python3

import os
import threading
import logging
from datetime import datetime
import yaml
import sys

# Directory and filename template for state files (per experiment+concurrency)
STATE_DIR = "/tmp/exp"
STATE_FILENAME_TEMPLATE = "auto_state_{experiment_name}_{conc_str}.yaml"
STATE_FILE = None

# Default monitoring time in seconds
DEFAULT_MONITORING_TIME = 600

CURRENT_TIMESTAMP = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
CURRENT_USER = os.getenv("USER", "unknown")

# Global automation mode instance
automation_mode = None

def set_automation_mode(mode_instance):
    """Set the global automation mode instance"""
    global automation_mode
    automation_mode = mode_instance
    
    # Log the active mode for debugging
    if automation_mode:
        mode_type = "super" if automation_mode.super_mode else "quiet" if automation_mode.quiet_mode else "normal"
        logging.debug(f"Automation mode set to: {mode_type}")

def get_automation_mode():
    """Get the current automation mode instance"""
    return automation_mode

def print_step(step, status, details=None):
    """Print step with automation mode awareness"""
    try:
        if automation_mode and automation_mode.quiet_mode:
            # Quiet mode: only store for summary, no stdout except critical failures
            if hasattr(automation_mode, 'results'):
                msg = f"{step}: {status}" + (f" - {details}" if details else "")
                automation_mode.results.append(f"[STEP] {msg}")
            # Only print FAILED status in quiet mode
            if status == "FAILED" or status == "ERROR" or status == "WARNING":
                msg = f"FAILED: {step}" + (f" - {details}" if details else "")
                print(msg, flush=True)
            return
        
        # Normal and super modes: full output
        timestamp = datetime.now().strftime("%H:%M:%S")
        msg = f"[{timestamp}] {step}: {status}"
        if details:
            msg += f" - {details}"
        
        if automation_mode:
            automation_mode.log_message(f"STEP: {step}: {status}" + (f" - {details}" if details else ""), 'debug')
            if automation_mode.super_mode:
                print(msg, flush=True)
            else:
                print(msg, flush=True)
        else:
            print(msg, flush=True)
    except Exception as e:
        # Ensure we never fail to print a FAILED message due to an error in this function
        error_msg = f"ERROR in print_step: {str(e)}"
        logging.error(error_msg)
        if status == "FAILED" or status == "ERROR" or status == "WARNING":
            print(f"FAILED: {step} - {details if details else ''}", flush=True)
            print(error_msg, flush=True)

def print_status(message):
    """Print status with automation mode awareness"""
    if automation_mode:
        automation_mode.log_message(f"STATUS: {message}", 'debug')
        
        if automation_mode.quiet_mode:
            # Quiet mode: only show critical messages
            if hasattr(automation_mode, 'results'):
                automation_mode.results.append(f"[STATUS] {message}")
            if any(keyword in message for keyword in ["ERROR", "FAILURE", "FAILED"]):
                print(message, flush=True)
            return
        
        # Normal and super modes
        if automation_mode.super_mode:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] {message}")
        else:
            print(message, flush=True)
    else:
        print(message, flush=True)

def log_debug(message):
    """Log debug message through automation mode
    
    In super mode: Log to file, print to stdout only if not quiet mode
    In normal mode: Log to file only, no stdout
    In quiet mode: Store in debug collection, no stdout
    """
    if automation_mode:
        # In quiet mode, only log to file, don't print to stdout
        if automation_mode.quiet_mode:
            logging.debug(message)
            # Store for final summary if applicable
            if hasattr(automation_mode, 'debug_logs'):
                automation_mode.debug_logs.append(message)
        else:
            # Normal mode behavior
            automation_mode.log_message(message, 'debug')
    else:
        logging.debug(message)

def log_info(message):
    """Log info message through automation mode
    
    In super mode: Log to file, print to stdout only if not quiet mode
    In normal mode: Log to file, print important info to stdout if not quiet
    In quiet mode: Store in results collection for summary, no stdout
    """
    if automation_mode:
        # In quiet mode, only log to file, don't print to stdout
        if automation_mode.quiet_mode:
            logging.info(message)
            # Store for final summary
            if hasattr(automation_mode, 'results'):
                automation_mode.results.append(f"[INFO] {message}")
        else:
            # Normal mode behavior
            automation_mode.log_message(message, 'info')
    else:
        logging.info(message)

def log_warning(message):
    """Log warning message through automation mode
    
    All modes: Print to stdout (important enough to always show)
    """
    if automation_mode:
        automation_mode.log_message(message, 'warning')
        
        # Warnings are important enough to show in all modes
        if message.strip():
            print(f"WARNING: {message}", flush=True)
    else:
        logging.warning(message)

def log_error(message):
    """Log error message through automation mode
    
    All modes: Print to stdout (critical to always show)
    """
    if automation_mode:
        automation_mode.log_message(message, 'error')
        
        # Errors are critical enough to show in all modes
        if message.strip():
            print(f"ERROR: {message}", flush=True)
    else:
        logging.error(message)

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
        self.log_file_path           = None
        self.demon_mode              = False

    def reset(self):
        """Reset the experiment state to initial values."""
        self.__init__()

experiment_state = ExperimentState()

class ProgressTracker:
    def __init__(self):
        self.file_stats        = {}
        self.lock              = threading.Lock()
        self.start_time        = 0
        self.last_full_display = 0
        self.last_console_display = 0
        self.display_interval  = 10  # seconds
        self.console_interval  = 30  # seconds for console updates

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
            if now_ts - self.last_console_display >= self.console_interval:
                self._display_console_progress()
                self.last_console_display = now_ts

    def force_display_progress(self):
        with self.lock:
            self._display_full_progress()
            self._display_console_progress()
            self.last_full_display = datetime.now().timestamp()
            self.last_console_display = datetime.now().timestamp()

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

        # Log the progress details based on mode
        if automation_mode:
            # Always log progress to debug level
            automation_mode.log_message(
                f"\n[Progress] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | " +
                f"Elapsed: {elapsed_min:.1f} minutes", 'debug'
            )
            
            # In super mode AND NOT quiet mode, print detailed progress
            if automation_mode.super_mode and not automation_mode.quiet_mode:
                print(f"\n=== Progress: {elapsed_min:.1f} minutes elapsed ===")
                if stats_lines:
                    print("-" * 70)
                    for line in stats_lines:
                        print(line)
                    print("-" * 70)
                    print(f"TOTAL: {total_size/(1024*1024):.2f}MB | +" +
                          f"{total_delta/(1024*1024):.2f}MB | Lines: {total_lines}")
        else:
            # Legacy behavior
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
    
    def _display_console_progress(self):
        """Display progress summary to console based on mode"""
        elapsed = datetime.now().timestamp() - self.start_time
        elapsed_min = elapsed / 60.0
        
        file_count = len(self.file_stats)
        total_size = sum(stats.get('size', 0) for _, stats in self.file_stats.items())
        total_lines = sum(stats.get('lines', 0) for _, stats in self.file_stats.items())
        
        if file_count > 0:
            progress_msg = f"Progress: {elapsed_min:.1f} min | Files: {file_count} | " + \
                          f"Size: {total_size/(1024*1024):.2f}MB | Lines: {total_lines}"
            
            if automation_mode:
                if automation_mode.quiet_mode:
                    # Don't print to stdout in quiet mode
                    if hasattr(automation_mode, 'results'):
                        automation_mode.results.append(f"[PROGRESS] {progress_msg}")
                elif automation_mode.super_mode:
                    # Super mode: Add timestamp and stats
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    print(f"[{timestamp}] {progress_msg}", flush=True)
                else:
                    # Normal mode: Simple progress to stdout
                    print(progress_msg, flush=True)
            else:
                # Legacy behavior
                print_status(progress_msg)

    def get_consolidated_file_stats(self):
        """Get consolidated file stats in a format ready for display"""
        stats_list = []
        with self.lock:
            for path, stats in self.file_stats.items():
                size = stats.get('size', 0)
                if size > 0:
                    name = os.path.basename(path)
                    mb_size = size / (1024 * 1024)
                    mb_delta = stats['delta_size'] / (1024 * 1024)
                    ln = stats.get('lines', 0)
                    stats_list.append({
                        "filename": name,
                        "path": path,
                        "mb_size": mb_size,
                        "mb_delta": mb_delta,
                        "lines": ln
                    })
        return stats_list

progress_tracker = ProgressTracker()

def generate_experiment_id(length=5):
    import string, random
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def generate_experiment_folder_name(experiment_name, concurrency, experiment_id):
    """Generate a standardized folder name for an experiment."""
    return f"{experiment_name}_c{concurrency}_{experiment_id}"

def init_state_file(experiment_name, concurrency_values):
    global STATE_FILE
    conc_str = "_".join(str(x) for x in concurrency_values)
    filename = STATE_FILENAME_TEMPLATE.format(
        experiment_name=experiment_name,
        conc_str=conc_str
    )
    folder_name = f"{experiment_name}_{conc_str}"
    state_dir = os.path.join(STATE_DIR, folder_name)
    os.makedirs(state_dir, exist_ok=True)
    
    STATE_FILE = os.path.join(state_dir, filename)
    log_debug(f"[config] STATE_FILE set to: {STATE_FILE}")
    
    # Only print in super mode
    if automation_mode and automation_mode.super_mode and not automation_mode.quiet_mode:
        print(f"State file initialized: {STATE_FILE}")

def load_experiment_state():
    if not STATE_FILE:
        error_msg = "load_experiment_state: STATE_FILE not initialized"
        log_error(error_msg)
        print_status(f"ERROR: {error_msg}")
        return {}
        
    if not os.path.exists(STATE_FILE):
        return {}
        
    try:
        with open(STATE_FILE, 'r') as f:
            data = yaml.safe_load(f) or {}
        log_debug(f"[config] Loaded state from {STATE_FILE}: {data}")
        return data
    except Exception as e:
        error_msg = f"Failed to load state file {STATE_FILE}: {e}"
        log_warning(f"[config] {error_msg}")
        print_status(f"WARNING: {error_msg}")
        return {}

def save_experiment_state(state):
    """Save experiment state with improved error reporting"""
    if not STATE_FILE:
        error_msg = "save_experiment_state: STATE_FILE not initialized"
        log_error(error_msg)
        print_status(f"ERROR: {error_msg}")
        return False
        
    if 'name' not in state or 'concurrency' not in state:
        error_msg = "save_experiment_state: Missing 'name' or 'concurrency' in state"
        log_error(error_msg)
        print_status(f"ERROR: {error_msg}")
        return False
        
    try:
        with open(STATE_FILE, 'w') as f:
            yaml.safe_dump(state, f, default_flow_style=False)
        os.chmod(STATE_FILE, 0o666)
        log_debug(f"[config] Saved state to {STATE_FILE}")
        
        # Only show in super mode
        if automation_mode and automation_mode.super_mode and not automation_mode.quiet_mode:
            print(f"State saved to {STATE_FILE}", flush=True)
            
        return True
    except Exception as e:
        error_msg = f"Failed to save state file {STATE_FILE}: {e}"
        log_error(f"[config] {error_msg}")
        print_status(f"FAILED: {error_msg}")
        return False

def clear_experiment_state():
    if not STATE_FILE:
        return True
        
    if os.path.exists(STATE_FILE):
        try:
            os.remove(STATE_FILE)
            log_debug(f"[config] Cleared state file {STATE_FILE}")
            
            # Print based on mode
            if automation_mode:
                if automation_mode.super_mode:
                    print(f"Cleared state file: {STATE_FILE} ")
                elif not automation_mode.quiet_mode:
                    print(f"Cleared state file")
            else:
                print_status(f"Cleared state file: {STATE_FILE}")
                
            return True
        except Exception as e:
            error_msg = f"Failed to clear state file {STATE_FILE}: {e}"
            log_error(f"[config] {error_msg}")
            print_status(f"ERROR: {error_msg}")
            return False
    return True

def get_experiment_path(experiment_name, experiment_id, concurrency, iteration=None):
    base = f"/var/log/exp/{experiment_name}_c{concurrency}_{experiment_id}"
    return f"{base}/{iteration}" if iteration is not None else base
