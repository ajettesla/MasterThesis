#!/usr/bin/env python3

import os
import sys
import time
import logging
import threading
import subprocess
import socket
import re
import getpass
from datetime import datetime
import builtins
import select

from config import (
    progress_tracker, experiment_state, log_debug, log_info, log_warning, log_error, get_automation_mode
)

class FileOnlyHandler(logging.Handler):
    """Handler that only writes to log file, not to stdout"""
    def __init__(self, filename):
        super().__init__()
        self.filename = filename
        self.file_handler = logging.FileHandler(filename)

    def emit(self, record):
        self.file_handler.emit(record)

    def close(self):
        self.file_handler.close()
        super().close()

def configure_logging(log_file=None):
    # Check if automation mode is active
    automation_mode = get_automation_mode()
    if automation_mode:
        # Let automation mode handle logging configuration
        return
    
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'
    root = logging.getLogger()
    for h in root.handlers[:]:
        root.removeHandler(h)
    root.setLevel(logging.DEBUG)
    if log_file:
        fh = logging.FileHandler(log_file)
        formatter = logging.Formatter(log_format, date_format)
        fh.setFormatter(formatter)
        root.addHandler(fh)
    for logger_name in ['paramiko', 'paramiko.transport', 'paramiko.client', 'urllib3', 'requests']:
        third_party_logger = logging.getLogger(logger_name)
        third_party_logger.propagate = False
        third_party_logger.setLevel(logging.WARNING)
        if log_file:
            third_party_logger.addHandler(fh)
    logging.getLogger().handlers = [h for h in logging.getLogger().handlers if not isinstance(h, logging.StreamHandler) or h.stream != sys.stdout]
    def handle_ex(exc_type, exc_val, exc_tb):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_val, exc_tb)
            return
        logging.error("Uncaught exception", exc_info=(exc_type, exc_val, exc_tb))
        print(f"ERROR: Uncaught exception: {exc_val}", file=sys.__stderr__)
    sys.excepthook = handle_ex

def get_current_hostname():
    try:
        return subprocess.check_output(['hostname'], text=True).strip()
    except Exception:
        return socket.gethostname()

def setup_logging(experiment_name, experiment_id, demon, timestamp, user):
    # Check if automation mode is active
    automation_mode = get_automation_mode()
    if automation_mode:
        if automation_mode.super_mode:
            # Super mode handles its own logging
            log_info(f"Using super mode logging: {automation_mode.log_file}")
            return automation_mode.log_file
        elif automation_mode.quiet_mode:
            # Quiet mode - minimal logging to stdout
            log_debug("Using quiet mode logging (minimal stdout)")
        else:
            # Normal mode - standard logging
            log_debug("Using normal mode logging (standard stdout)")
    
    experiment_state.demon_mode = demon
    conc = getattr(experiment_state, "current_concurrency", None)
    it  = getattr(experiment_state, "current_iteration",   None)
    part_c = f"_C{conc}" if conc is not None else ""
    part_i = f"_it{it}"  if it  is not None else ""
    path = f"/tmp/exp/{experiment_name}_{experiment_id}{part_c}{part_i}_auto.log"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    experiment_state.log_file_path = path
    configure_logging(log_file=path)
    logging.info("=== Experiment Log ===")
    logging.info(f"Experiment: {experiment_name}")
    logging.info(f"Experiment ID: {experiment_id}")
    logging.info(f"Timestamp: {timestamp}")
    logging.info(f"User: {user}")
    if conc is not None:
        logging.info(f"Concurrency: {conc}")
    if it is not None:
        logging.info(f"Iteration: {it}")
    logging.info("========================")
    
    # Print to stdout based on mode
    automation_mode = get_automation_mode()
    if not automation_mode or not automation_mode.quiet_mode:
        print(f"Log file: {path}")
    
    return path

def cleanup_logging():
    if not getattr(experiment_state, "demon_mode", False):
        return
    log = logging.getLogger()
    for h in log.handlers[:]:
        try:
            h.close()
        except:
            pass
        log.removeHandler(h)
    experiment_state.demon_mode = False

def check_and_clear_memory_usage():
    try:
        import psutil
        mem = psutil.virtual_memory().percent
        if mem > 85:
            log_warning(f"High memory usage: {mem}%. Clearing caches...")
            import gc; gc.collect()
            try:
                proc = psutil.Process()
                if hasattr(proc, 'memory_info'):
                    before = proc.memory_info().rss / 1024 / 1024
                    if sys.platform.startswith('linux'):
                        subprocess.run("sync", shell=True)
                        with open("/proc/sys/vm/drop_caches", "w") as f:
                            f.write("1")
                    after = proc.memory_info().rss / 1024 / 1024
                    
                    # Log based on mode
                    automation_mode = get_automation_mode()
                    if automation_mode and automation_mode.super_mode:
                        log_info(f"Memory usage reduced from {before:.1f}MB to {after:.1f}MB")
                    elif automation_mode and not automation_mode.quiet_mode:
                        print(f"Memory cleaned: {before-after:.1f}MB freed")
            except:
                pass
        return mem
    except ImportError:
        return None
    except Exception as e:
        log_error(f"Error checking memory: {e}")
        return None

class SimpleProgressDisplay(threading.Thread):
    def __init__(self, stop_event):
        super().__init__(daemon=True)
        self.stop_event = stop_event
        self.name = "SimpleProgressDisplay"
        self.last_connt1 = 0
        self.last_connt2 = 0
        self.ssh_connector = None
        self.clients = {}
        
        # Added fields for condition tracking
        self.initial_csv_count = None
        self.last_csv_check_time = 0
        self.csv_check_interval = 5  # Check CSV growth every 5 seconds
        self.csv_check_file = None
        self.csv_check_host = None
        self.csv_condition_met = False
        
        # Store current conntrack counts to avoid duplicate queries
        self.current_connt1_count = 0
        self.current_connt2_count = 0
        self.initial_conntrack_counts = {}
        self.last_conntrack_check_time = 0
        self.conntrack_check_interval = 5  # Check conntrack every 5 seconds
        self.conntrack_condition_met = False
        
        # Display intervals based on mode
        self.automation_mode = get_automation_mode()
        if self.automation_mode:
            if self.automation_mode.super_mode:
                self.display_interval = 10  # Super mode: more frequent updates
            elif self.automation_mode.quiet_mode:
                self.display_interval = 40  # Quiet mode: update every 40 seconds (changed from 60)
            else:
                self.display_interval = 30  # Normal mode: standard updates
        else:
            self.display_interval = 30  # Default interval

    def __del__(self):
        self.close_connections()

    def close_connections(self):
        for host, client in self.clients.items():
            if client:
                try:
                    client.close()
                except:
                    pass
        self.clients.clear()

    def get_conntrack_count(self, host):
        from ssh_utils import SSHConnector, run_command_locally, run_command_with_timeout
        if self.ssh_connector is None:
            self.ssh_connector = SSHConnector()
        if host not in self.clients:
            self.clients[host] = self.ssh_connector.connect(host)
        client = self.clients[host]
        cmd = "sudo conntrack -C"
        if client is None:
            status, out, _ = run_command_locally(cmd, f"[{host}]")
        else:
            try:
                status, out = run_command_with_timeout(client, cmd, 5, hostname=host)
            except:
                self.clients[host] = self.ssh_connector.connect(host)
                client = self.clients[host]
                if client:
                    status, out = run_command_with_timeout(client, cmd, 5, hostname=host)
                else:
                    status, out = False, "0"
        try:
            return int(out.strip()) if status and out.strip().isdigit() else 0
        except:
            return 0
    
    def get_csv_line_count(self, filepath, host):
        """Get the line count of a CSV file on a remote host"""
        from ssh_utils import run_command_locally, run_command_with_timeout
        
        if host not in self.clients:
            if self.ssh_connector is None:
                self.ssh_connector = SSHConnector()
            self.clients[host] = self.ssh_connector.connect(host)
            
        client = self.clients[host]
        tag = f"[{host} ssh]" if client else f"[{host} localhost]"
        cmd_count = f"wc -l {filepath} 2>/dev/null | awk '{{print $1}}'"
        
        if client is None:
            status, output, stderr = run_command_locally(cmd_count, tag)
        else:
            status, output = run_command_with_timeout(client, cmd_count, 5, hostname=host)
        
        if not status or not output.strip():
            log_debug(f"[monitor] {tag} Failed to get line count for {filepath}")
            return None
        
        try:
            return int(output.strip())
        except (ValueError, TypeError):
            log_debug(f"[monitor] {tag} Failed to parse line count: {output}")
            return None
    
    def check_csv_growth_condition(self, filepath, host):
        """Check if CSV file growth is less than 5 lines in the last interval"""
        current_time = time.time()
        if current_time - self.last_csv_check_time < self.csv_check_interval:
            return self.csv_condition_met  # Return last result if checking too frequently
        
        self.last_csv_check_time = current_time
        self.csv_check_file = filepath
        self.csv_check_host = host
        
        current_count = self.get_csv_line_count(filepath, host)
        if current_count is None:
            return False
            
        if self.initial_csv_count is None:
            # First check, just store the count
            self.initial_csv_count = current_count
            log_debug(f"[monitor] Initial CSV line count: {self.initial_csv_count}")
            return False
            
        # Calculate delta
        delta = current_count - self.initial_csv_count
        log_info(f"[monitor] CSV file delta: {delta} lines")
        
        # Reset initial count for next check
        self.initial_csv_count = current_count
        
        # Show detailed info in super mode or consolidated in quiet mode
        if self.automation_mode:
            if self.automation_mode.super_mode and not self.automation_mode.quiet_mode:
                print(f"CSV file growth on {host}: {delta} lines in last interval", flush=True)
            elif self.automation_mode.quiet_mode:
                # In quiet mode, store for later consolidated display
                pass
        
        # Condition met if delta < 5
        self.csv_condition_met = delta < 5
        return self.csv_condition_met
    
    def check_conntrack_delta_condition(self):
        """Check if conntrack entries delta is less than 100 in the last interval"""
        current_time = time.time()
        if current_time - self.last_conntrack_check_time < self.conntrack_check_interval:
            return self.conntrack_condition_met  # Return last result if checking too frequently
            
        self.last_conntrack_check_time = current_time
        
        # Use already fetched conntrack counts from run() method
        current_counts = {
            "connt1": self.current_connt1_count,
            "connt2": self.current_connt2_count
        }
            
        if not self.initial_conntrack_counts:
            # First check, just store the counts
            self.initial_conntrack_counts = current_counts.copy()
            log_debug(f"[monitor] Initial conntrack counts: {self.initial_conntrack_counts}")
            return False
            
        # Calculate deltas
        delta_connt1 = abs(current_counts.get("connt1", 0) - self.initial_conntrack_counts.get("connt1", 0))
        delta_connt2 = abs(current_counts.get("connt2", 0) - self.initial_conntrack_counts.get("connt2", 0))
        total_delta = delta_connt1 + delta_connt2
        
        log_info(f"[monitor] Conntrack delta - connt1: {delta_connt1}, connt2: {delta_connt2}, total: {total_delta}")
        
        # Reset initial counts for next check
        self.initial_conntrack_counts = current_counts.copy()
        
        # Show detailed info in super mode
        if self.automation_mode and self.automation_mode.super_mode:
            print(f"Conntrack entries delta - connt1: {delta_connt1}, connt2: {delta_connt2}, total: {total_delta}", flush=True)
        
        # Condition met if total delta < 100
        self.conntrack_condition_met = total_delta < 100
        return self.conntrack_condition_met

    def run(self):
        last_display_time = time.time()
        
        try:
            while not self.stop_event.is_set():
                current_time = time.time()
                
                try:
                    self.current_connt1_count = self.get_conntrack_count("connt1")
                    self.current_connt2_count = self.get_conntrack_count("connt2")
                    c1 = self.current_connt1_count
                    c2 = self.current_connt2_count
                    d1 = c1 - self.last_connt1
                    d2 = c2 - self.last_connt2
                    self.last_connt1, self.last_connt2 = c1, c2
                    
                    # Only display based on the configured interval
                    if current_time - last_display_time >= self.display_interval:
                        automation_mode = self.automation_mode
                        
                        if automation_mode:
                            if automation_mode.super_mode and not automation_mode.quiet_mode:
                                # Super mode: detailed progress
                                print(f"Progress: connt1={c1} (delta: {d1:+d}), connt2={c2} (delta: {d2:+d})", flush=True)
                                if self.csv_check_file:
                                    print(f"CSV condition: {'Met' if self.csv_condition_met else 'Not met'}", flush=True)
                                if self.initial_conntrack_counts:
                                    print(f"Conntrack condition: {'Met' if self.conntrack_condition_met else 'Not met'}", flush=True)
                            elif automation_mode.quiet_mode:
                                # Quiet mode: condensed single line progress with all info
                                csv_stats = progress_tracker.get_consolidated_file_stats()
                                # Format a compact single line with all file info and conntrack counts
                                file_parts = []
                                total_lines = 0
                                total_mb = 0
                                
                                for stat in csv_stats:
                                    name = stat.get("filename", "unknown")
                                    host_prefix = ""
                                    if ":" in stat.get("path", ""):
                                        host_prefix = stat.get("path", "").split(":")[0] + ":"
                                    mb_size = stat.get("mb_size", 0)
                                    total_mb += mb_size
                                    lines = stat.get("lines", 0)
                                    total_lines += lines
                                    
                                    if name.endswith("_ca.csv"):
                                        # Main CSV gets more details
                                        file_parts.append(f"{name}:{mb_size:.2f}MB/L{lines}")
                                    else:
                                        # Other files just simple stats
                                        file_parts.append(f"{host_prefix}{name}:{lines}")
                                
                                condition1 = "Met" if self.csv_condition_met else "Not met"
                                condition2 = "Met" if self.conntrack_condition_met else "Not met"
                                
                                # Single line compact format with all info
                                print(f"PROGRESS: {total_mb:.2f}MB/{total_lines} lines | " +
                                      f"Files: {' '.join(file_parts)} | " +
                                      f"connt1:{c1} connt2:{c2} | " +
                                      f"C1:{condition1} C2:{condition2}", flush=True)
                                
                            elif not automation_mode.quiet_mode:
                                # Normal mode: simplified progress
                                print(f"Progress: connt1={c1}, connt2={c2}", flush=True)
                        
                        last_display_time = current_time
                    
                    check_and_clear_memory_usage()
                    self.stop_event.wait(1)
                    
                except Exception as e:
                    log_error(f"Error in progress display: {e}")
                    time.sleep(5)
        finally:
            self.close_connections()

class LogMonitorHandler(threading.Thread): 
    def __init__(self, filepath, keywords, print_output, stop_event, result_dict, progress_callback=None):
        super().__init__()
        self.filepath = filepath
        self.keywords = keywords
        self.match_mode = bool(keywords)
        self.seen_keywords = set()
        self.new_line_count = 0
        self.total_bytes_read = 0
        self.last_size = 0
        self.print_output = print_output
        self.stop_event = stop_event
        self.result_dict = result_dict
        self.progress_callback = progress_callback
        self.current_host = get_current_hostname()
        self.proc = None
        self.last_progress_time = time.time()
        self.progress_interval = 10
        
    def get_file_size(self):
        try:
            result = subprocess.run(['sudo', 'stat', '-c', '%s', self.filepath], 
                                    capture_output=True, text=True)
            if result.returncode == 0:
                return int(result.stdout.strip())
        except:
            pass
        return 0

    def read_file_from_position(self, position):
        try:
            result = subprocess.run(['sudo', 'tail', '-c', f'+{position + 1}', self.filepath], 
                                    capture_output=True, text=True, errors='ignore')
            if result.returncode == 0:
                return result.stdout
        except Exception as e:
            log_error(f"[{self.current_host} local check] Error reading file: {e}")
        return ""

    def update_progress_silent(self, current_size):
        if self.progress_callback:
            try:
                self.progress_callback(
                    os.path.basename(self.filepath),
                    self.last_size,
                    current_size,
                    self.new_line_count,
                    self.total_bytes_read,
                    update_display=False
                )
            except Exception as e:
                log_error(f"Progress callback error: {e}")
        self.last_size = current_size

    def update_progress_with_display(self, current_size):
        current_time = time.time()
        if current_time - self.last_progress_time >= self.progress_interval:
            if self.progress_callback:
                try:
                    self.progress_callback(
                        os.path.basename(self.filepath),
                        self.last_size,
                        current_size,
                        self.new_line_count,
                        self.total_bytes_read,
                        update_display=True
                    )
                except Exception as e:
                    log_error(f"Progress callback error: {e}")
            self.last_size = current_size
            self.last_progress_time = current_time

    def terminate_process_safely(self):
        if self.proc and self.proc.poll() is None:
            try:
                subprocess.run(['sudo', 'kill', str(self.proc.pid)], 
                               capture_output=True, timeout=5)
                try:
                    self.proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    subprocess.run(['sudo', 'kill', '-9', str(self.proc.pid)], 
                                   capture_output=True, timeout=5)
            except Exception as e:
                log_warning(f"[{self.current_host} local check] Note: Could not terminate inotifywait process cleanly: {e}")

    def run(self):
        try:
            subprocess.run(['which', 'inotifywait'], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            log_error(f"[{self.current_host} local check] inotifywait not found. Please install inotify-tools")
            return

        if not os.path.exists(self.filepath):
            try:
                os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
                subprocess.run(['sudo', 'touch', self.filepath], check=True)
                log_warning(f"[{self.current_host} local check] Created file {self.filepath}")
            except Exception as e:
                log_error(f"[{self.current_host} local check] Could not create file {self.filepath}: {e}")
                return

        try:
            self.proc = subprocess.Popen(
                ['sudo', 'inotifywait', '-m', '-e', 'modify', '-e', 'create', self.filepath],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Log based on automation mode
            automation_mode = get_automation_mode()
            if automation_mode:
                if automation_mode.super_mode:
                    log_info(f"[{self.current_host} local check] Started inotifywait monitoring for {os.path.basename(self.filepath)} (detailed mode)")
                else:
                    log_debug(f"[{self.current_host} local check] Started inotifywait monitoring for {os.path.basename(self.filepath)}")
            else:
                log_info(f"[{self.current_host} local check] Started inotifywait monitoring for {os.path.basename(self.filepath)}")
                
        except Exception as e:
            log_error(f"[{self.current_host} local check] Failed to start inotifywait: {e}")
            return

        last_position = self.get_file_size()
        self.last_size = last_position
        self.total_bytes_read = last_position
        self.update_progress_silent(last_position)

        try:
            while not self.stop_event.is_set():
                if self.proc.poll() is not None:
                    log_error(f"[{self.current_host} local check] inotifywait process terminated unexpectedly for {os.path.basename(self.filepath)}")
                    break
                rlist, _, _ = select.select([self.proc.stdout], [], [], 0.5)
                if rlist:
                    line = self.proc.stdout.readline()
                    if line and ('MODIFY' in line or 'CREATE' in line):
                        current_size = self.get_file_size()
                        new_content = self.read_file_from_position(last_position)
                        if new_content:
                            new_lines = new_content.splitlines()
                            lines_added = len(new_lines)
                            bytes_read = len(new_content.encode('utf-8'))
                            self.total_bytes_read += bytes_read
                            if not self.match_mode:
                                self.new_line_count += lines_added
                            last_position = current_size
                            
                            # Process lines based on mode
                            automation_mode = get_automation_mode()
                            for log_line in new_lines:
                                original_line = log_line
                                log_line = log_line.strip()
                                if self.match_mode and log_line:
                                    for kw in self.keywords:
                                        if kw in log_line and kw not in self.seen_keywords:
                                            self.seen_keywords.add(kw)
                                            
                                            # Log keyword match based on mode
                                            if automation_mode:
                                                if automation_mode.super_mode:
                                                    log_info(f"[{self.current_host} local check] MATCH found keyword: '{kw}'")
                                                elif not automation_mode.quiet_mode:
                                                    print(f"Keyword matched: '{kw}'")
                                                # In quiet mode, we store this for summary but don't print
                                            else:
                                                log_info(f"[{self.current_host} local check] MATCH found keyword: '{kw}'")
                                                
                                if self.print_output and original_line:
                                    # Print based on mode
                                    if automation_mode:
                                        if automation_mode.super_mode:
                                            log_info(f"[{self.current_host} local check] LOG: {original_line}")
                                        elif not automation_mode.quiet_mode:
                                            print(f"Log: {original_line}")
                                        # In quiet mode, we don't print logs
                                    else:
                                        log_info(f"[{self.current_host} local check] LOG: {original_line}")
                    
                    self.update_progress_with_display(current_size)
                    if self.match_mode and self.seen_keywords == self.keywords:
                        # All keywords matched
                        if automation_mode:
                            if automation_mode.super_mode:
                                log_info(f"[{self.current_host} local check] All keywords matched. Stopping monitor.")
                            elif not automation_mode.quiet_mode:
                                print("All keywords matched")
                        else:
                            log_info(f"[{self.current_host} local check] All keywords matched. Stopping monitor.")
                        
                        if self.result_dict is not None:
                            self.result_dict[threading.current_thread().name] = len(self.seen_keywords)
                        self.stop_event.set()
                        break
                else:
                    current_size = self.get_file_size()
                    self.update_progress_silent(current_size)
                time.sleep(0.1)
        finally:
            self.terminate_process_safely()
            
            # Log completion based on mode
            automation_mode = get_automation_mode()
            if automation_mode:
                if automation_mode.super_mode:
                    log_info(f"[{self.current_host} local check] inotifywait monitoring stopped for {os.path.basename(self.filepath)}")
                elif not automation_mode.quiet_mode:
                    print(f"Monitoring stopped: {os.path.basename(self.filepath)}")
            else:
                log_info(f"[{self.current_host} local check] inotifywait monitoring stopped for {os.path.basename(self.filepath)}")

def monitor_log_file_watchdog(
    filepath: str,
    keyword_expr: str = "",
    timeout: int = None,
    print_output: bool = True,
    result_dict: dict = None,
    stop_event: threading.Event = None,
):
    current_host = get_current_hostname()
    keywords = set(re.findall(r"'(.*?)'", keyword_expr))
    match_mode = bool(keywords)
    mode = "Keyword Match Mode" if match_mode else "Log Growth Mode"
    
    # Log based on automation mode - but only to file in quiet mode
    automation_mode = get_automation_mode()
    if automation_mode:
        # Only log to file, don't print to stdout
        logging.debug(f"[{current_host} local check] LOG MONITOR Mode: {mode} for {os.path.basename(filepath)}")
    else:
        log_info(f"[{current_host} local check] LOG MONITOR Mode: {mode} for {os.path.basename(filepath)}")
    
    if stop_event is None:
        stop_event = threading.Event()
    def progress_callback(filename, prev_size, current_size, line_count, total_bytes, update_display=False):
        progress_tracker.update_file_progress(filename, prev_size, current_size, line_count, total_bytes, update_display)
    handler = LogMonitorHandler(
        filepath, keywords, print_output, stop_event, result_dict, progress_callback
    )
    handler.start()
    
    # Print based on mode - nothing in quiet mode
    if automation_mode:
        if automation_mode.super_mode and not automation_mode.quiet_mode:
            log_info(f"[{current_host} local check] Monitoring {os.path.basename(filepath)} using inotifywait...")
            print(f"Monitoring (detailed): {os.path.basename(filepath)}")
        elif not automation_mode.quiet_mode:
            print(f"Monitoring: {os.path.basename(filepath)}")
        # In quiet mode, no stdout
    else:
        log_info(f"[{current_host} local check] Monitoring {os.path.basename(filepath)} using inotifywait...")
    
    start_time = time.time()
    last_countdown_message = 0
    countdown_intervals = [30, 20, 10, 5]
    try:
        while not stop_event.is_set():
            if timeout:
                elapsed = time.time() - start_time
                remaining = timeout - elapsed
                if remaining <= 0:
                    if automation_mode:
                        if automation_mode.super_mode:
                            log_info(f"[{current_host} local check] Timeout reached. Stopping monitor for {filepath}.")
                        elif not automation_mode.quiet_mode:
                            print(f"Timeout reached for {os.path.basename(filepath)}")
                        # In quiet mode, no stdout
                    else:
                        log_info(f"[{current_host} local check] Timeout reached. Stopping monitor for {filepath}.")
                    stop_event.set()
                    break
                for interval in countdown_intervals:
                    if remaining <= interval and last_countdown_message != interval:
                        if remaining > 0:
                            if automation_mode:
                                if automation_mode.super_mode:
                                    log_info(f"[{current_host} local check] {int(remaining)} seconds left to close monitoring for {os.path.basename(filepath)}")
                                # For normal and quiet mode, we don't need countdown messages
                            else:
                                log_info(f"[{current_host} local check] {int(remaining)} seconds left to close monitoring for {os.path.basename(filepath)}")
                            last_countdown_message = interval
                            break
            time.sleep(1)
    finally:
        handler.join()
        
        # Log completion based on mode
        if automation_mode:
            if automation_mode.super_mode:
                log_info(f"[{current_host} local check] inotifywait monitoring finished for {os.path.basename(filepath)}.")
            # For normal and quiet mode, we don't need additional completion messages
        else:
            log_info(f"[{current_host} local check] inotifywait monitoring finished for {os.path.basename(filepath)}.")
        
        if result_dict is not None:
            if match_mode:
                result_dict[threading.current_thread().name] = len(handler.seen_keywords)
            else:
                result_dict[threading.current_thread().name] = handler.new_line_count

def monitor_remote_log_file(filepath, host, keyword_expr="", timeout=None, print_output=True, result_dict=None, stop_event=None):
    from ssh_utils import SSHConnector, run_command_locally, run_command_with_timeout
    current_host = get_current_hostname()
    
    if host == current_host or host == "localhost" or host == "convsrc2":
        monitor_log_file_watchdog(
            filepath=filepath,
            keyword_expr=keyword_expr,
            timeout=timeout,
            print_output=print_output,
            result_dict=result_dict,
            stop_event=stop_event
        )
        return
        
    ssh_connector = SSHConnector()
    client = ssh_connector.connect(host)
    tag = f"[{host} ssh]" if client else f"[{host} localhost]"
    
    # Log based on automation mode
    automation_mode = get_automation_mode()
    if automation_mode:
        if automation_mode.super_mode:
            log_info(f"[{current_host} local check] Starting remote monitoring of {os.path.basename(filepath)} on {host} using wc -l")
            print(f"Remote monitoring (detailed): {host}:{os.path.basename(filepath)}")
        elif not automation_mode.quiet_mode:
            print(f"Remote monitoring: {host}:{os.path.basename(filepath)}")
        # In quiet mode, no stdout
    else:
        log_info(f"[{current_host} local check] Starting remote monitoring of {os.path.basename(filepath)} on {host} using wc -l")
    
    keywords = set(re.findall(r"'(.*?)'", keyword_expr))
    match_mode = bool(keywords)
    seen_keywords = set()
    previous_line_count = 0
    current_line_count = 0
    previous_file_size = 0
    current_file_size = 0
    total_lines_grown = 0
    start_time = time.time()
    last_progress_time = time.time()
    progress_interval = 10
    
    def get_remote_file_stats():
        try:
            wc_cmd = f"wc -l {filepath} 2>/dev/null | awk '{{print $1}}' || echo 0"
            if client is None:
                return 0, 0
            stdin, stdout, stderr = client.exec_command(wc_cmd)
            line_output = stdout.read().decode().strip()
            try:
                line_count = int(line_output)
            except:
                line_count = 0
            size_cmd = f"stat -c %s {filepath} 2>/dev/null || echo 0"
            stdin, stdout, stderr = client.exec_command(size_cmd)
            size_output = stdout.read().decode().strip()
            try:
                file_size = int(size_output)
            except:
                file_size = 0
            return line_count, file_size
        except Exception as e:
            log_error(f"[{current_host} local check] Error getting stats for {filepath} on {host}: {e}")
            return 0, 0
    
    def update_progress_display(force_display=False):
        nonlocal last_progress_time
        current_time = time.time()
        if force_display or (current_time - last_progress_time >= progress_interval):
            progress_tracker.update_file_progress(
                f"{host}:{os.path.basename(filepath)}",
                previous_file_size,
                current_file_size,
                total_lines_grown,
                current_file_size,
                update_display=True
            )
            last_progress_time = current_time
    
    try:
        if client is None:
            log_error(f"[{current_host} local check] No SSH client for remote host {host}")
            return
        
        current_line_count, current_file_size = get_remote_file_stats()
        previous_line_count = current_line_count
        previous_file_size = current_file_size
        
        # Log initial stats based on mode
        if automation_mode and automation_mode.super_mode:
            log_debug(f"[{current_host} local check] Initial stats for {os.path.basename(filepath)} on {host}: {current_line_count} lines, {current_file_size} bytes")
        else:
            log_debug(f"[{current_host} local check] Initial stats for {os.path.basename(filepath)} on {host}")
            
        update_progress_display(force_display=True)
        check_interval = 5
        last_check_time = time.time()
        
        while not stop_event.is_set():
            current_time = time.time()
            if current_time - last_check_time >= check_interval:
                new_line_count, new_file_size = get_remote_file_stats()
                lines_grown = new_line_count - current_line_count
                bytes_grown = new_file_size - current_file_size
                
                if lines_grown > 0 or bytes_grown > 0:
                    # Log growth based on mode
                    if automation_mode:
                        if automation_mode.super_mode:
                            log_debug(f"[{current_host} local check] {host}:{os.path.basename(filepath)} - Lines: +{lines_grown} (total: {new_line_count}), Size: +{bytes_grown}B (total: {new_file_size}B)")
                        # For normal and quiet mode, we don't need detailed growth logs
                    else:
                        log_debug(f"[{current_host} local check] {host}:{os.path.basename(filepath)} - Lines: +{lines_grown}, Size: +{bytes_grown}B")
                        
                    total_lines_grown += lines_grown
                    previous_file_size = current_file_size
                    current_line_count = new_line_count
                    current_file_size = new_file_size
                    
                    if match_mode and lines_grown > 0:
                        tail_cmd = f"tail -n {lines_grown} {filepath} 2>/dev/null || echo ''"
                        stdin, stdout, stderr = client.exec_command(tail_cmd)
                        new_lines = stdout.read().decode().strip()
                        for line in new_lines.splitlines():
                            line = line.strip()
                            if line:
                                for kw in keywords:
                                    if kw in line and kw not in seen_keywords:
                                        seen_keywords.add(kw)
                                        # Log keyword match based on mode
                                        if automation_mode:
                                            if automation_mode.super_mode:
                                                log_info(f"[{current_host} local check] MATCH found keyword '{kw}' in {host}:{os.path.basename(filepath)}")
                                            elif not automation_mode.quiet_mode:
                                                print(f"Keyword matched in {host}: '{kw}'")
                                            # In quiet mode, we store for summary but don't print
                                        else:
                                            log_info(f"[{current_host} local check] MATCH found keyword '{kw}' in {host}:{os.path.basename(filepath)}")
                    
                    if seen_keywords == keywords:
                        # Log keyword match completion based on mode
                        if automation_mode:
                            if automation_mode.super_mode:
                                log_info(f"[{current_host} local check] All keywords matched on {host}. Stopping monitor.")
                            elif not automation_mode.quiet_mode:
                                print(f"All keywords matched on {host}")
                            # In quiet mode, no stdout
                        else:
                            log_info(f"[{current_host} local check] All keywords matched on {host}. Stopping monitor.")
                            
                        if result_dict is not None:
                            result_dict[f"remote-{host}-{threading.current_thread().name}"] = len(seen_keywords)
                        stop_event.set()
                        break
            
            last_check_time = current_time
            update_progress_display()
            
            if timeout:
                elapsed = time.time() - start_time
                if elapsed >= timeout:
                    # Log timeout based on mode
                    if automation_mode:
                        if automation_mode.super_mode:
                            log_info(f"[{current_host} local check] Timeout reached for remote monitoring of {filepath} on {host}")
                        elif not automation_mode.quiet_mode:
                            print(f"Timeout reached for {host}:{os.path.basename(filepath)}")
                        # In quiet mode, no stdout
                    else:
                        log_info(f"[{current_host} local check] Timeout reached for remote monitoring of {filepath} on {host}")
                    stop_event.set()
                    break
            time.sleep(1)
            
    except Exception as e:
        log_error(f"[{current_host} local check] Error monitoring remote file {filepath} on {host}: {e}")
    finally:
        if client:
            client.close()
            
        # Log completion based on mode
        if automation_mode:
            if automation_mode.super_mode:
                log_debug(f"[{current_host} local check] Remote monitoring finished for {os.path.basename(filepath)} on {host}. Total lines grown: {total_lines_grown}")
            # For normal and quiet mode, we don't need detailed completion messages
        else:
            log_debug(f"[{current_host} local check] Remote monitoring finished for {os.path.basename(filepath)} on {host}. Total lines grown: {total_lines_grown}")
            
        if result_dict is not None:
            if match_mode:
                result_dict[f"remote-{host}-{threading.current_thread().name}"] = len(seen_keywords)
            else:
                result_dict[f"remote-{host}-{threading.current_thread().name}"] = total_lines_grown
