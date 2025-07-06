#!/usr/bin/env python3

import os
import sys
import time
import logging
import threading
import re
import select
import subprocess
import random
import socket
import getpass
from datetime import datetime

from config import (
    colored, RED, GREEN, YELLOW, BLUE, CYAN, MAGENTA, BOLD, RESET,
    progress_tracker, experiment_state
)

def configure_logging(log_level=logging.INFO, log_file=None, quiet=False):
    """Configure logging with advanced options"""
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'
    
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    root_logger.setLevel(log_level)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(log_format, date_format))
    root_logger.addHandler(console_handler)
    
    # Suppress paramiko and other SSH-related logging in quiet mode
    if quiet:
        # Set paramiko loggers to WARNING level to suppress INFO messages
        logging.getLogger("paramiko").setLevel(logging.WARNING)
        logging.getLogger("paramiko.transport").setLevel(logging.WARNING)
        logging.getLogger("paramiko.transport.sftp").setLevel(logging.WARNING)
        logging.getLogger("paramiko.client").setLevel(logging.WARNING)
        # Also suppress SSH utils verbose logging
        logging.getLogger("ssh_utils").setLevel(logging.WARNING)
    
    if log_file:
        try:
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir)
            fh = logging.FileHandler(log_file)
            fh.setFormatter(logging.Formatter(log_format, date_format))
            root_logger.addHandler(fh)
            if not quiet:
                logging.info(f"Logging to file: {log_file}")
        except Exception as e:
            logging.error(f"Failed to set up file logging: {e}")

    def exception_handler(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        logging.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))
    sys.excepthook = exception_handler

    logging.info(f"Logging initialized at level {logging.getLevelName(log_level)}")
    logging.info(f"Python version: {sys.version}")
    logging.info(f"Platform: {sys.platform}")
    logging.info(f"User: {getpass.getuser()}")
    logging.info(f"Current time (UTC): {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}")

logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
    handlers=[logging.StreamHandler()]
)

class TeeOutput:
    def __init__(self, file_stream, original_stream):
        self.file_stream = file_stream
        self.original_stream = original_stream
        
    def write(self, data):
        try:
            self.file_stream.write(data)
        except Exception:
            pass
        self.original_stream.write(data)
        
    def flush(self):
        try:
            self.file_stream.flush()
        except Exception:
            pass
        self.original_stream.flush()
        
    def isatty(self):
        return self.original_stream.isatty()
        
    def fileno(self):
        return self.original_stream.fileno()

def get_current_hostname():
    try:
        return subprocess.check_output(['hostname'], text=True).strip()
    except:
        return socket.gethostname()


def setup_logging(experiment_name, experiment_id, demon, timestamp, user):
    """Set up logging to both file and stdout when in demon mode"""
    experiment_state.original_stdout = sys.stdout
    experiment_state.original_stderr = sys.stderr
    experiment_state.demon_mode = demon

    if demon:
        # include iteration suffix if set
        iteration = getattr(experiment_state, "current_iteration", None)
        iter_suffix = f"_{iteration}" if iteration is not None else ""

        log_timestamp = timestamp.replace(" ", "_").replace(":", "")
        log_path = f"/tmp/exp/{experiment_name}_{experiment_id}{iter_suffix}_{log_timestamp}_auto.log"
        experiment_state.log_file = open(log_path, 'w', buffering=1)

        # write header
        header = (
            "=== Experiment Log ===\n"
            f"Date/Time: {timestamp}\n"
            f"User: {user}\n"
            f"Host: {get_current_hostname()}\n"
            f"Experiment: {experiment_name}\n"
            f"Experiment ID: {experiment_id}\n"
            + (f"Iteration: {iteration}\n" if iteration is not None else "")
            + "==============================\n\n"
        )
        experiment_state.log_file.write(header)
        experiment_state.original_stdout.write(header)

        # tee stdout/stderr
        sys.stdout = TeeOutput(experiment_state.log_file, experiment_state.original_stdout)
        sys.stderr = TeeOutput(experiment_state.log_file, experiment_state.original_stderr)

        # route logging to same file
        fh = logging.FileHandler(log_path)
        fh.setLevel(logging.getLogger().level)
        fh.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            '%Y-%m-%d %H:%M:%S'
        ))
        logging.getLogger().addHandler(fh)

        return log_path
    else:
        return None

def cleanup_logging():
    if experiment_state.log_file and experiment_state.demon_mode:
        logger = logging.getLogger()
        for h in logger.handlers[:]:
            if isinstance(h, logging.FileHandler):
                if getattr(h.stream, 'name', None) == getattr(experiment_state.log_file, 'name', None):
                    logger.removeHandler(h)
                    try:
                        h.close()
                    except:
                        pass
        sys.stdout = experiment_state.original_stdout
        sys.stderr = experiment_state.original_stderr
        try:
            experiment_state.log_file.close()
        except:
            pass
        experiment_state.log_file = None
        experiment_state.demon_mode = False

def check_and_clear_memory_usage():
    try:
        import psutil
        mem = psutil.virtual_memory().percent
        if mem > 85:
            logging.warning(f"High memory usage: {mem}%. Clearing caches...")
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
                    logging.info(f"Memory usage reduced from {before:.1f}MB to {after:.1f}MB")
            except:
                pass
        return mem
    except ImportError:
        return None
    except Exception as e:
        logging.error(f"Error checking memory: {e}")
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

    def run(self):
        try:
            while not self.stop_event.is_set():
                try:
                    c1 = self.get_conntrack_count("connt1")
                    c2 = self.get_conntrack_count("connt2")
                    d1 = c1 - self.last_connt1
                    d2 = c2 - self.last_connt2
                    self.last_connt1, self.last_connt2 = c1, c2

                    logging.info("\n" + "="*80)
                    logging.info(f"Progress Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                    logging.info("="*80)
                    fmt = "{:<25} | {:>10} | {:>10} | {:>10}"
                    logging.info(fmt.format("File","Size (MB)","Lines","Delta (KB)"))
                    logging.info("-"*80)
                    for fp, stats in progress_tracker.file_stats.items():
                        name = os.path.basename(fp)
                        size_mb = stats.get('size',0)/(1024*1024)
                        lines  = stats.get('lines',0)
                        dk     = stats.get('delta_size',0)/1024
                        logging.info(fmt.format(name,f"{size_mb:.2f}",f"{lines}",f"{dk:.2f}"))
                    logging.info("-"*80)
                    logging.info("Conntrack Entries:")
                    logging.info(f"connt1: {c1} (Δ: {d1:+d})")
                    logging.info(f"connt2: {c2} (Δ: {d2:+d})")
                    logging.info("="*80)

                    check_and_clear_memory_usage()
                    self.stop_event.wait(5)
                except Exception as e:
                    logging.error(f"Error in progress display: {e}")
                    time.sleep(5)
        finally:
            self.close_connections()	
			
# Log monitoring class for watching files for growth or specific content
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
        self.progress_interval = 10  # Update progress every 30 seconds
        
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
            logging.error(f"{RED}[{self.current_host} local check] Error reading file: {e}{RESET}")
        return ""

    def update_progress_silent(self, current_size):
        """Update progress data without displaying - called frequently"""
        if self.progress_callback:
            try:
                self.progress_callback(
                    os.path.basename(self.filepath),
                    self.last_size,
                    current_size,
                    self.new_line_count,
                    self.total_bytes_read,
                    update_display=False  # Don't display immediately
                )
            except Exception as e:
                logging.error(f"{RED}Progress callback error: {e}{RESET}")
        self.last_size = current_size

    def update_progress_with_display(self, current_size):
        """Update progress and allow display - called every 30 seconds"""
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
                        update_display=True  # Allow display
                    )
                except Exception as e:
                    logging.error(f"{RED}Progress callback error: {e}{RESET}")
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
                logging.warning(f"{YELLOW}[{self.current_host} local check] Note: Could not terminate inotifywait process cleanly: {e}{RESET}")

    def run(self):
        # Check if inotifywait is available
        try:
            subprocess.run(['which', 'inotifywait'], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            logging.error(f"{RED}[{self.current_host} local check] inotifywait not found. Please install inotify-tools{RESET}")
            return

        # Check if file exists, if not create it
        if not os.path.exists(self.filepath):
            try:
                # Create parent directory if needed
                os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
                # Create empty file
                subprocess.run(['sudo', 'touch', self.filepath], check=True)
                logging.warning(f"{YELLOW}[{self.current_host} local check] Created file {self.filepath}{RESET}")
            except Exception as e:
                logging.error(f"{RED}[{self.current_host} local check] Could not create file {self.filepath}: {e}{RESET}")
                return

        try:
            self.proc = subprocess.Popen(
                ['sudo', 'inotifywait', '-m', '-e', 'modify', '-e', 'create', self.filepath],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            logging.info(f"{CYAN}[{self.current_host} local check] Started inotifywait monitoring for {os.path.basename(self.filepath)}{RESET}")
        except Exception as e:
            logging.error(f"{RED}[{self.current_host} local check] Failed to start inotifywait: {e}{RESET}")
            return

        # Initialize with current file size
        last_position = self.get_file_size()
        self.last_size = last_position
        self.total_bytes_read = last_position
        
        # Initial progress update
        self.update_progress_silent(last_position)

        try:
            while not self.stop_event.is_set():
                if self.proc.poll() is not None:
                    logging.error(f"{RED}[{self.current_host} local check] inotifywait process terminated unexpectedly for {os.path.basename(self.filepath)}{RESET}")
                    break

                rlist, _, _ = select.select([self.proc.stdout], [], [], 0.5)
                if rlist:
                    line = self.proc.stdout.readline()
                    if line and ('MODIFY' in line or 'CREATE' in line):
                        current_size = self.get_file_size()
                        
                        new_content = self.read_file_from_position(last_position)
                        if new_content:
                            # Count ALL lines including empty ones
                            new_lines = new_content.splitlines()
                            lines_added = len(new_lines)
                            
                            bytes_read = len(new_content.encode('utf-8'))
                            self.total_bytes_read += bytes_read
                            
                            # Update line count for growth mode
                            if not self.match_mode:
                                self.new_line_count += lines_added
                            
                            last_position = current_size

                            # Process lines for keyword matching
                            for log_line in new_lines:
                                original_line = log_line
                                log_line = log_line.strip()
                                    
                                if self.match_mode and log_line:
                                    for kw in self.keywords:
                                        if kw in log_line and kw not in self.seen_keywords:
                                            self.seen_keywords.add(kw)
                                            logging.info(f"{GREEN}[{self.current_host} local check] MATCH found keyword: '{kw}'{RESET}")

                                if self.print_output and original_line:
                                    logging.info(f"{CYAN}[{self.current_host} local check] LOG: {original_line}{RESET}")

                            # Update progress after processing (with potential display)
                            self.update_progress_with_display(current_size)

                            if self.match_mode and self.seen_keywords == self.keywords:
                                logging.info(f"{GREEN}[{self.current_host} local check] All keywords matched. Stopping monitor.{RESET}")
                                if self.result_dict is not None:
                                    self.result_dict[threading.current_thread().name] = len(self.seen_keywords)
                                self.stop_event.set()
                                break
                else:
                    # Periodic update even without changes (but no display)
                    current_size = self.get_file_size()
                    self.update_progress_silent(current_size)
                    
                time.sleep(0.1)

        finally:
            self.terminate_process_safely()
            logging.info(f"{CYAN}[{self.current_host} local check] inotifywait monitoring stopped for {os.path.basename(self.filepath)}{RESET}")

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
    logging.info(f"{BLUE}[{current_host} local check] LOG MONITOR Mode: {mode} for {os.path.basename(filepath)}{RESET}")

    if stop_event is None:
        stop_event = threading.Event()

    # Progress callback for updates
    def progress_callback(filename, prev_size, current_size, line_count, total_bytes, update_display=False):
        progress_tracker.update_file_progress(filename, prev_size, current_size, line_count, total_bytes, update_display)

    handler = LogMonitorHandler(
        filepath, keywords, print_output, stop_event, result_dict, progress_callback
    )
    handler.start()

    logging.info(f"{YELLOW}[{current_host} local check] Monitoring {os.path.basename(filepath)} using inotifywait...{RESET}")

    start_time = time.time()
    last_countdown_message = 0
    countdown_intervals = [30, 20, 10, 5]

    try:
        while not stop_event.is_set():
            if timeout:
                elapsed = time.time() - start_time
                remaining = timeout - elapsed
                
                if remaining <= 0:
                    logging.info(f"{RED}[{current_host} local check] Timeout reached. Stopping monitor for {filepath}.{RESET}")
                    stop_event.set()
                    break
                
                for interval in countdown_intervals:
                    if remaining <= interval and last_countdown_message != interval:
                        if remaining > 0:
                            logging.info(f"{YELLOW}[{current_host} local check] {int(remaining)} seconds left to close monitoring for {os.path.basename(filepath)}{RESET}")
                            last_countdown_message = interval
                            break
            
            time.sleep(1)
    finally:
        handler.join()
        logging.info(f"{CYAN}[{current_host} local check] inotifywait monitoring finished for {os.path.basename(filepath)}.{RESET}")

        if result_dict is not None:
            if match_mode:
                result_dict[threading.current_thread().name] = len(handler.seen_keywords)
            else:
                result_dict[threading.current_thread().name] = handler.new_line_count

def monitor_remote_log_file(filepath, host, keyword_expr="", timeout=None, print_output=True, result_dict=None, stop_event=None):
    """Monitor log files on remote hosts using wc -l for line counting"""
    from ssh_utils import SSHConnector, run_command_locally, run_command_with_timeout
    
    current_host = get_current_hostname()
    
    if host == current_host or host == "localhost" or host == "convsrc2":
        # Monitor locally using the existing function
        monitor_log_file_watchdog(
            filepath=filepath,
            keyword_expr=keyword_expr,
            timeout=timeout,
            print_output=print_output,
            result_dict=result_dict,
            stop_event=stop_event
        )
    else:
        # Monitor remotely using SSH and wc -l
        ssh_connector = SSHConnector()
        client = ssh_connector.connect(host)
        tag = f"[{host} ssh]" if client else f"[{host} localhost]"
        
        logging.debug(f"{BLUE}[{current_host} local check] Starting remote monitoring of {os.path.basename(filepath)} on {host} using wc -l{RESET}")
        
        keywords = set(re.findall(r"'(.*?)'", keyword_expr))
        match_mode = bool(keywords)
        seen_keywords = set()
        
        # Initialize tracking variables
        previous_line_count = 0
        current_line_count = 0
        previous_file_size = 0
        current_file_size = 0
        total_lines_grown = 0
        
        start_time = time.time()
        last_progress_time = time.time()
        progress_interval = 10  # Update progress every 30 seconds
        
        def get_remote_file_stats():
            """Get line count and file size from remote host"""
            try:
                # Get line count using wc -l
                wc_cmd = f"wc -l {filepath} 2>/dev/null | awk '{{print $1}}' || echo 0"
                if client is None:
                    return 0, 0
                
                stdin, stdout, stderr = client.exec_command(wc_cmd)
                line_output = stdout.read().decode().strip()
                try:
                    line_count = int(line_output)
                except:
                    line_count = 0
                
                # Get file size using stat
                size_cmd = f"stat -c %s {filepath} 2>/dev/null || echo 0"
                stdin, stdout, stderr = client.exec_command(size_cmd)
                size_output = stdout.read().decode().strip()
                try:
                    file_size = int(size_output)
                except:
                    file_size = 0
                
                return line_count, file_size
            except Exception as e:
                logging.error(f"{RED}[{current_host} local check] Error getting stats for {filepath} on {host}: {e}{RESET}")
                return 0, 0
        
        def update_progress_display(force_display=False):
            """Update progress tracker with current stats"""
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
                logging.error(f"{RED}[{current_host} local check] No SSH client for remote host {host}{RESET}")
                return
            
            # Get initial file stats
            current_line_count, current_file_size = get_remote_file_stats()
            previous_line_count = current_line_count
            previous_file_size = current_file_size
            
            logging.debug(f"{CYAN}[{current_host} local check] Initial stats for {os.path.basename(filepath)} on {host}: {current_line_count} lines, {current_file_size} bytes{RESET}")
            
            # Initial progress update
            update_progress_display(force_display=True)
            
            check_interval = 5  # Check every 5 seconds
            last_check_time = time.time()
            
            while not stop_event.is_set():
                current_time = time.time()
                
                # Check file stats every 5 seconds
                if current_time - last_check_time >= check_interval:
                    # Get current stats
                    new_line_count, new_file_size = get_remote_file_stats()
                    
                    # Calculate growth
                    lines_grown = new_line_count - current_line_count
                    bytes_grown = new_file_size - current_file_size
                    
                    if lines_grown > 0 or bytes_grown > 0:
                        # Only log at debug level to suppress verbose messages
                        logging.debug(f"{GREEN}[{current_host} local check] {host}:{os.path.basename(filepath)} - Lines: +{lines_grown} (total: {new_line_count}), Size: +{bytes_grown}B (total: {new_file_size}B){RESET}")
                        
                        # Update totals
                        total_lines_grown += lines_grown
                        previous_file_size = current_file_size
                        current_line_count = new_line_count
                        current_file_size = new_file_size
                        
                        # Handle keyword matching if needed
                        if match_mode and lines_grown > 0:
                            # Get the new lines for keyword matching
                            tail_cmd = f"tail -n {lines_grown} {filepath} 2>/dev/null || echo ''"
                            stdin, stdout, stderr = client.exec_command(tail_cmd)
                            new_lines = stdout.read().decode().strip()
                            
                            for line in new_lines.splitlines():
                                line = line.strip()
                                if line:
                                    for kw in keywords:
                                        if kw in line and kw not in seen_keywords:
                                            seen_keywords.add(kw)
                                            logging.info(f"{GREEN}[{current_host} local check] MATCH found keyword '{kw}' in {host}:{os.path.basename(filepath)}{RESET}")
                            
                            if seen_keywords == keywords:
                                logging.info(f"{GREEN}[{current_host} local check] All keywords matched on {host}. Stopping monitor.{RESET}")
                                if result_dict is not None:
                                    result_dict[f"remote-{host}-{threading.current_thread().name}"] = len(seen_keywords)
                                stop_event.set()
                                break
                    
                    last_check_time = current_time
                
                # Update progress display periodically
                update_progress_display()
                
                # Check timeout
                if timeout:
                    elapsed = time.time() - start_time
                    if elapsed >= timeout:
                        logging.info(f"{RED}[{current_host} local check] Timeout reached for remote monitoring of {filepath} on {host}{RESET}")
                        break
                
                time.sleep(1)  # Sleep for 1 second between checks
        
        except Exception as e:
            logging.error(f"{RED}[{current_host} local check] Error monitoring remote file {filepath} on {host}: {e}{RESET}")
        
        finally:
            if client:
                client.close()
            
            logging.debug(f"{CYAN}[{current_host} local check] Remote monitoring finished for {os.path.basename(filepath)} on {host}. Total lines grown: {total_lines_grown}{RESET}")
            
            if result_dict is not None:
                if match_mode:
                    result_dict[f"remote-{host}-{threading.current_thread().name}"] = len(seen_keywords)
                else:
                    result_dict[f"remote-{host}-{threading.current_thread().name}"] = total_lines_grown
                    result_dict[f"remote-{host}-{threading.current_thread().name}"] = total_lines_grown
