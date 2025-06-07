import os
import re
import shlex
import threading
import time
import subprocess
import socket
import paramiko
import select
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

def colored(msg, color):
    return f"{color}{msg}{RESET}"

def get_current_hostname():
    """Get the current hostname where the script is running"""
    try:
        return subprocess.check_output(['hostname'], text=True).strip()
    except:
        return socket.gethostname()

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
        self.progress_interval = 30  # Update progress every 30 seconds
        
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
            print(f"{RED}[{self.current_host} local check] Error reading file: {e}{RESET}")
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
                print(f"{RED}Progress callback error: {e}{RESET}")
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
                    print(f"{RED}Progress callback error: {e}{RESET}")
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
                print(f"{YELLOW}[{self.current_host} local check] Note: Could not terminate inotifywait process cleanly: {e}{RESET}")

    def run(self):
        # Check if inotifywait is available
        try:
            subprocess.run(['which', 'inotifywait'], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            print(f"{RED}[{self.current_host} local check] inotifywait not found. Please install inotify-tools{RESET}")
            return

        # Check if file exists, if not create it
        if not os.path.exists(self.filepath):
            try:
                # Create parent directory if needed
                os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
                # Create empty file
                subprocess.run(['sudo', 'touch', self.filepath], check=True)
                print(f"{YELLOW}[{self.current_host} local check] Created file {self.filepath}{RESET}")
            except Exception as e:
                print(f"{RED}[{self.current_host} local check] Could not create file {self.filepath}: {e}{RESET}")
                return

        try:
            self.proc = subprocess.Popen(
                ['sudo', 'inotifywait', '-m', '-e', 'modify', '-e', 'create', self.filepath],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            print(f"{CYAN}[{self.current_host} local check] Started inotifywait monitoring for {os.path.basename(self.filepath)}{RESET}")
        except Exception as e:
            print(f"{RED}[{self.current_host} local check] Failed to start inotifywait: {e}{RESET}")
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
                    print(f"{RED}[{self.current_host} local check] inotifywait process terminated unexpectedly for {os.path.basename(self.filepath)}{RESET}")
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
                                            print(f"{GREEN}[{self.current_host} local check] MATCH found keyword: '{kw}'{RESET}")

                                if self.print_output and original_line:
                                    print(f"{CYAN}[{self.current_host} local check] LOG: {original_line}{RESET}")

                            # Update progress after processing (with potential display)
                            self.update_progress_with_display(current_size)

                            if self.match_mode and self.seen_keywords == self.keywords:
                                print(f"{GREEN}[{self.current_host} local check] All keywords matched. Stopping monitor.{RESET}")
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
            print(f"{CYAN}[{self.current_host} local check] inotifywait monitoring stopped for {os.path.basename(self.filepath)}{RESET}")

class ProgressTracker:
    """Centralized progress tracking for all log monitors"""
    def __init__(self):
        self.file_stats = {}
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.last_full_display = 0
        self.display_interval = 90  # Display every 90 seconds (1.5 minutes)
        
    def update_file_progress(self, filename, prev_size, current_size, line_count, total_bytes, update_display=False):
        with self.lock:
            self.file_stats[filename] = {
                'prev_size': prev_size,
                'current_size': current_size,
                'line_count': line_count,
                'total_bytes': total_bytes,
                'last_update': time.time(),
                'growth_since_last': current_size - prev_size if prev_size > 0 else 0
            }
            
            # Only display if enough time has passed AND update_display is True
            current_time = time.time()
            if update_display and (current_time - self.last_full_display >= self.display_interval):
                self._display_full_progress()
                self.last_full_display = current_time
    
    def force_display_progress(self):
        """Force display progress now"""
        with self.lock:
            self._display_full_progress()
            self.last_full_display = time.time()
    
    def _display_full_progress(self):
        """Display progress for ALL monitored files"""
        elapsed = time.time() - self.start_time
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        print(f"\n{BOLD}{MAGENTA}╔════════════════════════════════════════════════════════════════════════╗{RESET}")
        print(f"{BOLD}{MAGENTA}║                    COMPREHENSIVE LOG GROWTH REPORT                    ║{RESET}")
        print(f"{BOLD}{MAGENTA}║ Time: {current_time} | Elapsed: {elapsed/60:.1f} minutes{' '*(35-len(current_time))}║{RESET}")
        print(f"{BOLD}{MAGENTA}╠════════════════════════════════════════════════════════════════════════╣{RESET}")
        
        if not self.file_stats:
            print(f"{MAGENTA}║{RESET} {RED}No log files being monitored!{RESET}")
            print(f"{BOLD}{MAGENTA}╚════════════════════════════════════════════════════════════════════════╝{RESET}\n")
            return
        
        total_size = 0
        total_lines = 0
        total_growth = 0
        
        # Sort files by name for consistent display
        sorted_files = sorted(self.file_stats.items())
        
        for filename, stats in sorted_files:
            current_size = stats['current_size']
            line_count = stats['line_count']
            growth = stats['growth_since_last']
            last_update_time = stats['last_update']
            
            # Calculate time since last update
            time_since_update = time.time() - last_update_time
            update_status = f"{time_since_update:.0f}s ago" if time_since_update < 60 else f"{time_since_update/60:.1f}m ago"
            
            # Format file size
            if current_size < 1024:
                size_str = f"{current_size}B"
            elif current_size < 1024 * 1024:
                size_str = f"{current_size/1024:.1f}KB"
            else:
                size_str = f"{current_size/(1024*1024):.1f}MB"
            
            # Format growth
            if growth > 0:
                if growth < 1024:
                    growth_str = f"+{growth}B"
                    growth_color = GREEN
                elif growth < 1024 * 1024:
                    growth_str = f"+{growth/1024:.1f}KB"
                    growth_color = GREEN
                else:
                    growth_str = f"+{growth/(1024*1024):.1f}MB"
                    growth_color = GREEN
            else:
                growth_str = "no change"
                growth_color = YELLOW
            
            # Calculate growth rate (KB per second, then format as KB/sec)
            if elapsed > 0:
                rate_kb_sec = (current_size / 1024) / elapsed
                if rate_kb_sec >= 1:
                    rate_str = f"{rate_kb_sec:.1f}KB/s"
                elif rate_kb_sec >= 0.1:
                    rate_str = f"{rate_kb_sec:.2f}KB/s"
                else:
                    rate_str = f"{rate_kb_sec*1000:.0f}B/s"
            else:
                rate_str = "N/A"
            
            total_size += current_size
            total_lines += line_count
            total_growth += growth
            
            # Display file info
            filename_display = filename[:25] + "..." if len(filename) > 28 else filename
            
            print(f"{MAGENTA}║{RESET} {CYAN}{filename_display:30}{RESET} │ {BOLD}{size_str:>8}{RESET} │ {growth_color}{growth_str:>10}{RESET} │ Lines: {BLUE}{line_count:>6}{RESET} │ {YELLOW}{rate_str:>10}{RESET} {MAGENTA}║{RESET}")
        
        print(f"{BOLD}{MAGENTA}╠════════════════════════════════════════════════════════════════════════╣{RESET}")
        
        # Summary
        total_size_str = f"{total_size/(1024*1024):.1f}MB" if total_size > 1024*1024 else f"{total_size/1024:.1f}KB"
        total_growth_str = f"{total_growth/(1024*1024):.1f}MB" if total_growth > 1024*1024 else f"{total_growth/1024:.1f}KB"
        avg_rate = (total_size / 1024) / elapsed if elapsed > 0 else 0
        avg_rate_str = f"{avg_rate:.1f}KB/s" if avg_rate >= 1 else f"{avg_rate*1000:.0f}B/s"
        
        print(f"{MAGENTA}║{RESET} {BOLD}TOTAL:{' '*24}{RESET} │ {BOLD}{GREEN}{total_size_str:>8}{RESET} │ {BOLD}{GREEN}{total_growth_str:>10}{RESET} │ Lines: {BOLD}{BLUE}{total_lines:>6}{RESET} │ {BOLD}{YELLOW}{avg_rate_str:>10}{RESET} {MAGENTA}║{RESET}")
        print(f"{BOLD}{MAGENTA}╚════════════════════════════════════════════════════════════════════════╝{RESET}\n")

# Global progress tracker
progress_tracker = ProgressTracker()

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
    print(f"{BLUE}[{current_host} local check] LOG MONITOR Mode: {mode} for {os.path.basename(filepath)}{RESET}")

    if stop_event is None:
        stop_event = threading.Event()

    # Progress callback for updates
    def progress_callback(filename, prev_size, current_size, line_count, total_bytes, update_display=False):
        progress_tracker.update_file_progress(filename, prev_size, current_size, line_count, total_bytes, update_display)

    handler = LogMonitorHandler(
        filepath, keywords, print_output, stop_event, result_dict, progress_callback
    )
    handler.start()

    print(f"{YELLOW}[{current_host} local check] Monitoring {os.path.basename(filepath)} using inotifywait...{RESET}")

    start_time = time.time()
    last_countdown_message = 0
    countdown_intervals = [30, 20, 10, 5]

    try:
        while not stop_event.is_set():
            if timeout:
                elapsed = time.time() - start_time
                remaining = timeout - elapsed
                
                if remaining <= 0:
                    print(f"{RED}[{current_host} local check] Timeout reached. Stopping monitor for {filepath}.{RESET}")
                    stop_event.set()
                    break
                
                for interval in countdown_intervals:
                    if remaining <= interval and last_countdown_message != interval:
                        if remaining > 0:
                            print(f"{YELLOW}[{current_host} local check] {int(remaining)} seconds left to close monitoring for {os.path.basename(filepath)}{RESET}")
                            last_countdown_message = interval
                            break
            
            time.sleep(1)
    finally:
        handler.join()
        print(f"{CYAN}[{current_host} local check] inotifywait monitoring finished for {os.path.basename(filepath)}.{RESET}")

        if result_dict is not None:
            if match_mode:
                result_dict[threading.current_thread().name] = len(handler.seen_keywords)
            else:
                result_dict[threading.current_thread().name] = handler.new_line_count

# ---- SSH Connector ----
class SSHConnector:
    def __init__(self, ssh_config_path=None):
        self.ssh_config_path = ssh_config_path or os.path.expanduser("~/.ssh/config")
        self.config = self._load_ssh_config()
        self.local_hostnames = self._get_local_hostnames()

    def _load_ssh_config(self):
        if not os.path.exists(self.ssh_config_path):
            raise FileNotFoundError(f"{RED}SSH config file not found at {self.ssh_config_path}{RESET}")
        config = paramiko.SSHConfig()
        with open(self.ssh_config_path, 'r') as f:
            config.parse(f)
        return config

    def _get_local_hostnames(self):
        local_names = set()
        try:
            local_names.add(subprocess.check_output(['hostname'], text=True).strip())
        except Exception:
            pass
        local_names.update({"localhost", "127.0.0.1", socket.gethostname(), socket.getfqdn()})
        return local_names

    def connect(self, hostname):
        hostname_lower = hostname.lower()
        if hostname_lower in self.local_hostnames:
            current_host = get_current_hostname()
            print(f"{CYAN}[{current_host} local check] Hostname '{hostname}' resolved as local machine. Using local connection.{RESET}")
            return None

        host_config = self.config.lookup(hostname)
        if not host_config:
            raise ValueError(f"{RED}No configuration found for {hostname}{RESET}")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs = {
            "hostname": host_config.get("hostname", hostname),
            "username": host_config.get("user"),
            "port": int(host_config.get("port", 22)),
        }

        if "proxyjump" in host_config:
            proxy_host = host_config["proxyjump"]
            proxy_config = self.config.lookup(proxy_host)
            proxy_client = paramiko.SSHClient()
            proxy_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            proxy_client.connect(
                hostname=proxy_config.get("hostname", proxy_host),
                username=proxy_config.get("user"),
                port=int(proxy_config.get("port", 22)),
            )
            proxy_transport = proxy_client.get_transport()
            dest_addr = (connect_kwargs["hostname"], connect_kwargs["port"])
            local_addr = ("127.0.0.1", 0)
            proxy_channel = proxy_transport.open_channel("direct-tcpip", dest_addr, local_addr)
            connect_kwargs["sock"] = proxy_channel

        client.connect(**connect_kwargs)
        return client

# ---- Remote Program Runner ----
class RemoteProgramRunner:
    def __init__(
        self,
        hostname: str,
        command: str,
        working_dir: str = "/opt/MasterThesis/trafGen",
        check_stuck: bool = True,
        stuck_check_interval: int = 5,
        stuck_check_idle_threshold: int = 30,
        timeout: int = 60,
        max_duration: int = 120,
        cleanup: bool = False,
        verbose: bool = False,
        program_name: str = None,
    ):
        self.hostname = hostname
        self.command = command
        self.working_dir = working_dir
        self.check_stuck = check_stuck
        self.stuck_check_interval = stuck_check_interval
        self.stuck_check_idle_threshold = stuck_check_idle_threshold
        self.timeout = timeout
        self.max_duration = max_duration
        self.cleanup = cleanup
        self.verbose = verbose
        self.program_name = program_name or self._extract_program_name()

        self.log_file = f"/tmp/{self.program_name}.log"
        self.pid_file = f"/tmp/{self.program_name}.pid"
        self.client = None
        self.pid = None
        self.result = {
            "hostname": hostname,
            "status": "unknown",
            "output": "",
            "error": "",
            "pid": None,
            "log_file": self.log_file,
        }

    def _extract_program_name(self):
        tokens = shlex.split(self.command)
        for token in tokens:
            if token not in {"sudo", "env", "bash", "sh"} and not token.startswith("-"):
                return os.path.basename(token)
        return "unknown_program"

    def log(self, msg):
        current_host = get_current_hostname()
        print(f"{BLUE}[{current_host} local check] {self.hostname}: {msg}{RESET}")

    def connect(self):
        connector = SSHConnector()
        self.client = connector.connect(self.hostname)
        return self.client is not None

    def run_command(self, cmd, timeout=None, verbose=None):
        if self.client is None:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout or self.timeout)
            return (result.returncode == 0, result.stdout, result.stderr)
        else:
            try:
                stdin, stdout, stderr = self.client.exec_command(cmd, timeout=timeout or self.timeout)
                stdout.channel.settimeout(timeout or self.timeout)
                stderr.channel.settimeout(timeout or self.timeout)
                exit_code = stdout.channel.recv_exit_status()
                return (exit_code == 0, stdout.read().decode(), stderr.read().decode())
            except socket.timeout:
                return (False, "", "SSH command timed out")
            except Exception as e:
                return (False, "", str(e))

    def launch(self):
        full_cmd = f"cd {self.working_dir} && nohup {self.command} > {self.log_file} 2>&1 & echo $! > {self.pid_file} && echo $!"
        
        try:
            status, output, err = self.run_command(full_cmd, timeout=15)
            if not status:
                self.result.update({"status": "launch_failed", "error": err})
                return False
            
            lines = output.strip().split('\n')
            for line in lines:
                if line.strip().isdigit():
                    self.pid = line.strip()
                    self.result["pid"] = self.pid
                    return True
            
            time.sleep(2)
            status, pid_out, err = self.run_command(f"cat {self.pid_file}", timeout=5)
            if status and pid_out.strip().isdigit():
                self.pid = pid_out.strip()
                self.result["pid"] = self.pid
                return True
            
            self.result.update({"status": "pid_fetch_failed", "error": f"Could not get PID. Output: {output}"})
            return False
            
        except Exception as e:
            self.result.update({"status": "launch_failed", "error": str(e)})
            return False

    def is_process_running(self):
        if not self.pid:
            return False
        ps_status, ps_out, _ = self.run_command(f"ps -p {self.pid}", timeout=5)
        return ps_status and bool(re.search(rf"\b{self.pid}\b", ps_out))

    def is_stuck(self):
        stat_cmd = f"stat -c %Y {self.log_file}"
        stat_status, mtime_str, _ = self.run_command(stat_cmd, timeout=5)
        if stat_status and mtime_str.strip().isdigit():
            last_modified = int(mtime_str.strip())
            idle_time = time.time() - last_modified
            return idle_time >= self.stuck_check_idle_threshold
        return False

    def kill(self):
        if self.pid:
            self.run_command(f"sudo kill {self.pid}", timeout=5)
            self.result["status"] = "killed_stuck"

    def collect_logs(self):
        success, final_out, _ = self.run_command(f"cat {self.log_file}", timeout=10)
        if success:
            self.result["output"] = final_out

    def cleanup_files(self):
        self.run_command(f"rm -f {self.pid_file}", timeout=5)

    def run(self):
        self.log(f"{BOLD}Starting: {self.command}{RESET}")

        if not self.connect():
            self.result["status"] = "connection_failed"
            return self.result

        if not self.launch():
            if self.client:
                self.client.close()
            return self.result

        start_time = time.time()
        while time.time() - start_time < self.max_duration:
            if not self.is_process_running():
                self.result["status"] = "completed"
                self.collect_logs()
                break

            if self.check_stuck and self.is_stuck():
                self.log(f"{RED}{self.program_name} appears stuck. Killing it.{RESET}")
                self.kill()
                self.collect_logs()
                break

            elapsed = int(time.time() - start_time)
            if elapsed % 30 == 0:
                self.log(f"{YELLOW}Running... {elapsed}s elapsed{RESET}")

            time.sleep(self.stuck_check_interval)
        else:
            self.log(f"{RED}Timeout reached. Killing process.{RESET}")
            self.kill()
            self.result["status"] = "timeout"

        if self.cleanup:
            self.cleanup_files()

        if self.client:
            self.client.close()
        self.log(f"{BOLD}Finished with status: {self.result['status']}{RESET}")
        return self.result
