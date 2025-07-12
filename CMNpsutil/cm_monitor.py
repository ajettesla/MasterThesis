#!/usr/bin/env python3
import psutil
import time
import argparse
import sys
import os
import signal
import csv
import subprocess
import re
import getpass
import threading
from datetime import datetime, timezone, UTC
from queue import Queue, Empty

PID_FILE = '/tmp/exp/cpu_mem_monitor.pid'
DEFAULT_INTERVAL = 1.0

# Shared data structure for measurements
class CycleData:
    def __init__(self):
        self.system_cycles = 0.0
        self.process_cycles = {}
        self.clock_delta = None
        self.lock = threading.Lock()
        
    def update_system(self, cycles):
        with self.lock:
            self.system_cycles = cycles
            
    def update_process(self, pid, cycles):
        with self.lock:
            self.process_cycles[pid] = cycles
            
    def update_clock_delta(self, delta):
        with self.lock:
            self.clock_delta = delta
            
    def get_system(self):
        with self.lock:
            return self.system_cycles
            
    def get_process(self, pid):
        with self.lock:
            return self.process_cycles.get(pid, 0.0)
            
    def get_total_process(self, pids):
        with self.lock:
            return sum(self.process_cycles.get(pid, 0.0) for pid in pids)
            
    def get_clock_delta(self):
        with self.lock:
            return self.clock_delta

# Global cycle data instance
cycle_data = CycleData()

def timestamp_ns():
    ts = time.time_ns()
    sec = ts // 1_000_000_000
    nsec = ts % 1_000_000_000
    return f"{sec}.{nsec:09d}"

def get_formatted_datetime():
    """Get current date and time in UTC in YYYY-MM-DD HH:MM:SS format"""
    try:
        # Use the recommended timezone-aware approach
        return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
    except AttributeError:
        # Fall back for Python < 3.11
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

def get_current_user():
    """Get current user's login name"""
    return getpass.getuser()

def get_conntrack_count():
    try:
        result = subprocess.run(['sudo', '-n', 'conntrack', '-C'], capture_output=True, text=True)
        if result.returncode == 0:
            return int(result.stdout.strip())
        return None
    except (subprocess.SubprocessError, FileNotFoundError, ValueError):
        return None

def get_cycles_per_sec(pid=None, duration=1):
    """Get CPU cycles per second using perf stat"""
    try:
        if pid:
            cmd = ["sudo", "perf", "stat", "-e", "cycles", "-p", str(pid), "--", "sleep", str(duration)]
        else:
            cmd = ["sudo", "perf", "stat", "-e", "cycles", "--", "sleep", str(duration)]
            
        result = subprocess.run(
            cmd,
            stderr=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            text=True
        )

        stderr = result.stderr
        cycles = None
        elapsed = None

        for line in stderr.splitlines():
            if 'cycles' in line:
                m = re.search(r"([\d,]+)\s+cycles", line)
                if m:
                    cycles = int(m.group(1).replace(',', ''))
            if 'seconds time elapsed' in line:
                m = re.search(r"([\d.]+)\s+seconds time elapsed", line)
                if m:
                    elapsed = float(m.group(1))

        if cycles and elapsed:
            # Convert to GHz (cycles per second divided by 1 billion)
            return cycles / elapsed / 1_000_000_000
        return 0.0
    except Exception as e:
        print(f"Error getting CPU cycles: {e}", file=sys.stderr)
        return 0.0

# Thread function for system CPU cycles
def system_cycles_thread():
    while True:
        cycles = get_cycles_per_sec()
        cycle_data.update_system(cycles)
        time.sleep(1)  # Update every second

# Thread function for process CPU cycles
def process_cycles_thread(pid):
    while True:
        try:
            if not psutil.pid_exists(pid):
                cycle_data.update_process(pid, 0.0)
                time.sleep(1)
                continue
                
            cycles = get_cycles_per_sec(pid)
            cycle_data.update_process(pid, cycles)
        except Exception as e:
            print(f"Error in process_cycles_thread for PID {pid}: {e}", file=sys.stderr)
            cycle_data.update_process(pid, 0.0)
        time.sleep(1)  # Update every second

# Thread function for clock difference
def clockdiff_thread(target_ip, interval):
    while True:
        try:
            cmd = ["sudo", "clockdiff", target_ip]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10 # Add a timeout to prevent hanging
            )
            
            if result.returncode == 0:
                stdout = result.stdout.strip()
                
                # First, try to parse verbose format (e.g., "delta=0ms")
                match = re.search(r'delta=(-?\d+)ms', stdout)
                if match:
                    delta = int(match.group(1))
                    cycle_data.update_clock_delta(delta)
                else:
                    # If verbose fails, try to parse raw format (e.g., "1752341059 0 0")
                    parts = stdout.split()
                    if len(parts) >= 2:
                        try:
                            # The second part should be the delta
                            delta = int(parts[1])
                            cycle_data.update_clock_delta(delta)
                        except (ValueError, IndexError):
                            print(f"clockdiff: could not parse delta from raw output: {stdout}", file=sys.stderr)
                            cycle_data.update_clock_delta(None)
                    else:
                        # If both parsing attempts fail
                        print(f"clockdiff: could not parse delta from unrecognized output: {stdout}", file=sys.stderr)
                        cycle_data.update_clock_delta(None)
            else:
                # Command failed
                print(f"clockdiff: command failed for IP {target_ip} with exit code {result.returncode}", file=sys.stderr)
                if result.stderr:
                    print(f"clockdiff stderr: {result.stderr.strip()}", file=sys.stderr)
                cycle_data.update_clock_delta(None)

        except subprocess.TimeoutExpired:
            print(f"clockdiff: command timed out for IP {target_ip}", file=sys.stderr)
            cycle_data.update_clock_delta(None) # Reset on timeout
        except FileNotFoundError:
            print("clockdiff: command not found. Please ensure 'iputils-clockdiff' is installed.", file=sys.stderr)
            return # Stop the thread
        except Exception as e:
            print(f"clockdiff: an unexpected error occurred for IP {target_ip}: {e}", file=sys.stderr)
            cycle_data.update_clock_delta(None) # Reset on error
        
        time.sleep(interval)

def get_system_stats(prev_cpu, elapsed):
    cpu = psutil.cpu_times()
    total = sum(cpu)
    idle = cpu.idle
    sys_pct = 0.0
    if prev_cpu and elapsed > 0:
        dt_total = total - sum(prev_cpu)
        dt_idle = idle - prev_cpu.idle
        sys_pct = 100.0 * (dt_total - dt_idle) / dt_total
    mem = psutil.virtual_memory()
    
    # Get CPU cycles in GHz from shared data
    cpu_cycles_ghz = cycle_data.get_system()
    
    return sys_pct, mem.used, mem.percent, cpu, cpu_cycles_ghz

def get_process_stats(pids, prev_cpu, elapsed):
    cpu_pct = 0.0
    mem_used = 0
    mem_pct = 0.0
    new_prev = {}
    
    for pid in pids:
        try:
            p = psutil.Process(pid)
            times = p.cpu_times()
            if pid in prev_cpu and elapsed > 0:
                dt = (times.user + times.system) - (
                    prev_cpu[pid].user + prev_cpu[pid].system)
                cpu_pct += 100.0 * dt / elapsed
            new_prev[pid] = times
            mi = p.memory_info()
            mem_used += mi.rss
            mem_pct += p.memory_percent()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    # Get total CPU cycles for all pids from shared data
    total_cpu_cycles_ghz = cycle_data.get_total_process(pids) if pids else 0.0
            
    return cpu_pct, mem_used, mem_pct, new_prev, total_cpu_cycles_ghz

def get_clockdiff_target_ip():
    """Check local IPs and return the remote target for clockdiff."""
    try:
        result = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
        if result.returncode != 0:
            return None
        
        output = result.stdout
        if '172.16.1.4' in output:
            return '172.16.1.3'
        if '172.16.1.3' in output:
            return '172.16.1.4'
    except (subprocess.SubprocessError, FileNotFoundError):
        return None
    return None

def check_clockdiff_response_time(target_ip):
    """Runs clockdiff once to measure and print its response time."""
    if not target_ip:
        print("clockdiff: No target IP found, skipping response time check.", file=sys.stderr)
        return
    
    print(f"clockdiff: Checking initial response time for {target_ip}...", file=sys.stderr)
    try:
        cmd = ["sudo", "clockdiff", target_ip]
        t0 = time.time()
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10
        )
        t1 = time.time()
        
        if result.returncode == 0:
            print(f"clockdiff: Initial response time: {t1 - t0:.4f} seconds.", file=sys.stderr)
        else:
            print(f"clockdiff: Initial check failed. Exit code: {result.returncode}", file=sys.stderr)
            if result.stderr:
                print(f"clockdiff stderr: {result.stderr.strip()}", file=sys.stderr)
                
    except Exception as e:
        print(f"clockdiff: An error occurred during initial check: {e}", file=sys.stderr)

def monitor(args, csv_output):
    # Get current date/time and username for the header
    current_datetime = get_formatted_datetime()
    current_user = get_current_user()
    
    print(f"Monitoring started at {current_datetime} by user {current_user}", file=sys.stderr)
    
    fieldnames = [
        'time', 'date_time', 'user', 'sys_cpu_percent', 'sys_cpu_cycles_ghz', 
        'sys_mem_used_mb', 'sys_mem_percent', 'proc_cpu_percent', 
        'proc_cpu_cycles_ghz', 'proc_mem_mb', 'proc_mem_percent', 
        'conntrack_count', 'pids', 'clock_delta_ms'
    ]
    writer = csv.DictWriter(csv_output, fieldnames=fieldnames)
    writer.writeheader()

    def shutdown(signum, frame):
        print("Shutting down monitor.", file=sys.stderr)
        if args.daemon:
            try:
                os.remove(PID_FILE)
            except FileNotFoundError:
                pass
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    if args.daemon:
        # Ensure directory exists for PID file
        os.makedirs(os.path.dirname(PID_FILE), exist_ok=True)
        with open(PID_FILE, 'w') as f:
            f.write(str(os.getpid()))
        print(f"Daemon started with PID {os.getpid()}.", file=sys.stderr)

    # Start system CPU cycles thread
    sys_thread = threading.Thread(target=system_cycles_thread, daemon=True)
    sys_thread.start()
    
    # Find clockdiff target and start the monitoring thread
    clockdiff_target_ip = get_clockdiff_target_ip()
    if clockdiff_target_ip:
        print(f"Found local IP, targeting {clockdiff_target_ip} for clockdiff.", file=sys.stderr)
        # Perform the one-time response check before starting the thread
        check_clockdiff_response_time(clockdiff_target_ip)
        
        # Start the continuous monitoring thread
        clockdiff_th = threading.Thread(
            target=clockdiff_thread, 
            args=(clockdiff_target_ip, args.interval), 
            daemon=True
        )
        clockdiff_th.start()

    # Process threads dictionary
    process_threads = {}
    
    prev_cpu = None
    prev_proc_cpu = {}
    last_time = None

    while True:
        try:
            t0 = time.time()
            ts = timestamp_ns()
            current_datetime = get_formatted_datetime()
            current_user = get_current_user()  # Refresh username
            elapsed = t0 - (last_time or t0)

            sys_pct, sys_mem, sys_mem_pct, cpu_t, sys_cpu_cycles_ghz = get_system_stats(prev_cpu, elapsed)
            
            # Get conntrack count
            conntrack_count = get_conntrack_count()

            pids = []
            if args.program:
                for p in psutil.process_iter(['name']):
                    if p.info['name'] == args.program:
                        pids.append(p.pid)
            
            # Start threads for new PIDs
            for pid in pids:
                if pid not in process_threads:
                    thread = threading.Thread(target=process_cycles_thread, args=(pid,), daemon=True)
                    process_threads[pid] = thread
                    thread.start()
                    
            proc_cpu, proc_mem, proc_mem_pct, prev_proc_cpu, proc_cpu_cycles_ghz = get_process_stats(pids, prev_proc_cpu, elapsed)

            # Prepare CPU cycle values for output
            sys_cycles_str = f"{sys_cpu_cycles_ghz:.6f}"
            
            # Only include process CPU cycles if we're monitoring a specific program
            if args.program and pids:
                proc_cpu_str = f"{proc_cpu:.2f}"
                proc_cycles_str = f"{proc_cpu_cycles_ghz:.6f}"
                proc_mem_mb_str = f"{proc_mem / (1024*1024):.2f}"
                proc_mem_pct_str = f"{proc_mem_pct:.2f}"
                pids_str = f"[{';'.join(map(str, pids))}]"
            else:
                proc_cpu_str = ""
                proc_cycles_str = ""
                proc_mem_mb_str = ""
                proc_mem_pct_str = ""
                pids_str = "[]"
            
            # Get clock delta
            clock_delta = cycle_data.get_clock_delta()
            clock_delta_str = str(clock_delta) if clock_delta is not None else "N/A"

            row = {
                'time': ts,
                'date_time': current_datetime,
                'user': current_user,
                'sys_cpu_percent': f"{sys_pct:.2f}",
                'sys_cpu_cycles_ghz': sys_cycles_str,
                'sys_mem_used_mb': f"{sys_mem / (1024*1024):.2f}",
                'sys_mem_percent': f"{sys_mem_pct:.2f}",
                'proc_cpu_percent': proc_cpu_str,
                'proc_cpu_cycles_ghz': proc_cycles_str,
                'proc_mem_mb': proc_mem_mb_str,
                'proc_mem_percent': proc_mem_pct_str,
                'conntrack_count': str(conntrack_count) if conntrack_count is not None else '',
                'pids': pids_str,
                'clock_delta_ms': clock_delta_str
            }

            writer.writerow(row)
            csv_output.flush()

            prev_cpu = cpu_t
            last_time = t0

            # Account for the time taken to collect data
            elapsed_time = time.time() - t0
            sleep_time = max(0, args.interval - elapsed_time)
            time.sleep(sleep_time)
        except Exception as e:
            print(f"Error in main monitoring loop: {e}", file=sys.stderr)
            time.sleep(1)  # Wait a bit before retrying

def daemonize_and_run(args, csv_output):
    if os.fork() > 0:
        return
    os.setsid()
    if os.fork() > 0:
        sys.exit(0)
    os.umask(0)
    sys.stdin.flush(); sys.stdout.flush(); sys.stderr.flush()
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_path = os.path.join(script_dir, "cpu_mem_monitor_stdout.log")
    log_file = open(log_path, "a+")
    os.dup2(log_file.fileno(), sys.stdout.fileno())
    os.dup2(log_file.fileno(), sys.stderr.fileno())
    monitor(args, csv_output)

def main():
    parser = argparse.ArgumentParser(description="CPU and Memory Monitor")
    parser.add_argument('-p', '--program', help="Exact process name to monitor")
    parser.add_argument('-i', '--interval', type=float, default=DEFAULT_INTERVAL,
                        help="Monitoring interval in seconds")
    parser.add_argument('-d', '--daemon', action='store_true', help="Run as daemon")
    parser.add_argument('-k', '--kill', action='store_true', help="Kill running daemon")
    parser.add_argument('-l', '--log', help="CSV output file path")
    args = parser.parse_args()

    if args.kill:
        if os.path.exists(PID_FILE):
            try:
                with open(PID_FILE) as f:
                    pid = int(f.read().strip())
                try:
                    # Check if the process exists before trying to kill it
                    if psutil.pid_exists(pid):
                        os.kill(pid, signal.SIGTERM)
                        print(f"Terminated daemon with PID {pid}", file=sys.stderr)
                    else:
                        print(f"Process with PID {pid} no longer exists. Cleaning up PID file.", file=sys.stderr)
                except ProcessLookupError:
                    print(f"Process with PID {pid} no longer exists. Cleaning up PID file.", file=sys.stderr)
                
                # Always try to clean up the PID file
                try:
                    os.remove(PID_FILE)
                    print("PID file removed.", file=sys.stderr)
                except FileNotFoundError:
                    print("PID file already removed.", file=sys.stderr)
            except (ValueError, IOError) as e:
                print(f"Error reading PID file: {e}", file=sys.stderr)
                try:
                    os.remove(PID_FILE)
                except FileNotFoundError:
                    pass
        else:
            print("No daemon PID file found.", file=sys.stderr)
        sys.exit(0)

    if args.log:
        # Ensure the directory exists for the log file
        log_dir = os.path.dirname(args.log)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
            
        with open(args.log, 'w', newline='') as csv_output:
            if args.daemon:
                daemonize_and_run(args, csv_output)
            else:
                monitor(args, csv_output)
    else:
        if args.daemon:
            daemonize_and_run(args, sys.stdout)
        else:
            monitor(args, sys.stdout)

if __name__ == '__main__':
    main()
