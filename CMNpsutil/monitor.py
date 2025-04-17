#!/usr/bin/env python3
import psutil
import time
import argparse
import sys
import os
from datetime import datetime

try:
    from daemon import DaemonContext
    import lockfile
except ImportError:
    print("Please install python-daemon: pip install python-daemon", file=sys.stderr)
    sys.exit(1)

import signal
import ctypes

# PID file for daemon tracking
PID_FILE = '/tmp/monitor.pid'

# TSC variables
tsc_freq = None
tsc_offset = 0

# --- Utility Functions ---

def calibrate_tsc():
    """Calibrate TSC frequency and offset to align with epoch time in nanoseconds."""
    global tsc_freq, tsc_offset
    try:
        libc = ctypes.CDLL(None)
        libc.__cpuid(0, 0, 0, 0, 0)
        tsc_start = read_tsc()
        epoch_start = time.time_ns()
        time.sleep(1)
        libc.__cpuid(0, 0, 0, 0, 0)
        tsc_end = read_tsc()
        epoch_end = time.time_ns()
        elapsed_tsc = tsc_end - tsc_start
        elapsed_ns = epoch_end - epoch_start
        tsc_freq = elapsed_tsc / elapsed_ns
        tsc_offset = epoch_start - int(tsc_start / tsc_freq)
    except Exception:
        tsc_freq = None
        tsc_offset = 0

def read_tsc():
    """Read the system clock (intended as TSC) or fall back to perf_counter_ns."""
    try:
        return ctypes.c_uint64(time.clock_gettime_ns(time.CLOCK_REALTIME)).value
    except Exception:
        return time.perf_counter_ns()

def tsc_to_ns():
    """Convert TSC-like clock to nanoseconds since epoch."""
    if tsc_freq is None:
        return time.perf_counter_ns()
    return int(read_tsc() / tsc_freq) + tsc_offset

def log_to_file(log_file, message):
    """Append a message to the specified log file."""
    with open(log_file, 'a') as f:
        f.write(message + '\n')

# --- Stats Collection Functions ---

def find_pids(program_name):
    """Find all process IDs for the given program name."""
    pids = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if program_name.lower() in proc.info['name'].lower():
                pids.append(proc.info['pid'])
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            print(f"Error accessing process {proc.info['pid']}: {e}", file=sys.stderr)
    return pids

def get_system_stats(prev_cpu_times, elapsed_time):
    """Retrieve system-wide CPU, memory, and network statistics."""
    curr_cpu_times = psutil.cpu_times()
    if prev_cpu_times and elapsed_time > 0:
        total_delta = sum(curr_cpu_times) - sum(prev_cpu_times)
        idle_delta = curr_cpu_times.idle - prev_cpu_times.idle
        sys_cpu_total = 100 * (total_delta - idle_delta) / total_delta if total_delta > 0 else 0.0
    else:
        sys_cpu_total = 0.0
    mem = psutil.virtual_memory()
    sys_mem_mb = mem.used / (1024 * 1024)
    sys_mem_percent = mem.percent
    net_io = psutil.net_io_counters()
    return sys_cpu_total, sys_mem_mb, sys_mem_percent, net_io.bytes_sent, net_io.bytes_recv, curr_cpu_times

def get_process_stats(pids, prev_proc_times, elapsed_time):
    """Get process CPU, memory, and network stats for specified PIDs."""
    proc_cpu_percent = 0.0
    mem_mb = 0.0
    mem_percent = 0.0
    total_mem = psutil.virtual_memory().total
    curr_proc_times = {}
    for pid in pids:
        try:
            proc = psutil.Process(pid)
            curr_times = proc.cpu_times()
            curr_proc_times[pid] = curr_times
            if pid in prev_proc_times and elapsed_time > 0:
                delta_user = curr_times.user - prev_proc_times[pid].user
                delta_system = curr_times.system - prev_proc_times[pid].system
                proc_cpu_percent += (delta_user + delta_system) / elapsed_time * 100
            mem_info = proc.memory_info()
            mem_used = getattr(mem_info, 'pss', mem_info.rss)
            mem_mb += mem_used / (1024 * 1024)
            mem_percent += (mem_used / total_mem) * 100
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            print(f"Error accessing process {pid}: {e}", file=sys.stderr)
    net_io = psutil.net_io_counters()
    return proc_cpu_percent, mem_mb, mem_percent, net_io.bytes_sent, net_io.bytes_recv, curr_proc_times

# --- Daemon Management ---

def kill_daemon():
    """Kill the daemon process using the PID file."""
    if not os.path.exists(PID_FILE):
        print("No PID file found. Is the daemon running?", file=sys.stderr)
        sys.exit(1)
    try:
        with open(PID_FILE, 'r') as f:
            pid = int(f.read().strip())
        os.kill(pid, signal.SIGTERM)
        print(f"Daemon with PID {pid} terminated.", file=sys.stderr)
        os.remove(PID_FILE)
    except (ValueError, OSError) as e:
        print(f"Failed to kill daemon: {e}", file=sys.stderr)
        sys.exit(1)

# --- Main Monitoring Function ---

def monitor_program(program_name, log_file, interval, daemonize=False):
    """Monitor system and program resource usage with high-precision timestamp."""
    calibrate_tsc()

    last_sys_sent, last_sys_recv = 0, 0
    last_proc_sent, last_proc_recv = 0, 0
    prev_cpu_times = None
    prev_proc_times = {}
    last_time = None

    pid_refresh_interval = 10
    pid_refresh_counter = 0
    pids = None if program_name else []

    header = f"Monitoring {'system and ' + program_name if program_name else 'system only'} (Refresh Interval: {interval}s, press Ctrl+C to stop)"
    subheader = ("Time (s), CPU_Computer_Total (%), Mem_Computer (MB), Mem_Computer (%), Net_Computer (KB/s), "
                 "CPU_Program (%), Mem_Program (MB), Mem_Program (%), Net_Program_SystemWide (KB/s)")
    start_time_str = datetime.now().isoformat()
    start_msg = f"Monitoring started at {start_time_str}"
    note = "# Note: Net_Program_SystemWide is based on system-wide network I/O, not per-process."

    if not daemonize:
        print(header)
        print(subheader)
        print(start_msg)
        if program_name:
            print(note)
    if log_file:
        log_to_file(log_file, header)
        log_to_file(log_file, subheader)
        log_to_file(log_file, start_msg)
        if program_name:
            log_to_file(log_file, note)

    net_io = psutil.net_io_counters()
    last_sys_sent, last_sys_recv = net_io.bytes_sent, net_io.bytes_recv
    last_proc_sent, last_proc_recv = net_io.bytes_sent, net_io.bytes_recv

    while True:
        try:
            start_time = time.time()
            current_time_ns = tsc_to_ns()
            elapsed_time = start_time - last_time if last_time is not None else 0.0

            if program_name:
                if pids is None or pid_refresh_counter % pid_refresh_interval == 0:
                    pids = find_pids(program_name)
                pid_refresh_counter += 1

            sys_cpu_total, sys_mem_mb, sys_mem_percent, sys_current_sent, sys_current_recv, curr_cpu_times = get_system_stats(
                prev_cpu_times, elapsed_time)
            sys_net_rate = ((sys_current_sent - last_sys_sent) + (sys_current_recv - last_sys_recv)) / elapsed_time / 1024 if elapsed_time > 0 else 0.0

            if not program_name:
                message = f"{current_time_ns / 1e9:.6f}, {sys_cpu_total:.2f}, {sys_mem_mb:.2f}, {sys_mem_percent:.2f}, {sys_net_rate:.2f}, N/A, N/A, N/A, N/A"
            elif not pids:
                message = f"{current_time_ns / 1e9:.6f}, {sys_cpu_total:.2f}, {sys_mem_mb:.2f}, {sys_mem_percent:.2f}, {sys_net_rate:.2f}, 0.00, 0.00, 0.00, 0.00"
            else:
                proc_cpu_percent, proc_mem_mb, proc_mem_percent, proc_current_sent, proc_current_recv, curr_proc_times = get_process_stats(
                    pids, prev_proc_times, elapsed_time)
                proc_net_rate = ((proc_current_sent - last_proc_sent) + (proc_current_recv - last_proc_recv)) / elapsed_time / 1024 if elapsed_time > 0 else 0.0
                message = f"{current_time_ns / 1e9:.6f}, {sys_cpu_total:.2f}, {sys_mem_mb:.2f}, {sys_mem_percent:.2f}, {sys_net_rate:.2f}, {proc_cpu_percent:.2f}, {proc_mem_mb:.2f}, {proc_mem_percent:.2f}, {proc_net_rate:.2f}"
                last_proc_sent, last_proc_recv = proc_current_sent, proc_current_recv
                prev_proc_times = curr_proc_times

            if not daemonize:
                print(message)
            if log_file:
                log_to_file(log_file, message)

            last_sys_sent, last_sys_recv = sys_current_sent, sys_current_recv
            prev_cpu_times = curr_cpu_times
            last_time = start_time

            end_time = time.time()
            execution_time = end_time - start_time
            sleep_time = max(0, interval - execution_time)
            time.sleep(sleep_time)

        except KeyboardInterrupt:
            stop_time_str = datetime.now().isoformat()
            stop_msg = f"Monitoring stopped by user at {stop_time_str}"
            if not daemonize:
                print(stop_msg)
            if log_file:
                log_to_file(log_file, stop_msg)
            break
        except Exception as e:
            error_msg = f"Error: {e}"
            if not daemonize:
                print(error_msg, file=sys.stderr)
            if log_file:
                log_to_file(log_file, error_msg)
            time.sleep(interval)

# --- Main Entry Point ---

def main():
    """Parse arguments and start monitoring or kill daemon."""
    parser = argparse.ArgumentParser(description="Monitor system and program resource usage.")
    parser.add_argument('-p', '--program', type=str, help="Name of the program to monitor (e.g., 'python')")
    parser.add_argument('-l', '--log', type=str, help="Log file path to store output")
    parser.add_argument('-i', '--interval', type=float, default=5.0, help="Monitoring interval in seconds (default: 5)")
    parser.add_argument('-d', '--daemonize', action='store_true', help="Run as a daemon in the background")
    parser.add_argument('-k', '--kill', action='store_true', help="Kill the running daemon")
    args = parser.parse_args()

    if args.kill:
        kill_daemon()
        sys.exit(0)

    if args.daemonize:
        if not args.log:
            print("Error: -l/--log is required when daemonizing.", file=sys.stderr)
            sys.exit(1)
        try:
            with open(args.log, 'a') as f:
                pass
        except Exception as e:
            print(f"Error: Cannot write to log file {args.log}: {e}", file=sys.stderr)
            sys.exit(1)
        with DaemonContext(pidfile=lockfile.FileLock(PID_FILE), stdout=open(args.log, 'a'), stderr=open(args.log, 'a')):
            monitor_program(args.program, args.log, args.interval, daemonize=True)
    else:
        monitor_program(args.program, args.log, args.interval, daemonize=False)

if __name__ == "__main__":
    main()
