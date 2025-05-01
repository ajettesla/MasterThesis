#!/usr/bin/env python3
import psutil
import time
import argparse
import sys
import os
import signal
import csv
from datetime import datetime

PID_FILE = '/tmp/cpu_mem_monitor.pid'
DEFAULT_INTERVAL = 5.0

def timestamp_ns():
    ts = time.time_ns()
    sec = ts // 1_000_000_000
    nsec = ts % 1_000_000_000
    return f"{sec}.{nsec:09d}"

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
    return sys_pct, mem.used, mem.percent, cpu

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
    return cpu_pct, mem_used, mem_pct, new_prev

def monitor(args, csv_output):
    fieldnames = [
        'time', 'sys_cpu_percent', 'sys_mem_used_mb', 'sys_mem_percent',
        'proc_cpu_percent', 'proc_mem_mb', 'proc_mem_percent', 'pids'
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
        with open(PID_FILE, 'w') as f:
            f.write(str(os.getpid()))
        print(f"Daemon started with PID {os.getpid()}.", file=sys.stderr)

    prev_cpu = None
    prev_proc_cpu = {}
    last_time = None

    print("Monitoring started.", file=sys.stderr)
    while True:
        t0 = time.time()
        ts = timestamp_ns()
        elapsed = t0 - (last_time or t0)

        sys_pct, sys_mem, sys_mem_pct, cpu_t = get_system_stats(prev_cpu, elapsed)

        pids = []
        if args.program:
            for p in psutil.process_iter(['name']):
                if p.info['name'] == args.program:
                    pids.append(p.pid)
        proc_cpu, proc_mem, proc_mem_pct, prev_proc_cpu = get_process_stats(pids, prev_proc_cpu, elapsed)

        row = {
            'time': ts,
            'sys_cpu_percent': f"{sys_pct:.2f}",
            'sys_mem_used_mb': f"{sys_mem / (1024*1024):.2f}",
            'sys_mem_percent': f"{sys_mem_pct:.2f}",
            'proc_cpu_percent': f"{proc_cpu:.2f}" if args.program else '',
            'proc_mem_mb': f"{proc_mem / (1024*1024):.2f}" if args.program else '',
            'proc_mem_percent': f"{proc_mem_pct:.2f}" if args.program else '',
            'pids': f"[{';'.join(map(str, pids))}]" if pids else "[]",
        }

        writer.writerow(row)
        csv_output.flush()

        prev_cpu = cpu_t
        last_time = t0

        time.sleep(max(0, args.interval - (time.time() - t0)))

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
            with open(PID_FILE) as f:
                pid = int(f.read().strip())
            os.kill(pid, signal.SIGTERM)
            print(f"Terminated daemon {pid}", file=sys.stderr)
            try:
                os.remove(PID_FILE)
            except FileNotFoundError:
                pass
        else:
            print("No daemon PID file found.", file=sys.stderr)
        sys.exit(0)

    if args.log:
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
