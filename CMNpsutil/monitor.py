#!/usr/bin/env python3
import psutil
import time
import argparse
import sys
import os
import signal
import csv
import subprocess
from datetime import datetime

PID_FILE = '/tmp/monitor.pid'
DEFAULT_INTERVAL = 5.0

def timestamp_ns():
    ts = time.time_ns()
    sec = ts // 1_000_000_000
    nsec = ts % 1_000_000_000
    return f"{sec}.{nsec:09d}"

def get_interface_stats(interface):
    try:
        output = subprocess.check_output(
            ['ip', '-s', 'link', 'show', 'dev', interface],
            stderr=subprocess.DEVNULL,
            text=True
        )
        lines = output.splitlines()
        rx_line = next(l for l in lines if l.strip().startswith('RX:'))
        tx_line = next(l for l in lines if l.strip().startswith('TX:'))
        rx_vals = list(map(int, lines[lines.index(rx_line) + 1].split()))
        tx_vals = list(map(int, lines[lines.index(tx_line) + 1].split()))
        return {
            'rx_bytes': rx_vals[0],
            'rx_packets': rx_vals[1],
            'rx_errors': rx_vals[2],
            'rx_dropped': rx_vals[3],
            'tx_bytes': tx_vals[0],
            'tx_packets': tx_vals[1],
            'tx_errors': tx_vals[2],
            'tx_dropped': tx_vals[3],
        }
    except Exception:
        return None

def get_system_stats(prev_cpu, prev_net, elapsed):
    cpu = psutil.cpu_times()
    total = sum(cpu)
    idle = cpu.idle
    sys_pct = 0.0
    if prev_cpu and elapsed > 0:
        dt_total = total - sum(prev_cpu)
        dt_idle = idle - prev_cpu.idle
        sys_pct = 100.0 * (dt_total - dt_idle) / dt_total

    mem = psutil.virtual_memory()
    net = psutil.net_io_counters()
    net_rate = 0.0
    if prev_net and elapsed > 0:
        sent_d = net.bytes_sent - prev_net.bytes_sent
        recv_d = net.bytes_recv - prev_net.bytes_recv
        net_rate = (sent_d + recv_d) / elapsed / 1024

    return sys_pct, mem.used, mem.percent, net_rate, cpu, net

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
        'time', 'sys_cpu_percent', 'sys_mem_used_mb', 'sys_mem_percent', 'sys_net_kbps',
        'proc_cpu_percent', 'proc_mem_mb', 'proc_mem_percent', 'pids',
        'rx_bytes_per_sec', 'tx_bytes_per_sec', 'rx_packets_per_sec', 'tx_packets_per_sec',
        'rx_errors', 'rx_dropped', 'tx_errors', 'tx_dropped'
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
    prev_net = None
    prev_proc_cpu = {}
    last_time = None
    last_iface = None
    if args.iface:
        last_iface = get_interface_stats(args.iface)

    print("Monitoring started.", file=sys.stderr)
    while True:
        t0 = time.time()
        ts = timestamp_ns()
        elapsed = t0 - (last_time or t0)

        sys_pct, sys_mem, sys_mem_pct, sys_net, cpu_t, net_t = \
            get_system_stats(prev_cpu, prev_net, elapsed)

        pids = []
        if args.program:
            for p in psutil.process_iter(['name']):
                if p.info['name'] == args.program:
                    pids.append(p.pid)
        proc_cpu, proc_mem, proc_mem_pct, prev_proc_cpu = \
            get_process_stats(pids, prev_proc_cpu, elapsed)

        iface_data = dict.fromkeys(
            ['rx_bytes_per_sec', 'tx_bytes_per_sec', 'rx_packets_per_sec', 'tx_packets_per_sec',
             'rx_errors', 'rx_dropped', 'tx_errors', 'tx_dropped'],
            ''
        )
        if args.iface and last_iface:
            current = get_interface_stats(args.iface)
            if current and elapsed > 0:
                iface_data = {
                    'rx_bytes_per_sec': f"{(current['rx_bytes'] - last_iface['rx_bytes']) / elapsed:.2f}",
                    'tx_bytes_per_sec': f"{(current['tx_bytes'] - last_iface['tx_bytes']) / elapsed:.2f}",
                    'rx_packets_per_sec': f"{(current['rx_packets'] - last_iface['rx_packets']) / elapsed:.2f}",
                    'tx_packets_per_sec': f"{(current['tx_packets'] - last_iface['tx_packets']) / elapsed:.2f}",
                    'rx_errors': current['rx_errors'],
                    'rx_dropped': current['rx_dropped'],
                    'tx_errors': current['tx_errors'],
                    'tx_dropped': current['tx_dropped'],
                }
            last_iface = current

        row = {
            'time': ts,
            'sys_cpu_percent': f"{sys_pct:.2f}",
            'sys_mem_used_mb': f"{sys_mem / (1024*1024):.2f}",
            'sys_mem_percent': f"{sys_mem_pct:.2f}",
            'sys_net_kbps': f"{sys_net:.2f}",
            'proc_cpu_percent': f"{proc_cpu:.2f}" if args.program else '',
            'proc_mem_mb': f"{proc_mem / (1024*1024):.2f}" if args.program else '',
            'proc_mem_percent': f"{proc_mem_pct:.2f}" if args.program else '',
            'pids': f"[{';'.join(map(str, pids))}]" if pids else "[]",
        }
        row.update(iface_data)

        writer.writerow(row)
        csv_output.flush()

        prev_cpu, prev_net = cpu_t, net_t
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
    # Redirect stdout/stderr to a log file in the script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_path = os.path.join(script_dir, "monitor_stdout.log")
    log_file = open(log_path, "a+")
    os.dup2(log_file.fileno(), sys.stdout.fileno())
    os.dup2(log_file.fileno(), sys.stderr.fileno())
    monitor(args, csv_output)

def main():
    parser = argparse.ArgumentParser(description="CSV output monitor with interface stats")
    parser.add_argument('-p', '--program', help="Exact process name to monitor")
    parser.add_argument('-i', '--interval', type=float, default=DEFAULT_INTERVAL,
                        help="Monitoring interval in seconds")
    parser.add_argument('-d', '--daemon', action='store_true', help="Run as daemon")
    parser.add_argument('-k', '--kill', action='store_true', help="Kill running daemon")
    parser.add_argument('--iface', help="Network interface to monitor (e.g., enp0s3)")
    parser.add_argument('-l', '--log', help="CSV output file path (writes CSV data here instead of stdout)")
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

