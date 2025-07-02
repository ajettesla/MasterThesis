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

PID_FILE = '/tmp/exp/network_monitor.pid'
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

def get_system_net_stats(prev_net, elapsed):
    net = psutil.net_io_counters()
    net_rate = 0.0
    if prev_net and elapsed > 0:
        sent_d = net.bytes_sent - prev_net.bytes_sent
        recv_d = net.bytes_recv - prev_net.bytes_recv
        net_rate = (sent_d + recv_d) / elapsed / 1024
    return net_rate, net

def monitor(args, csv_output):
    fieldnames = [
        'time', 'sys_net_kbps',
        'total_bytes_sent', 'total_bytes_recv', 'total_packets_sent', 'total_packets_recv',
        'total_errin', 'total_errout', 'total_dropin', 'total_dropout',
        'iface_rx_bytes', 'iface_rx_packets', 'iface_tx_bytes', 'iface_tx_packets',
        'iface_rx_bytes_per_sec', 'iface_tx_bytes_per_sec',
        'iface_rx_packets_per_sec', 'iface_tx_packets_per_sec',
        'iface_rx_errors', 'iface_rx_dropped', 'iface_tx_errors', 'iface_tx_dropped'
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

    prev_net = None
    last_time = None
    last_iface = None
    if args.iface:
        last_iface = get_interface_stats(args.iface)

    print("Monitoring started.", file=sys.stderr)
    while True:
        t0 = time.time()
        ts = timestamp_ns()
        elapsed = t0 - (last_time or t0)

        sys_net, net_t = get_system_net_stats(prev_net, elapsed)

        row = {
            'time': ts,
            'sys_net_kbps': f"{sys_net:.2f}",
            'total_bytes_sent': net_t.bytes_sent,
            'total_bytes_recv': net_t.bytes_recv,
            'total_packets_sent': net_t.packets_sent,
            'total_packets_recv': net_t.packets_recv,
            'total_errin': net_t.errin,
            'total_errout': net_t.errout,
            'total_dropin': net_t.dropin,
            'total_dropout': net_t.dropout,
        }

        if args.iface:
            current = get_interface_stats(args.iface)
            if current:
                iface_data = {
                    'iface_rx_bytes': current['rx_bytes'],
                    'iface_rx_packets': current['rx_packets'],
                    'iface_tx_bytes': current['tx_bytes'],
                    'iface_tx_packets': current['tx_packets'],
                    'iface_rx_errors': current['rx_errors'],
                    'iface_rx_dropped': current['rx_dropped'],
                    'iface_tx_errors': current['tx_errors'],
                    'iface_tx_dropped': current['tx_dropped'],
                }
                if last_iface and elapsed > 0:
                    iface_data.update({
                        'iface_rx_bytes_per_sec': f"{(current['rx_bytes'] - last_iface['rx_bytes']) / elapsed:.2f}",
                        'iface_tx_bytes_per_sec': f"{(current['tx_bytes'] - last_iface['tx_bytes']) / elapsed:.2f}",
                        'iface_rx_packets_per_sec': f"{(current['rx_packets'] - last_iface['rx_packets']) / elapsed:.2f}",
                        'iface_tx_packets_per_sec': f"{(current['tx_packets'] - last_iface['tx_packets']) / elapsed:.2f}",
                    })
                else:
                    iface_data.update({
                        'iface_rx_bytes_per_sec': '',
                        'iface_tx_bytes_per_sec': '',
                        'iface_rx_packets_per_sec': '',
                        'iface_tx_packets_per_sec': '',
                    })
                last_iface = current
            else:
                iface_data = {k: '' for k in [
                    'iface_rx_bytes', 'iface_rx_packets', 'iface_tx_bytes', 'iface_tx_packets',
                    'iface_rx_errors', 'iface_rx_dropped', 'iface_tx_errors', 'iface_tx_dropped',
                    'iface_rx_bytes_per_sec', 'iface_tx_bytes_per_sec',
                    'iface_rx_packets_per_sec', 'iface_tx_packets_per_sec'
                ]}
        else:
            iface_data = {k: '' for k in [
                'iface_rx_bytes', 'iface_rx_packets', 'iface_tx_bytes', 'iface_tx_packets',
                'iface_rx_errors', 'iface_rx_dropped', 'iface_tx_errors', 'iface_tx_dropped',
                'iface_rx_bytes_per_sec', 'iface_tx_bytes_per_sec',
                'iface_rx_packets_per_sec', 'iface_tx_packets_per_sec'
            ]}

        row.update(iface_data)
        writer.writerow(row)
        csv_output.flush()

        prev_net = net_t
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
    log_path = os.path.join(script_dir, "network_monitor_stdout.log")
    log_file = open(log_path, "a+")
    os.dup2(log_file.fileno(), sys.stdout.fileno())
    os.dup2(log_file.fileno(), sys.stderr.fileno())
    monitor(args, csv_output)

def main():
    parser = argparse.ArgumentParser(description="Network Monitor with Cumulative Stats")
    parser.add_argument('-i', '--interval', type=float, default=DEFAULT_INTERVAL,
                        help="Monitoring interval in seconds")
    parser.add_argument('-d', '--daemon', action='store_true', help="Run as daemon")
    parser.add_argument('-k', '--kill', action='store_true', help="Kill running daemon")
    parser.add_argument('--iface', help="Network interface to monitor (e.g., enp0s3)")
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
