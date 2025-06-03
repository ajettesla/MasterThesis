#!/usr/bin/env python3
import argparse
import csv
import datetime
import logging
import os
import signal
import sys
import threading
import time
from collections import defaultdict

def parse_line(line):
    """
    Parse a single log line into its components.
    Returns a dictionary of extracted fields or None if invalid.
    """
    parts = line.strip().split()
    if len(parts) != 8:
        return None  # Invalid line
    try:
        timestamp_str = parts[0]
        timestamp = datetime.datetime.fromisoformat(timestamp_str)
        ip = parts[1]
        device = parts[2]
        program = parts[3]
        payload_str = parts[7]
        payload_fields = payload_str.split(',')
        if len(payload_fields) != 10:
            return None  # Invalid payload
        seqno = int(payload_fields[0])
        timestamp_nano = int(payload_fields[1])
        hash_value = payload_fields[2]
        type_num = int(payload_fields[3])
        state_num = int(payload_fields[4])
        proto_num = int(payload_fields[5])
        srcip = payload_fields[6]
        srcport = int(payload_fields[7])
        dstip = payload_fields[8]
        dstport = int(payload_fields[9])
    except (ValueError, IndexError):
        return None  # Invalid data
    return {
        'timestamp': timestamp,
        'device': device,
        'hash': hash_value,
        'type_num': type_num,
        'state_num': state_num,
        'proto_num': proto_num,
        'srcip': srcip,
        'srcport': srcport,
        'dstip': dstip,
        'dstport': dstport,
        'payload': payload_str,
        'timestamp_nano': timestamp_nano
    }

def process_entry(entry, device_a, device_b, dict_a, dict_b, writer, totals, lock, debug_mode):
    """
    Process a single log entry, checking for matches and writing results.
    """
    D = entry['device']
    if D not in [device_a, device_b]:
        return
    K = (entry['hash'], entry['type_num'], entry['state_num'], entry['proto_num'], 
         entry['srcip'], entry['srcport'], entry['dstip'], entry['dstport'])
    if D == device_a:
        self_dict = dict_a
        other_dict = dict_b
        other_D = device_b
    else:
        self_dict = dict_b
        other_dict = dict_a
        other_D = device_a
    matched = False
    if K in other_dict and other_dict[K]:
        for other_entry in list(other_dict[K]):
            diff_nano = entry['timestamp_nano'] - other_entry['timestamp_nano']
            debug_str = f"{D} ({entry['payload']}) -> {other_D} ({other_entry['payload']})" if debug_mode else ''
            writer.writerow([diff_nano, entry['proto_num'], entry['state_num'], debug_str])
            with lock:
                totals[1] += 1
            logging.debug(f"Match found: {D} ({entry['payload']}) -> {other_D} ({other_entry['payload']}) (matched)")
            other_dict[K].remove(other_entry)
            matched = True
    if not matched:
        self_dict[K].append(entry)

def periodic_print(lock, totals, stop_event):
    """
    Periodically log total lines read and matches found until stopped.
    """
    while not stop_event.is_set():
        time.sleep(5)
        with lock:
            lines = totals[0]
            matches = totals[1]
        logging.info(f"Total lines read: {lines}")
        logging.info(f"Total matches found: {matches}")

def main():
    """
    Process conntrack logs, with options for daemon mode, killing the program, and debug output.
    """
    parser = argparse.ArgumentParser(description="Process conntrack logs for matching entries.")
    parser.add_argument('-a', help="Name of device A")
    parser.add_argument('-b', help="Name of device B")
    parser.add_argument('-l', help="Path to log file")
    parser.add_argument('-o', help="Path to output CSV file")
    parser.add_argument('-d', action='store_true', help="Enable debug mode")
    parser.add_argument('-k', action='store_true', help="Kill the running instance")
    parser.add_argument('-D', action='store_true', help="Run in daemon mode")
    parser.add_argument('-L', help="Log file path (default: ~/.conntrack_processor.log)")
    args = parser.parse_args()

    pid_file = '/tmp/conntrack_processor.pid'

    if args.k:
        if os.path.exists(pid_file):
            with open(pid_file, 'r') as f:
                pid = int(f.read().strip())
            try:
                os.kill(pid, signal.SIGTERM)
                print(f"Sent SIGTERM to process {pid}")
            except ProcessLookupError:
                print(f"No process with PID {pid}")
            os.remove(pid_file)
        else:
            print("No running instance found")
        sys.exit(0)
    else:
        if os.path.exists(pid_file):
            with open(pid_file, 'r') as f:
                pid = int(f.read().strip())
            try:
                os.kill(pid, 0)
                print(f"Instance already running with PID {pid}")
                sys.exit(1)
            except ProcessLookupError:
                # Remove stale PID file
                os.remove(pid_file)

        if args.D:
            if args.L:
                log_file = args.L
            else:
                log_file = os.path.expanduser('~/.conntrack_processor.log')
            # Daemonize
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
            # Child process
            os.setsid()
            os.chdir('/')
            # Second fork
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
            # Grandchild process
            # Redirect stdin
            with open('/dev/null', 'r') as devnull:
                os.dup2(devnull.fileno(), sys.stdin.fileno())
            # Redirect stdout and stderr to log_file
            try:
                log_fd = os.open(log_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
                os.dup2(log_fd, sys.stdout.fileno())
                os.dup2(log_fd, sys.stderr.fileno())
                os.close(log_fd)
            except OSError as e:
                sys.exit(1)
            # Write PID file
            with open(pid_file, 'w') as f:
                f.write(str(os.getpid()))
            # Set up logging
            logging.basicConfig(stream=sys.stdout, level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
        else:
            # Not daemon mode
            logging.basicConfig(stream=sys.stdout, level=logging.INFO, format='%(message)s')

        if args.d:
            logging.getLogger().setLevel(logging.DEBUG)

        if not args.D and not all([args.a, args.b, args.l, args.o]):
            parser.error("Options -a, -b, -l, -o are required when not in daemon mode or when -k is not provided")

        logging.info("Starting conntrack processor")

    device_a = args.a
    device_b = args.b
    log_file = args.l
    output_file = args.o
    debug_mode = args.d

    if not os.path.exists(output_file):
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['timedifference', 'protocol_num', 'state_num', 'debug_info'])

    csvfile = open(output_file, 'a', newline='')
    writer = csv.writer(csvfile)

    dict_a = defaultdict(list)
    dict_b = defaultdict(list)
    lock = threading.Lock()
    totals = [0, 0]
    last_flush_time = time.time()

    stop_event = threading.Event()

    def signal_handler(signum, frame):
        logging.info(f"Received signal {signum}, shutting down")
        stop_event.set()

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    print_thread = threading.Thread(target=periodic_print, args=(lock, totals, stop_event), daemon=True)
    print_thread.start()

    with open(log_file, 'r') as f:
        while not stop_event.is_set():
            line = f.readline()
            if line:
                logging.debug(f"Read line: {line.strip()}")
                with lock:
                    totals[0] += 1
                entry = parse_line(line)
                if entry:
                    process_entry(entry, device_a, device_b, dict_a, dict_b, writer, totals, lock, debug_mode)
            else:
                time.sleep(0.1)

            current_time = time.time()
            if current_time - last_flush_time >= 5:
                csvfile.flush()
                last_flush_time = current_time

    logging.info("Exiting")
    os.remove(pid_file)

if __name__ == '__main__':
    main()
