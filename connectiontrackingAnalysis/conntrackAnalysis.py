#!/usr/bin/env python3
import argparse
import csv
import datetime
from collections import defaultdict
import time
import os
import threading
from threading import Lock

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
        # Ignore parts[4], [5], [6] as they are placeholders ("-")
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
        'payload': payload_str,  # Add full payload string
    }

def process_entry(entry, device_a, device_b, dict_a, dict_b, writer, totals, lock, debug_mode):
    """
    Process a single log entry:
    - Check if it belongs to device_a or device_b.
    - If from device_a or device_b, check for matches in the other device.
    - If a match is found (same hash and payload), calculate timestamp difference and write to CSV.
    - If debug_mode is enabled, print match details.
    - Remove matched entries from both devices' dictionaries.
    - If no match is found, add the entry to the appropriate dictionary.
    """
    D = entry['device']
    if D not in [device_a, device_b]:
        return  # Ignore entries not from specified devices
    K = (entry['hash'], entry['type_num'], entry['state_num'], entry['proto_num'], 
         entry['srcip'], entry['srcport'], entry['dstip'], entry['dstport'])
    if D == device_a:
        self_dict = dict_a
        other_dict = dict_b
        other_D = device_b
    else:  # D == device_b
        self_dict = dict_b
        other_dict = dict_a
        other_D = device_a
    matched = False
    if K in other_dict and other_dict[K]:
        for item in list(other_dict[K]):
            if debug_mode:
                ts_other, payload_other = item
            else:
                ts_other = item
                payload_other = None
            diff = (entry['timestamp'] - ts_other).total_seconds()
            writer.writerow([diff, entry['proto_num'], entry['state_num']])
            with lock:
                totals[1] += 1  # Increment match counter
            if debug_mode:
                print(f"Match found: {D} ({entry['payload']}) -> {other_D} ({payload_other}) (matched)")
            other_dict[K].remove(item)
            matched = True
    if not matched:
        if debug_mode:
            self_dict[K].append((entry['timestamp'], entry['payload']))
        else:
            self_dict[K].append(entry['timestamp'])

def periodic_print(lock, totals):
    """
    Periodically print total lines read and total matches found.
    """
    while True:
        time.sleep(5)
        with lock:
            lines = totals[0]
            matches = totals[1]
        print(f"Total lines read: {lines}")
        print(f"Total matches found: {matches}")

def main():
    """
    Main function to handle command-line arguments, initialize data structures,
    and continuously process log files with periodic reporting.
    """
    parser = argparse.ArgumentParser(description="Process conntrack logs for matching entries.")
    parser.add_argument('-a', required=True, help="Name of device A")
    parser.add_argument('-b', required=True, help="Name of device B")
    parser.add_argument('-l', required=True, help="Path to log file")
    parser.add_argument('-o', required=True, help="Path to output CSV file")
    parser.add_argument('-d', action='store_true', help="Enable debug mode")
    args = parser.parse_args()
    
    device_a = args.a
    device_b = args.b
    log_file = args.l
    output_file = args.o
    debug_mode = args.d
    
    # Check if output file exists; if not, create it and write headers
    if not os.path.exists(output_file):
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['timedifference', 'protocol_num', 'state_num'])
    
    # Open output file for appending
    csvfile = open(output_file, 'a', newline='')
    writer = csv.writer(csvfile)
    
    # Initialize dictionaries for storing unmatched entries
    dict_a = defaultdict(list)  # Key: (hash, type_num, state_num, proto_num, srcip, srcport, dstip, dstport); Value: list of timestamps or (timestamp, payload)
    dict_b = defaultdict(list)
    
    # Initialize counters and timer for periodic reporting
    lock = Lock()
    totals = [0, 0]  # [total_lines_read, total_matches_found]
    last_flush_time = time.time()
    
    # Start periodic print thread
    print_thread = threading.Thread(target=periodic_print, args=(lock, totals), daemon=True)
    print_thread.start()
    
    # Open log file for reading
    with open(log_file, 'r') as f:
        while True:
            line = f.readline()
            if line:
                with lock:
                    totals[0] += 1  # Increment total lines read
                entry = parse_line(line)
                if entry:
                    process_entry(entry, device_a, device_b, dict_a, dict_b, writer, totals, lock, debug_mode)
            else:
                time.sleep(0.1)  # Sleep briefly if no new lines
            
            # Periodic CSV flush every 5 seconds
            current_time = time.time()
            if current_time - last_flush_time >= 5:
                csvfile.flush()
                last_flush_time = current_time

if __name__ == '__main__':
    main()
