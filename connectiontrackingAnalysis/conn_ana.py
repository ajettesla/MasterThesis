#!/usr/bin/env python3

import re
import csv
import time
import argparse
import datetime
from collections import defaultdict, deque
import signal
import sys

# Regular expression patterns for parsing syslog entries
SYSLOG_PATTERN = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+\d{2}:\d{2})\s+(\S+)\s+;\s+(.*)'
MASTER_PATTERN = r'(\d+),(\d+),([a-f0-9]+),([^,]+),(\d+),([^,]+),(\d+),([^,]+),([^,]+),(\d+),([^,]+),([^,]*)'
SLAVE_PATTERN = r'(\d+),([a-f0-9]+),([^,]+),(\d+),([^,]+),(\d+),([^,]+),([^,]+),(\d+),([^,]+),([^,]*)'

class ConnectionTracker:
    def __init__(self, master_name, slave_name, output_file):
        self.master_name = master_name
        self.slave_name = slave_name
        self.output_file = output_file
        
        # Dictionary to store master events by hash
        self.master_events = {}
        
        # Queue for unmatched master events (ordered by timestamp)
        self.unmatched_queue = deque()
        
        # Statistics
        self.stats = {
            'total_master_events': 0,
            'total_slave_events': 0,
            'matched_events': 0,
            'unmatched_events': 0
        }
        
        # Initialize CSV output file
        with open(self.output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['timediff_ns', 'protocol'])
        
        print(f"Initialized tracking between {master_name} and {slave_name}")
        print(f"Results will be saved to {output_file}")

    def process_log_line(self, line):
        """Process a single log line from syslog"""
        # Parse syslog format
        syslog_match = re.match(SYSLOG_PATTERN, line)
        if not syslog_match:
            return
            
        syslog_timestamp, hostname, data = syslog_match.groups()
        
        # Check if this is a connection tracking entry for our machines
        if self.master_name in data:
            self._process_master_event(data)
        elif self.slave_name in data:
            self._process_slave_event(data)

    def _process_master_event(self, data):
        """Process a master connection tracking event"""
        # Extract the connection tracking data after the machine name
        conn_data = data.split(self.master_name)[1].strip()
        
        # Parse the master event data
        master_match = re.match(MASTER_PATTERN, conn_data)
        if not master_match:
            return
            
        event_id, timestamp, hash_val, src_ip, src_port, dst_ip, dst_port, protocol, state, timeout, tcp_state, assured = master_match.groups()
        
        # Store the master event
        self.master_events[hash_val] = {
            'id': event_id,
            'timestamp': int(timestamp),
            'protocol': protocol,
            'details': f"{src_ip},{src_port},{dst_ip},{dst_port},{protocol},{state},{timeout},{tcp_state},{assured}"
        }
        
        # Add to unmatched queue
        self.unmatched_queue.append(hash_val)
        
        self.stats['total_master_events'] += 1
        
        # Cleanup old events if queue gets too large
        if len(self.unmatched_queue) > 10000:
            old_hash = self.unmatched_queue.popleft()
            if old_hash in self.master_events:
                del self.master_events[old_hash]
                self.stats['unmatched_events'] += 1

    def _process_slave_event(self, data):
        """Process a slave connection tracking event"""
        # Extract the connection tracking data after the machine name
        conn_data = data.split(self.slave_name)[1].strip()
        
        # Parse the slave event data
        slave_match = re.match(SLAVE_PATTERN, conn_data)
        if not slave_match:
            return
            
        timestamp, hash_val, src_ip, src_port, dst_ip, dst_port, protocol, state, timeout, tcp_state, assured = slave_match.groups()
        
        self.stats['total_slave_events'] += 1
        
        # Check if we have a matching master event
        if hash_val in self.master_events:
            master_event = self.master_events[hash_val]
            
            # Calculate time difference in nanoseconds
            time_diff = int(timestamp) - master_event['timestamp']
            
            # Save the result
            with open(self.output_file, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([time_diff, master_event['protocol']])
            
            # Remove from unmatched queue and dictionary
            if hash_val in self.unmatched_queue:
                self.unmatched_queue.remove(hash_val)
            del self.master_events[hash_val]
            
            self.stats['matched_events'] += 1

    def process_log_file(self, log_file):
        """Process a log file line by line"""
        try:
            with open(log_file, 'r') as f:
                # Move to the end of the file
                f.seek(0, 2)
                
                while True:
                    line = f.readline()
                    if line:
                        self.process_log_line(line)
                    else:
                        # No new lines, wait a bit
                        time.sleep(0.1)
                        
                        # Print statistics periodically
                        if self.stats['total_master_events'] % 100 == 0 and self.stats['total_master_events'] > 0:
                            self._print_stats()
        except KeyboardInterrupt:
            self._print_stats()
            print("\nExiting...")

    def _print_stats(self):
        """Print current statistics"""
        print("\n--- Connection Tracking Statistics ---")
        print(f"Total master events: {self.stats['total_master_events']}")
        print(f"Total slave events: {self.stats['total_slave_events']}")
        print(f"Matched events: {self.stats['matched_events']}")
        print(f"Unmatched events in queue: {len(self.unmatched_queue)}")
        print(f"Unmatched and expired events: {self.stats['unmatched_events']}")
        if self.stats['matched_events'] > 0:
            match_rate = (self.stats['matched_events'] / self.stats['total_master_events']) * 100
            print(f"Match rate: {match_rate:.2f}%")
        print("--------------------------------------")

def signal_handler(sig, frame):
    print("\nExiting gracefully...")
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description='Analyze connection tracking logs from master and slave machines')
    parser.add_argument('-m', '--master', required=True, help='Master machine name')
    parser.add_argument('-s', '--slave', required=True, help='Slave machine name')
    parser.add_argument('-l', '--log', required=True, help='Log file to read')
    parser.add_argument('-o', '--output', required=True, help='Output file to save results')
    
    args = parser.parse_args()
    
    # Set up signal handler for graceful exit
    signal.signal(signal.SIGINT, signal_handler)
    
    # Create tracker and process log file
    tracker = ConnectionTracker(args.master, args.slave, args.output)
    tracker.process_log_file(args.log)

if __name__ == "__main__":
    main()

