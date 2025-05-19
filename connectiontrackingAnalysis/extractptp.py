#!/usr/bin/env python3
import re
import csv
import os
import time
import argparse

# Define the regular expression pattern for PTP log lines
pattern = r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{2}:\d{2}).*master offset\s+(-?\d+)\s+s2\s+freq\s+([+-]?\d+)\s+path delay\s+(\d+)"
compiled_pattern = re.compile(pattern)

# Set up command-line argument parsing
parser = argparse.ArgumentParser(description="Continuously process PTP log file and write to CSV until Ctrl+C is pressed.")
parser.add_argument("-i", "--input", required=True, help="Input PTP log file")
parser.add_argument("-o", "--output", required=True, help="Output CSV file")
args = parser.parse_args()

# Define CSV fieldnames
fieldnames = ['timestamp', 'master_offset', 'freq_adjustment', 'path_delay']

# Check if output file exists and determine if header should be written
exists = os.path.exists(args.output)
size = os.path.getsize(args.output) if exists else 0
write_header = not exists or size == 0

# Open input and output files
input_file = open(args.input, 'r')
csvfile = open(args.output, 'a', newline='')
writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

# Write header if necessary
if write_header:
    writer.writeheader()

# Initialize file_size to 0 to process existing content
file_size = 0

try:
    while True:
        # Check current file size
        stat = os.fstat(input_file.fileno())
        current_size = stat.st_size
        
        if current_size > file_size:
            # Read and process new lines (or existing lines on first run)
            while True:
                line = input_file.readline()
                if not line:
                    break
                # Extract data using regex
                match = compiled_pattern.search(line)
                if match:
                    data = {
                        'timestamp': match.group(1),
                        'master_offset': int(match.group(2)),
                        'freq_adjustment': int(match.group(3)),
                        'path_delay': int(match.group(4))
                    }
                    # Write extracted data to CSV
                    writer.writerow(data)
                    # Flush the CSV file to ensure data is written immediately
                    csvfile.flush()
            
            # Update file_size to current position
            file_size = input_file.tell()
        else:
            # No new content, sleep for 1 second
            time.sleep(1)
except KeyboardInterrupt:
    print("Stopped by user")
finally:
    # Close files
    input_file.close()
    csvfile.close()
