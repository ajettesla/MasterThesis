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
from collections import defaultdict, Counter
import ipaddress
import queue
import atexit
import psutil

def is_in_subnet(ip_str, subnet_str):
    """
    Check if an IP address is within a given subnet.
    """
    try:
        ip = ipaddress.IPv4Address(ip_str)
        subnet = ipaddress.IPv4Network(subnet_str, strict=False)
        return ip in subnet
    except (ipaddress.AddressValueError, ValueError):
        return False

def get_tcp_state_name(state_num):
    """
    Convert TCP state number to human readable name.
    """
    tcp_states = {
        0: "NONE",
        1: "SYN_SENT",
        2: "SYN_RECV", 
        3: "ESTABLISHED",
        4: "FIN_WAIT",
        5: "CLOSE_WAIT",
        6: "LAST_ACK",
        7: "TIME_WAIT",
        8: "CLOSE",
        9: "SYN_SENT2"
    }
    return tcp_states.get(state_num, f"UNKNOWN_{state_num}")

def get_protocol_name(proto_num):
    """
    Convert protocol number to name.
    """
    protocols = {
        1: "ICMP",
        6: "TCP", 
        17: "UDP"
    }
    return protocols.get(proto_num, f"PROTO_{proto_num}")

def kill_running_processes():
    """
    Kill all running conntrackAnalysis.py processes.
    """
    killed_count = 0
    current_pid = os.getpid()
    
    try:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                # Check if it's a Python process running conntrackAnalysis.py
                if (proc.info['name'] and 'python' in proc.info['name'].lower() and
                    proc.info['cmdline'] and len(proc.info['cmdline']) > 1):
                    
                    # Check if conntrackAnalysis.py is in the command line
                    cmdline_str = ' '.join(proc.info['cmdline'])
                    if 'conntrackAnalysis.py' in cmdline_str and proc.info['pid'] != current_pid:
                        print(f"Killing process {proc.info['pid']}: {cmdline_str}")
                        proc.terminate()
                        try:
                            proc.wait(timeout=5)  # Wait up to 5 seconds for graceful termination
                        except psutil.TimeoutExpired:
                            print(f"Force killing process {proc.info['pid']}")
                            proc.kill()
                        killed_count += 1
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
                
    except Exception as e:
        print(f"Error while killing processes: {e}")
    
    # Also check PID file
    pid_file = '/tmp/conntrack_processor.pid'
    if os.path.exists(pid_file):
        try:
            with open(pid_file, 'r') as f:
                pid = int(f.read().strip())
            try:
                os.kill(pid, signal.SIGTERM)
                print(f"Sent SIGTERM to PID file process {pid}")
                killed_count += 1
            except ProcessLookupError:
                print(f"PID file process {pid} not found")
            os.remove(pid_file)
        except Exception as e:
            print(f"Error handling PID file: {e}")
    
    if killed_count == 0:
        print("No running conntrackAnalysis.py processes found")
    else:
        print(f"Killed {killed_count} process(es)")
    
    return killed_count

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
        
        # Filter: only process if both src and dst IPs are in 172.16.1.0/24 range
        if not (is_in_subnet(srcip, '172.16.1.0/24') and is_in_subnet(dstip, '172.16.1.0/24')):
            return None
            
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

class StatisticsCollector:
    """
    Thread-safe statistics collector that runs in a separate thread.
    """
    def __init__(self, experiment_name, device_a, device_b, output_dir):
        self.experiment_name = experiment_name
        self.device_a = device_a
        self.device_b = device_b
        self.output_dir = output_dir
        
        self.stats_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        
        # Simplified statistics - only count matched pairs and unmatched packets
        self.stats = {
            'total_lines': 0,
            'total_packets_a': 0,
            'total_packets_b': 0,
            'matches_found': 0,
            'second_pass_matches': 0
        }
        
        # TCP state statistics (matched pairs and unmatched packets)
        self.tcp_matched_states = Counter()  # Each match pair counted once
        self.tcp_unmatched_states = Counter()  # Each unmatched packet counted once
        self.udp_matched_count = 0  # Each match pair counted once
        self.udp_unmatched_count = 0  # Each unmatched packet counted once
        
        # Unmatched connection details
        self.unmatched_connections = Counter()
        
        self.thread = None
        self.start_time = time.time()
        
    def start(self):
        """Start the statistics collection thread."""
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        
    def stop(self):
        """Stop the statistics collection thread."""
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)  # Wait max 1 second
            
    def _run(self):
        """Main statistics collection loop."""
        last_log_time = time.time()
        
        while not self.stop_event.is_set():
            try:
                # Process queued statistics updates
                while not self.stats_queue.empty():
                    try:
                        update = self.stats_queue.get_nowait()
                        self._process_update(update)
                    except queue.Empty:
                        break
                
                # Periodic logging
                current_time = time.time()
                if current_time - last_log_time >= 5.0:
                    self._log_periodic_stats()
                    last_log_time = current_time
                    
                time.sleep(0.1)
                
            except Exception as e:
                logging.error(f"Statistics thread error: {e}")
                
    def _process_update(self, update):
        """Process a statistics update."""
        update_type = update['type']
        data = update['data']
        
        with self.lock:
            if update_type == 'increment':
                for key, value in data.items():
                    self.stats[key] = self.stats.get(key, 0) + value
                    
            elif update_type == 'packet_processed':
                device = data['device']
                if device == self.device_a:
                    self.stats['total_packets_a'] += 1
                else:
                    self.stats['total_packets_b'] += 1
                    
            elif update_type == 'matched_pair':
                # Count only once per match pair
                entry1 = data['entry1']
                
                if entry1['proto_num'] == 6:  # TCP
                    state_name = get_tcp_state_name(entry1['state_num'])
                    self.tcp_matched_states[state_name] += 1
                elif entry1['proto_num'] == 17:  # UDP
                    self.udp_matched_count += 1
                    
            elif update_type == 'unmatched_entry':
                entry = data['entry']
                device = data['device']
                
                if entry['proto_num'] == 6:  # TCP
                    state_name = get_tcp_state_name(entry['state_num'])
                    self.tcp_unmatched_states[state_name] += 1
                elif entry['proto_num'] == 17:  # UDP
                    self.udp_unmatched_count += 1
                
                # Track unmatched connection details
                conn_key = f"{entry['srcip']}:{entry['srcport']} -> {entry['dstip']}:{entry['dstport']} ({get_protocol_name(entry['proto_num'])})"
                if entry['proto_num'] == 6:
                    conn_key += f" {get_tcp_state_name(entry['state_num'])}"
                conn_key += f" [{device}]"
                self.unmatched_connections[conn_key] += 1
                
    def _log_periodic_stats(self):
        """Log periodic statistics."""
        with self.lock:
            runtime = time.time() - self.start_time
            lines = self.stats.get('total_lines', 0)
            packets_a = self.stats.get('total_packets_a', 0)
            packets_b = self.stats.get('total_packets_b', 0)
            matches = self.stats.get('matches_found', 0)
            rate = lines / runtime if runtime > 0 else 0
            
        logging.info(f"[{self.experiment_name}] Runtime: {runtime:.1f}s, "
                    f"Lines/sec: {rate:.1f}, Packets A: {packets_a}, Packets B: {packets_b}, Matches: {matches}")
        
    def update_stats(self, **kwargs):
        """Queue a statistics update."""
        try:
            self.stats_queue.put({'type': 'increment', 'data': kwargs}, timeout=0.1)
        except queue.Full:
            pass  # Drop update if queue is full
    
    def add_packet_processed(self, device):
        """Add a processed packet to statistics."""
        try:
            self.stats_queue.put({
                'type': 'packet_processed', 
                'data': {'device': device}
            }, timeout=0.1)
        except queue.Full:
            pass
            
    def add_matched_pair(self, entry1, entry2):
        """Add a matched pair to statistics (counts as one match)."""
        try:
            self.stats_queue.put({
                'type': 'matched_pair', 
                'data': {'entry1': entry1, 'entry2': entry2}
            }, timeout=0.1)
        except queue.Full:
            pass
            
    def add_unmatched_entry(self, entry, device):
        """Add an unmatched entry to statistics."""
        try:
            self.stats_queue.put({
                'type': 'unmatched_entry', 
                'data': {'entry': entry, 'device': device}
            }, timeout=0.1)
        except queue.Full:
            pass
            
    def write_final_summary(self):
        """Write final summary with current statistics."""
        # Process any remaining queue items
        while not self.stats_queue.empty():
            try:
                update = self.stats_queue.get_nowait()
                self._process_update(update)
            except queue.Empty:
                break
                
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        summary_log = os.path.join(self.output_dir, f"conntrackAnalysis_summary_{self.experiment_name}_{timestamp}.log")
        
        with self.lock:
            runtime = time.time() - self.start_time
            
            total_packets_a = self.stats.get('total_packets_a', 0)
            total_packets_b = self.stats.get('total_packets_b', 0)
            total_packets = total_packets_a + total_packets_b
            matches_found = self.stats.get('matches_found', 0)
            
            # Calculate statistics
            total_tcp_matched = sum(self.tcp_matched_states.values())
            total_tcp_unmatched = sum(self.tcp_unmatched_states.values())
            total_udp_matched = self.udp_matched_count
            total_udp_unmatched = self.udp_unmatched_count
            
            # Verification: 2 * matched + unmatched should equal total packets
            accounted_packets = (2 * matches_found) + total_tcp_unmatched + total_udp_unmatched
            
            with open(summary_log, 'w') as f:
                f.write("="*80 + "\n")
                f.write(f"CONNTRACK ANALYSIS EXPERIMENT SUMMARY\n")
                f.write(f"Experiment Name: {self.experiment_name}\n")
                f.write(f"Start Time: {datetime.datetime.now().isoformat()}\n")
                f.write(f"Runtime: {runtime:.2f} seconds\n")
                f.write(f"User: ajettesla\n")
                f.write(f"Device A: {self.device_a}\n")
                f.write(f"Device B: {self.device_b}\n")
                f.write(f"IP Range Filter: 172.16.1.0/24\n")
                f.write("="*80 + "\n\n")
                
                f.write("PACKET PROCESSING STATISTICS:\n")
                f.write(f"Total log lines read: {self.stats.get('total_lines', 0)}\n")
                f.write(f"Total packets from {self.device_a}: {total_packets_a}\n")
                f.write(f"Total packets from {self.device_b}: {total_packets_b}\n")
                f.write(f"Total packets processed: {total_packets}\n")
                f.write(f"Total match pairs found: {matches_found}\n")
                f.write(f"  - First pass matches: {matches_found - self.stats.get('second_pass_matches', 0)}\n")
                f.write(f"  - Second pass matches: {self.stats.get('second_pass_matches', 0)}\n")
                f.write(f"Packets involved in matches: {2 * matches_found}\n")
                f.write(f"Unmatched packets: {total_tcp_unmatched + total_udp_unmatched}\n\n")
                
                f.write("VERIFICATION (Ideal: 2*matched + unmatched = total):\n")
                f.write(f"2 * {matches_found} + {total_tcp_unmatched + total_udp_unmatched} = {accounted_packets}\n")
                f.write(f"Total packets: {total_packets}\n")
                f.write(f"Difference: {total_packets - accounted_packets}\n")
                if total_packets > 0:
                    match_rate = (2 * matches_found) / total_packets * 100
                    f.write(f"Match rate: {match_rate:.2f}%\n")
                f.write("\n")
                
                f.write("TCP PACKET ANALYSIS:\n")
                f.write("Matched TCP States (each match pair counted once):\n")
                if total_tcp_matched > 0:
                    for state, count in self.tcp_matched_states.most_common():
                        percentage = (count / total_tcp_matched * 100)
                        f.write(f"  {state}: {count} pairs ({percentage:.1f}%)\n")
                f.write(f"Total TCP match pairs: {total_tcp_matched}\n")
                f.write(f"TCP packets in matches: {2 * total_tcp_matched}\n\n")
                
                f.write("Unmatched TCP States:\n")
                if total_tcp_unmatched > 0:
                    for state, count in self.tcp_unmatched_states.most_common():
                        percentage = (count / total_tcp_unmatched * 100)
                        f.write(f"  {state}: {count} packets ({percentage:.1f}%)\n")
                f.write(f"Total TCP unmatched packets: {total_tcp_unmatched}\n\n")
                
                f.write("UDP PACKET ANALYSIS:\n")
                f.write(f"UDP match pairs: {total_udp_matched}\n")
                f.write(f"UDP packets in matches: {2 * total_udp_matched}\n")
                f.write(f"UDP unmatched packets: {total_udp_unmatched}\n")
                total_udp_packets = (2 * total_udp_matched) + total_udp_unmatched
                if total_udp_packets > 0:
                    udp_match_rate = (2 * total_udp_matched) / total_udp_packets * 100
                    f.write(f"UDP match rate: {udp_match_rate:.1f}%\n")
                f.write("\n")
                
                f.write("TOP 20 UNMATCHED CONNECTIONS:\n")
                for i, (conn_detail, count) in enumerate(self.unmatched_connections.most_common(20)):
                    f.write(f"{i+1:2d}. {conn_detail} - Count: {count}\n")
                f.write(f"\nTotal unique unmatched connections: {len(self.unmatched_connections)}\n\n")
                
                f.write(f"PROCESSING RATE: {self.stats.get('total_lines', 0) / runtime:.1f} lines/sec\n")
                f.write("="*80 + "\n")
                
        logging.info(f"Final summary written to: {summary_log}")
        return summary_log

def create_flexible_keys(entry):
    """
    Create a single hash-based key for matching.
    Returns a list with only the hash-based key.
    """
    # Only use hash-based key
    return [(entry['hash'], entry['type_num'], entry['state_num'], entry['proto_num'], 
             entry['srcip'], entry['srcport'], entry['dstip'], entry['dstport'])]

def find_best_match(entry, candidates, time_tolerance_ns=1000000000):  # 1 second tolerance
    """
    Find the best matching candidate where candidate's timestamp is greater than entry's timestamp.
    Only matches where conn2_time - conn1_time > 0
    """
    best_match = None
    best_time_diff = float('inf')
    
    for candidate in candidates:
        # Only consider matches where conn2_time > conn1_time (positive difference)
        time_diff = candidate['timestamp_nano'] - entry['timestamp_nano']
        if time_diff > 0 and time_diff < best_time_diff and time_diff <= time_tolerance_ns:
            best_match = candidate
            best_time_diff = time_diff
    
    return best_match, best_time_diff if best_match else 0

def process_entry(entry, device_a, device_b, dict_a, dict_b, writer, stats_collector, debug_mode):
    """
    Process a single log entry, checking for matches and writing results.
    Only match from device A (conn1) to device B (conn2).
    """
    D = entry['device']
    if D not in [device_a, device_b]:
        return
    
    # Count this packet
    stats_collector.add_packet_processed(D)
    
    # Only process matching when the entry is from device A (conn1)
    if D == device_a:
        # Create hash-based key only
        flexible_keys = create_flexible_keys(entry)
        matched = False
        
        for key_idx, K in enumerate(flexible_keys):
            if K in dict_b and dict_b[K]:
                # Find best match where conn2_time - conn1_time > 0
                best_match, time_diff = find_best_match(entry, dict_b[K])
                if best_match:
                    # Calculate positive time difference (conn2 - conn1)
                    diff_nano = best_match['timestamp_nano'] - entry['timestamp_nano']
                    # Maintain original debug format
                    debug_str = f"{D} ({entry['payload']}) -> {device_b} ({best_match['payload']}) [key_type:{key_idx}]" if debug_mode else ''
                    writer.writerow([diff_nano, entry['proto_num'], entry['state_num'], debug_str])
                    
                    # Update statistics - count as one match pair
                    stats_collector.update_stats(matches_found=1)
                    stats_collector.add_matched_pair(entry, best_match)
                    
                    logging.debug(f"Match found (key_type {key_idx}): {D} ({entry['payload']}) -> {device_b} ({best_match['payload']}) (matched)")
                    dict_b[K].remove(best_match)
                    matched = True
                    break
        
        if not matched:
            # Store only in device A dictionary for later matching by device B entries
            for K in flexible_keys:
                dict_a[K].append(entry)
            
            # This will be counted as unmatched later if no match is found
            stats_collector.add_unmatched_entry(entry, D)
    else:
        # This is a device B (conn2) entry
        # Only store it for potential matching with device A entries
        flexible_keys = create_flexible_keys(entry)
        for K in flexible_keys:
            dict_b[K].append(entry)

def second_pass_matching(dict_a, dict_b, device_a, device_b, writer, stats_collector, debug_mode):
    """
    Perform a second pass to match previously unmatched entries with more relaxed criteria.
    Only match from device A (conn1) to device B (conn2) with positive time difference.
    """
    logging.info("Starting second pass matching for unmatched entries...")
    
    # Collect all unmatched entries from both devices
    unmatched_a = []
    unmatched_b = []
    
    # Extract unique entries (avoid duplicates from multiple keys)
    seen_a = set()
    seen_b = set()
    
    for key_list in dict_a.values():
        for entry in key_list:
            entry_id = (entry['timestamp_nano'], entry['payload'])
            if entry_id not in seen_a:
                unmatched_a.append(entry)
                seen_a.add(entry_id)
    
    for key_list in dict_b.values():
        for entry in key_list:
            entry_id = (entry['timestamp_nano'], entry['payload'])
            if entry_id not in seen_b:
                unmatched_b.append(entry)
                seen_b.add(entry_id)
    
    logging.info(f"Second pass: {len(unmatched_a)} unmatched from {device_a}, {len(unmatched_b)} unmatched from {device_b}")
    
    # Try to match unmatched entries with relaxed criteria
    second_pass_matches = 0
    time_tolerance_ns = 5000000000  # 5 seconds tolerance for second pass
    
    matched_indices_a = set()
    matched_indices_b = set()
    
    # Only match from device A to device B with positive time difference
    for i, entry_a in enumerate(unmatched_a):
        if i in matched_indices_a:
            continue
            
        for j, entry_b in enumerate(unmatched_b):
            if j in matched_indices_b:
                continue
                
            # Only consider matches where conn2_time > conn1_time (positive difference)
            time_diff = entry_b['timestamp_nano'] - entry_a['timestamp_nano']
            
            # Check if they could be a match with relaxed criteria
            if (time_diff > 0 and
                time_diff <= time_tolerance_ns and
                entry_a['proto_num'] == entry_b['proto_num'] and
                entry_a['hash'] == entry_b['hash']):
                
                # Write the positive time difference
                diff_nano = entry_b['timestamp_nano'] - entry_a['timestamp_nano']
                # Maintain original debug format
                debug_str = f"{device_a} ({entry_a['payload']}) -> {device_b} ({entry_b['payload']}) [second_pass]" if debug_mode else ''
                writer.writerow([diff_nano, entry_a['proto_num'], entry_a['state_num'], debug_str])
                
                second_pass_matches += 1
                matched_indices_a.add(i)
                matched_indices_b.add(j)
                
                # Update statistics - count as one match pair
                stats_collector.update_stats(matches_found=1, second_pass_matches=1)
                stats_collector.add_matched_pair(entry_a, entry_b)
                
                logging.debug(f"Second pass match: {device_a} ({entry_a['payload']}) -> {device_b} ({entry_b['payload']})")
                break
    
    logging.info(f"Second pass completed: {second_pass_matches} additional matches found")
    return second_pass_matches

class GracefulShutdown:
    """
    Handle graceful shutdown with timeout.
    """
    def __init__(self, timeout=3.0):
        self.timeout = timeout
        self.shutdown_event = threading.Event()
        self.shutdown_started = False
        
    def signal_handler(self, signum, frame):
        if self.shutdown_started:
            logging.warning("Force shutdown - killing process")
            os._exit(1)
            
        self.shutdown_started = True
        logging.info(f"Shutdown requested (signal {signum}). Graceful shutdown in progress...")
        self.shutdown_event.set()
        
        # Start force shutdown timer
        def force_shutdown():
            time.sleep(self.timeout)
            if not self.shutdown_event.is_set():
                logging.error(f"Graceful shutdown timeout ({self.timeout}s). Force killing process.")
                os._exit(1)
                
        threading.Thread(target=force_shutdown, daemon=True).start()
        
    def is_shutdown_requested(self):
        return self.shutdown_event.is_set()

def main():
    """
    Process conntrack logs, with options for daemon mode, killing the program, and debug output.
    """
    parser = argparse.ArgumentParser(description="Process conntrack logs for matching entries.")
    parser.add_argument('-a', help="Name of device A")
    parser.add_argument('-b', help="Name of device B")
    parser.add_argument('-l', help="Path to log file")
    parser.add_argument('-o', help="Path to output CSV file")
    parser.add_argument('-e', help="Experiment name for logging and summary")
    parser.add_argument('-d', action='store_true', help="Enable debug mode")
    parser.add_argument('-k', action='store_true', help="Kill all running conntrackAnalysis.py processes")
    parser.add_argument('-D', action='store_true', help="Run in daemon mode")
    parser.add_argument('-L', help="Log file path (default: /tmp/conntrackAnalysis.log)")
    parser.add_argument('--no-second-pass', action='store_true', help="Skip second pass matching")
    args = parser.parse_args()

    if args.k:
        killed_count = kill_running_processes()
        sys.exit(0)

    # Check if already running (only if not killing)
    pid_file = '/tmp/conntrack_processor.pid'
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
            log_file = '/tmp/conntrackAnalysis.log'
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
        parser.error("Options -a, -b, -l, -o are required when not in daemon mode")

    experiment_name = args.e if args.e else f"exp_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    logging.info(f"Starting conntrack processor for experiment: {experiment_name}")

    device_a = args.a
    device_b = args.b
    log_file = args.l
    output_file = args.o
    debug_mode = args.d

    # Determine output directory from CSV file path
    output_dir = os.path.dirname(os.path.abspath(output_file)) if output_file else '/tmp'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    # Set up graceful shutdown
    shutdown_handler = GracefulShutdown(timeout=3.0)
    signal.signal(signal.SIGTERM, shutdown_handler.signal_handler)
    signal.signal(signal.SIGINT, shutdown_handler.signal_handler)

    # Initialize statistics collector
    stats_collector = StatisticsCollector(experiment_name, device_a, device_b, output_dir)
    stats_collector.start()
    
    # Ensure cleanup on exit
    def cleanup():
        logging.info("Cleaning up...")
        if stats_collector:
            stats_collector.stop()
            stats_collector.write_final_summary()
        if os.path.exists(pid_file):
            os.remove(pid_file)
    
    atexit.register(cleanup)

    if not os.path.exists(output_file):
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['timedifference', 'protocol_num', 'state_num', 'debug_info'])

    csvfile = None
    writer = None
    
    try:
        csvfile = open(output_file, 'a', newline='')
        writer = csv.writer(csvfile)

        dict_a = defaultdict(list)
        dict_b = defaultdict(list)
        last_flush_time = time.time()

        # Main processing loop
        with open(log_file, 'r') as f:
            while not shutdown_handler.is_shutdown_requested():
                line = f.readline()
                if line:
                    logging.debug(f"Read line: {line.strip()}")
                    stats_collector.update_stats(total_lines=1)
                    entry = parse_line(line)
                    if entry:
                        process_entry(entry, device_a, device_b, dict_a, dict_b, writer, stats_collector, debug_mode)
                else:
                    time.sleep(0.1)

                current_time = time.time()
                if current_time - last_flush_time >= 5:
                    csvfile.flush()
                    last_flush_time = current_time

        # Second pass: try to match unmatched entries
        if not args.no_second_pass and not shutdown_handler.is_shutdown_requested():
            logging.info("First pass completed. Starting second pass matching...")
            second_pass_matching(dict_a, dict_b, device_a, device_b, writer, stats_collector, debug_mode)

        logging.info(f"[{experiment_name}] Processing completed normally")

    except KeyboardInterrupt:
        logging.info(f"[{experiment_name}] Interrupted by user")
    except Exception as e:
        logging.error(f"[{experiment_name}] Error during processing: {e}")
    finally:
        if csvfile:
            csvfile.close()
        
        # Stop statistics collector and write final summary
        stats_collector.stop()
        summary_file = stats_collector.write_final_summary()
        logging.info(f"[{experiment_name}] Experiment completed. Summary: {summary_file}")
        
        if os.path.exists(pid_file):
            os.remove(pid_file)

if __name__ == '__main__':
    main()
