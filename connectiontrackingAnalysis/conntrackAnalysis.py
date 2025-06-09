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
        
        # Main statistics
        self.stats = {
            'total_lines': 0,
            'total_entries': 0,
            'matches_found': 0,
            'unmatched_a': 0,
            'unmatched_b': 0,
            'tcp_established': 0,
            'tcp_established_a': 0,
            'tcp_established_b': 0,
            'tcp_established_matched': 0,
            'udp_total': 0,
            'udp_a': 0,
            'udp_b': 0,
            'udp_matched': 0
        }
        
        # TCP state statistics
        self.tcp_matched_states = Counter()
        self.tcp_unmatched_states = Counter()
        self.udp_matched_count = 0
        self.udp_unmatched_count = 0
        
        # Unmatched connection details (limited to top connections)
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
                    
            elif update_type == 'matched_entry':
                entry = data['entry']
                if entry['proto_num'] == 6:  # TCP
                    state_name = get_tcp_state_name(entry['state_num'])
                    self.tcp_matched_states[state_name] += 1
                elif entry['proto_num'] == 17:  # UDP
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
                
            elif update_type == 'match_type':
                key = f"matches_key_type_{data['key_type']}"
                self.stats[key] = self.stats.get(key, 0) + 1
                
    def _log_periodic_stats(self):
        """Log periodic statistics."""
        with self.lock:
            runtime = time.time() - self.start_time
            lines = self.stats.get('total_lines', 0)
            entries = self.stats.get('total_entries', 0)
            matches = self.stats.get('matches_found', 0)
            rate = lines / runtime if runtime > 0 else 0
            
        logging.info(f"[{self.experiment_name}] Runtime: {runtime:.1f}s, "
                    f"Lines/sec: {rate:.1f}, Lines: {lines}, Entries: {entries}, Matches: {matches}")
        
    def update_stats(self, **kwargs):
        """Queue a statistics update."""
        try:
            self.stats_queue.put({'type': 'increment', 'data': kwargs}, timeout=0.1)
        except queue.Full:
            pass  # Drop update if queue is full
            
    def add_matched_entry(self, entry, device):
        """Add a matched entry to statistics."""
        try:
            self.stats_queue.put({
                'type': 'matched_entry', 
                'data': {'entry': entry, 'device': device}
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
            
    def add_match_type(self, key_type):
        """Record which matching strategy was used."""
        try:
            self.stats_queue.put({
                'type': 'match_type', 
                'data': {'key_type': key_type}
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
                
                f.write("PROCESSING STATISTICS:\n")
                f.write(f"Total log lines read: {self.stats.get('total_lines', 0)}\n")
                f.write(f"Valid entries processed: {self.stats.get('total_entries', 0)}\n")
                f.write(f"Total matches found: {self.stats.get('matches_found', 0)}\n")
                f.write(f"First pass matches: {self.stats.get('matches_found', 0) - self.stats.get('second_pass_matches', 0)}\n")
                f.write(f"Second pass matches: {self.stats.get('second_pass_matches', 0)}\n")
                f.write(f"Unmatched entries from {self.device_a}: {self.stats.get('unmatched_a', 0)}\n")
                f.write(f"Unmatched entries from {self.device_b}: {self.stats.get('unmatched_b', 0)}\n")
                f.write(f"Total unmatched entries: {self.stats.get('unmatched_a', 0) + self.stats.get('unmatched_b', 0)}\n\n")
                
                f.write("TCP PACKET ANALYSIS:\n")
                f.write("Matched TCP States:\n")
                total_tcp_matched = sum(self.tcp_matched_states.values())
                for state, count in self.tcp_matched_states.most_common():
                    percentage = (count / total_tcp_matched * 100) if total_tcp_matched > 0 else 0
                    f.write(f"  {state}: {count} ({percentage:.1f}%)\n")
                f.write(f"Total TCP matched: {total_tcp_matched}\n\n")
                
                f.write("Unmatched TCP States:\n")
                total_tcp_unmatched = sum(self.tcp_unmatched_states.values())
                for state, count in self.tcp_unmatched_states.most_common():
                    percentage = (count / total_tcp_unmatched * 100) if total_tcp_unmatched > 0 else 0
                    f.write(f"  {state}: {count} ({percentage:.1f}%)\n")
                f.write(f"Total TCP unmatched: {total_tcp_unmatched}\n\n")
                
                f.write("UDP PACKET ANALYSIS:\n")
                f.write(f"UDP matched: {self.udp_matched_count}\n")
                f.write(f"UDP unmatched: {self.udp_unmatched_count}\n")
                total_udp = self.udp_matched_count + self.udp_unmatched_count
                if total_udp > 0:
                    udp_match_rate = (self.udp_matched_count / total_udp * 100)
                    f.write(f"UDP match rate: {udp_match_rate:.1f}%\n")
                f.write("\n")
                
                f.write("MATCHING STRATEGY BREAKDOWN:\n")
                strategy_names = [
                    "Exact match (with hash)",
                    "Match without hash", 
                    "Reversed src/dst match",
                    "Connection tuple only",
                    "Reversed connection tuple"
                ]
                for i in range(5):
                    key_matches = self.stats.get(f'matches_key_type_{i}', 0)
                    if key_matches > 0:
                        f.write(f"{strategy_names[i]}: {key_matches}\n")
                f.write("\n")
                
                f.write("TOP 20 UNMATCHED CONNECTIONS:\n")
                for i, (conn_detail, count) in enumerate(self.unmatched_connections.most_common(20)):
                    f.write(f"{i+1:2d}. {conn_detail} - Count: {count}\n")
                f.write(f"\nTotal unique unmatched connections: {len(self.unmatched_connections)}\n\n")
                
                total_entries = self.stats.get('total_entries', 0)
                matches = self.stats.get('matches_found', 0)
                match_rate = (matches / total_entries * 100) if total_entries > 0 else 0
                first_pass_matches = matches - self.stats.get('second_pass_matches', 0)
                first_pass_rate = (first_pass_matches / total_entries * 100) if total_entries > 0 else 0
                improvement = match_rate - first_pass_rate
                
                f.write(f"OVERALL MATCH RATES:\n")
                f.write(f"First pass match rate: {first_pass_rate:.2f}%\n")
                f.write(f"Final match rate: {match_rate:.2f}%\n")
                f.write(f"Improvement from second pass: {improvement:.2f}%\n")
                f.write(f"Processing rate: {self.stats.get('total_lines', 0) / runtime:.1f} lines/sec\n")
                f.write("="*80 + "\n")
                
        logging.info(f"Final summary written to: {summary_log}")
        return summary_log

def create_flexible_keys(entry):
    """
    Create multiple matching keys for more flexible matching.
    Returns a list of keys to try for matching.
    """
    base_key = (entry['type_num'], entry['state_num'], entry['proto_num'], 
                entry['srcip'], entry['srcport'], entry['dstip'], entry['dstport'])
    
    # Different key variations for flexible matching
    keys = [
        # Original key with hash
        (entry['hash'], entry['type_num'], entry['state_num'], entry['proto_num'], 
         entry['srcip'], entry['srcport'], entry['dstip'], entry['dstport']),
        
        # Key without hash (in case hash differs between devices)
        base_key,
        
        # Key with reversed src/dst (in case of bidirectional flows)
        (entry['type_num'], entry['state_num'], entry['proto_num'], 
         entry['dstip'], entry['dstport'], entry['srcip'], entry['srcport']),
        
        # Key with only connection tuple (ignoring type/state differences)
        (entry['proto_num'], entry['srcip'], entry['srcport'], entry['dstip'], entry['dstport']),
        
        # Key with reversed connection tuple
        (entry['proto_num'], entry['dstip'], entry['dstport'], entry['srcip'], entry['srcport'])
    ]
    
    return keys

def find_best_match(entry, candidates, time_tolerance_ns=1000000000):  # 1 second tolerance
    """
    Find the best matching candidate based on timestamp proximity.
    """
    best_match = None
    best_time_diff = float('inf')
    
    for candidate in candidates:
        time_diff = abs(entry['timestamp_nano'] - candidate['timestamp_nano'])
        if time_diff < best_time_diff and time_diff <= time_tolerance_ns:
            best_match = candidate
            best_time_diff = time_diff
    
    return best_match, best_time_diff

def process_entry(entry, device_a, device_b, dict_a, dict_b, writer, stats_collector, debug_mode):
    """
    Process a single log entry, checking for matches and writing results.
    """
    D = entry['device']
    if D not in [device_a, device_b]:
        return
    
    # Update basic statistics
    stats_update = {'total_entries': 1}
    if entry['proto_num'] == 6:  # TCP
        if entry['state_num'] == 3:  # TCP ESTABLISHED state
            stats_update['tcp_established'] = 1
            if D == device_a:
                stats_update['tcp_established_a'] = 1
            else:
                stats_update['tcp_established_b'] = 1
    elif entry['proto_num'] == 17:  # UDP
        stats_update['udp_total'] = 1
        if D == device_a:
            stats_update['udp_a'] = 1
        else:
            stats_update['udp_b'] = 1
    
    stats_collector.update_stats(**stats_update)
    
    # Determine which dictionaries to use
    if D == device_a:
        self_dict = dict_a
        other_dict = dict_b
        other_D = device_b
    else:
        self_dict = dict_b
        other_dict = dict_a
        other_D = device_a
    
    # Try multiple matching strategies
    matched = False
    flexible_keys = create_flexible_keys(entry)
    
    for key_idx, K in enumerate(flexible_keys):
        if K in other_dict and other_dict[K]:
            # Find best match based on timestamp
            best_match, time_diff = find_best_match(entry, other_dict[K])
            if best_match:
                diff_nano = entry['timestamp_nano'] - best_match['timestamp_nano']
                debug_str = f"{D} ({entry['payload']}) -> {other_D} ({best_match['payload']}) [key_type:{key_idx}]" if debug_mode else ''
                writer.writerow([diff_nano, entry['proto_num'], entry['state_num'], debug_str])
                
                # Update statistics
                match_stats = {'matches_found': 1}
                if entry['proto_num'] == 6 and entry['state_num'] == 3:  # TCP ESTABLISHED
                    match_stats['tcp_established_matched'] = 1
                elif entry['proto_num'] == 17:  # UDP
                    match_stats['udp_matched'] = 1
                
                stats_collector.update_stats(**match_stats)
                stats_collector.add_match_type(key_idx)
                stats_collector.add_matched_entry(entry, D)
                stats_collector.add_matched_entry(best_match, other_D)
                
                logging.debug(f"Match found (key_type {key_idx}): {D} ({entry['payload']}) -> {other_D} ({best_match['payload']}) (matched)")
                other_dict[K].remove(best_match)
                matched = True
                break
    
    if not matched:
        # Store with all flexible keys for later matching
        for K in flexible_keys:
            self_dict[K].append(entry)
        
        # Update unmatched statistics
        if D == device_a:
            stats_collector.update_stats(unmatched_a=1)
        else:
            stats_collector.update_stats(unmatched_b=1)
        
        stats_collector.add_unmatched_entry(entry, D)

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
    parser.add_argument('-k', action='store_true', help="Kill the running instance")
    parser.add_argument('-D', action='store_true', help="Run in daemon mode")
    parser.add_argument('-L', help="Log file path (default: /tmp/conntrackAnalysis.log)")
    parser.add_argument('--no-second-pass', action='store_true', help="Skip second pass matching")
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
            parser.error("Options -a, -b, -l, -o are required when not in daemon mode or when -k is not provided")

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
