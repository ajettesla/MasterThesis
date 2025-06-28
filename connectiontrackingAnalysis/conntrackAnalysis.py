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
                if (proc.info['name'] and 'python' in proc.info['name'].lower() and
                    proc.info['cmdline'] and len(proc.info['cmdline']) > 1):
                    cmdline_str = ' '.join(proc.info['cmdline'])
                    if 'conntrackAnalysis.py' in cmdline_str and proc.info['pid'] != current_pid:
                        print(f"Killing process {proc.info['pid']}: {cmdline_str}")
                        proc.terminate()
                        try:
                            proc.wait(timeout=5)
                        except psutil.TimeoutExpired:
                            print(f"Force killing process {proc.info['pid']}")
                            proc.kill()
                        killed_count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception as e:
        print(f"Error while killing processes: {e}")

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
    if len(parts) < 8:
        return None
    try:
        timestamp_str = parts[0]
        timestamp = datetime.datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        device = parts[2]
        payload_str = parts[7]
        payload_fields = payload_str.split(',')
        if len(payload_fields) != 10:
            return None

        seqno, timestamp_nano, hash_value, type_num, state_num, proto_num, srcip, srcport, dstip, dstport = (
            int(payload_fields[0]), int(payload_fields[1]), payload_fields[2], int(payload_fields[3]),
            int(payload_fields[4]), int(payload_fields[5]), payload_fields[6], int(payload_fields[7]),
            payload_fields[8], int(payload_fields[9])
        )

        if not (is_in_subnet(srcip, '172.16.1.0/24') and is_in_subnet(dstip, '172.16.1.0/24')):
            return None
    except (ValueError, IndexError):
        return None

    return {
        'timestamp': timestamp, 'device': device, 'hash': hash_value, 'type_num': type_num,
        'state_num': state_num, 'proto_num': proto_num, 'srcip': srcip, 'srcport': srcport,
        'dstip': dstip, 'dstport': dstport, 'payload': payload_str, 'timestamp_nano': timestamp_nano
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

        self.stats = {
            'total_lines': 0, 'packets_a': 0, 'packets_b': 0, 'matches': 0, 'unmatched': 0,
            'neg_diff_matches': 0, 'pos_diff_matches': 0,
            'neg_diff_min_us': 0.0, 'neg_diff_max_us': 0.0,
            'neg_diff_us_buckets': Counter()
        }
        self.thread = None
        self.start_time = time.time()

    def start(self):
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)

    def _run(self):
        last_log_time = time.time()
        while not self.stop_event.is_set():
            try:
                while not self.stats_queue.empty():
                    try:
                        update = self.stats_queue.get_nowait()
                        self._process_update(update)
                    except queue.Empty:
                        break
                current_time = time.time()
                if current_time - last_log_time >= 5.0:
                    self._log_periodic_stats()
                    last_log_time = current_time
                time.sleep(0.1)
            except Exception as e:
                logging.error(f"Statistics thread error: {e}")

    def _process_update(self, update):
        update_type = update.pop('type')
        with self.lock:
            if update_type == 'basic':
                for key, value in update.items():
                    self.stats[key] += value
            elif update_type == 'negative_match':
                diff_us = update['diff_us']
                self.stats['neg_diff_matches'] += 1
                self.stats['neg_diff_min_us'] = min(self.stats['neg_diff_min_us'], diff_us)
                self.stats['neg_diff_max_us'] = max(self.stats['neg_diff_max_us'], diff_us)
                
                abs_diff_us = abs(diff_us)
                if abs_diff_us <= 1:
                    bucket = '0 to -1 us'
                elif abs_diff_us <= 10:
                    bucket = '-1 to -10 us'
                elif abs_diff_us <= 100:
                    bucket = '-10 to -100 us'
                elif abs_diff_us <= 1000:
                    bucket = '-100 to -1000 us'
                else:
                    bucket = '< -1000 us'
                self.stats['neg_diff_us_buckets'][bucket] += 1

    def _log_periodic_stats(self):
        with self.lock:
            runtime = time.time() - self.start_time
            lines = self.stats['total_lines']
            packets_a = self.stats['packets_a']
            packets_b = self.stats['packets_b']
            matches = self.stats['matches']
            neg_matches = self.stats['neg_diff_matches']
            pos_matches = self.stats['pos_diff_matches']
            rate = lines / runtime if runtime > 0 else 0
        logging.info(
            f"[{self.experiment_name}] Runtime: {runtime:.1f}s, Lines/sec: {rate:.1f}, "
            f"Packets A: {packets_a}, B: {packets_b}, "
            f"Matches: {matches} (Pos: {pos_matches}, Neg: {neg_matches})"
        )

    def update_stats(self, update_type='basic', **kwargs):
        kwargs['type'] = update_type
        try:
            self.stats_queue.put(kwargs, timeout=0.1)
        except queue.Full:
            pass

    def write_final_summary(self):
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
            total_packets_a = self.stats['packets_a']
            total_packets_b = self.stats['packets_b']
            total_packets = total_packets_a + total_packets_b
            matches_found = self.stats['matches']
            unmatched_count = self.stats['unmatched']
            pos_matches = self.stats['pos_diff_matches']
            neg_matches = self.stats['neg_diff_matches']
            accounted_packets = (2 * matches_found) + unmatched_count

            with open(summary_log, 'w') as f:
                f.write("="*80 + "\n")
                f.write(f"CONNTRACK ANALYSIS EXPERIMENT SUMMARY\n")
                f.write(f"Experiment Name: {self.experiment_name}\n")
                f.write(f"Completion Time: {datetime.datetime(2025, 6, 28, 12, 7, 55).isoformat()}Z\n")
                f.write(f"Runtime: {runtime:.2f} seconds\n")
                f.write(f"User: ajettesla\n")
                f.write(f"Device A: {self.device_a}\n")
                f.write(f"Device B: {self.device_b}\n")
                f.write(f"IP Range Filter: 172.16.1.0/24\n")
                f.write("="*80 + "\n\n")

                f.write("PACKET PROCESSING STATISTICS:\n")
                f.write(f"Total log lines read: {self.stats['total_lines']}\n")
                f.write(f"Total packets from {self.device_a} (A): {total_packets_a}\n")
                f.write(f"Total packets from {self.device_b} (B): {total_packets_b}\n")
                f.write(f"Total packets processed: {total_packets}\n\n")

                f.write("MATCHING RESULTS:\n")
                f.write(f"Total match pairs found: {matches_found}\n")
                f.write(f"  - Positive time diff (B > A): {pos_matches}\n")
                f.write(f"  - Negative time diff (A > B): {neg_matches}\n")
                f.write(f"Packets involved in matches: {2 * matches_found}\n")
                f.write(f"Unmatched packets: {unmatched_count}\n\n")
                
                f.write("NEGATIVE TIME DIFFERENCE ANALYSIS (microseconds):\n")
                if neg_matches > 0:
                    f.write(f"  Min negative value: {self.stats['neg_diff_min_us']:.3f} us\n")
                    f.write(f"  Max negative value: {self.stats['neg_diff_max_us']:.3f} us\n")
                    f.write(f"  Distribution of negative values:\n")
                    sorted_buckets = sorted(self.stats['neg_diff_us_buckets'].items(), key=lambda item: item[1], reverse=True)
                    for bucket, count in sorted_buckets:
                        percentage = (count / neg_matches) * 100
                        f.write(f"    - {bucket:<18}: {count:<7} ({percentage:.2f}%)\n")
                else:
                    f.write("  No negative time differences were recorded.\n")
                f.write("\n")

                f.write("VERIFICATION (Ideal: 2*matched + unmatched = total):\n")
                f.write(f"2 * {matches_found} + {unmatched_count} = {accounted_packets}\n")
                f.write(f"Total packets processed: {total_packets}\n")
                f.write(f"Difference: {total_packets - accounted_packets}\n")
                if total_packets > 0:
                    match_rate = (2 * matches_found) / total_packets * 100
                    f.write(f"Match rate: {match_rate:.2f}%\n")
                f.write("\n")

                f.write(f"PROCESSING RATE: {self.stats['total_lines'] / runtime:.1f} lines/sec\n")
                f.write("="*80 + "\n")
        logging.info(f"Final summary written to: {summary_log}")

def create_hash_key(entry):
    return (
        entry['hash'], entry['type_num'], entry['state_num'], entry['proto_num'],
        entry['srcip'], entry['srcport'], entry['dstip'], entry['dstport']
    )

def find_best_match(entry, candidates):
    best_match = None
    min_abs_diff = float('inf')
    for candidate in candidates:
        time_diff = candidate['timestamp_nano'] - entry['timestamp_nano']
        abs_diff = abs(time_diff)
        if abs_diff < min_abs_diff:
            min_abs_diff = abs_diff
            best_match = candidate
    return best_match

def process_entry(entry, dict_a, dict_b, writer, stats_collector, debug_mode):
    device = entry['device']
    is_device_a = device == stats_collector.device_a
    stats_collector.update_stats(packets_a=1 if is_device_a else 0, packets_b=1 if not is_device_a else 0)

    current_dict = dict_a if is_device_a else dict_b
    match_dict = dict_b if is_device_a else dict_a
    key = create_hash_key(entry)

    if key in match_dict and match_dict[key]:
        best_match = find_best_match(entry, match_dict[key])
        entry_a = entry if is_device_a else best_match
        entry_b = best_match if is_device_a else entry
        time_diff_ns = entry_b['timestamp_nano'] - entry_a['timestamp_nano']

        debug_str = f"{entry_a['payload']} -> {entry_b['payload']}" if debug_mode else ''
        writer.writerow([time_diff_ns, entry_a['proto_num'], entry_a['state_num'], debug_str])

        stats_collector.update_stats(matches=1, unmatched=-1)
        
        if time_diff_ns < 0:
            stats_collector.update_stats(update_type='negative_match', diff_us=time_diff_ns / 1000.0)
        else:
            stats_collector.update_stats(pos_diff_matches=1)

        match_dict[key].remove(best_match)
        if not match_dict[key]:
            del match_dict[key]
    else:
        current_dict[key].append(entry)
        stats_collector.update_stats(unmatched=1)

class GracefulShutdown:
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
        threading.Thread(target=self._force_shutdown_timer, daemon=True).start()

    def _force_shutdown_timer(self):
        time.sleep(self.timeout)
        logging.error(f"Graceful shutdown timeout ({self.timeout}s). Force killing process.")
        os._exit(1)

    def is_shutdown_requested(self):
        return self.shutdown_event.is_set()

def main():
    parser = argparse.ArgumentParser(description="Process conntrack logs for matching entries.")
    parser.add_argument('-a', help="Name of device A (e.g., conn1)", required=True)
    parser.add_argument('-b', help="Name of device B (e.g., conn2)", required=True)
    parser.add_argument('-l', help="Path to log file to process", required=True)
    parser.add_argument('-o', help="Path to output CSV file", required=True)
    parser.add_argument('-e', help="Experiment name for logging and summary")
    parser.add_argument('-d', action='store_true', help="Enable debug mode")
    parser.add_argument('-k', action='store_true', help="Kill all running conntrackAnalysis.py processes")
    parser.add_argument('-D', action='store_true', help="Run in daemon mode")
    parser.add_argument('-L', help="Log file path for daemon (default: /tmp/conntrackAnalysis.log)")
    args = parser.parse_args()

    if args.k:
        kill_running_processes()
        sys.exit(0)

    pid_file = '/tmp/conntrack_processor.pid'
    if os.path.exists(pid_file):
        try:
            with open(pid_file, 'r') as f: pid = int(f.read().strip())
            os.kill(pid, 0)
            print(f"Instance already running with PID {pid}. Use -k to kill.")
            sys.exit(1)
        except (ProcessLookupError, ValueError):
            os.remove(pid_file)

    if args.D:
        log_file_daemon = args.L if args.L else '/tmp/conntrackAnalysis.log'
        pid = os.fork()
        if pid > 0: sys.exit(0)
        os.setsid(); os.chdir('/'); pid = os.fork()
        if pid > 0: sys.exit(0)
        with open('/dev/null', 'r') as devnull: os.dup2(devnull.fileno(), sys.stdin.fileno())
        try:
            log_fd = os.open(log_file_daemon, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
            os.dup2(log_fd, sys.stdout.fileno()); os.dup2(log_fd, sys.stderr.fileno()); os.close(log_fd)
        except OSError: sys.exit(1)
        with open(pid_file, 'w') as f: f.write(str(os.getpid()))
        logging.basicConfig(stream=sys.stdout, level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
    else:
        logging.basicConfig(stream=sys.stdout, level=logging.INFO, format='%(message)s')

    if args.d: logging.getLogger().setLevel(logging.DEBUG)

    experiment_name = args.e if args.e else f"exp_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    logging.info(f"Starting conntrack processor for experiment: {experiment_name}")

    output_dir = os.path.dirname(os.path.abspath(args.o))
    os.makedirs(output_dir, exist_ok=True)

    shutdown_handler = GracefulShutdown()
    signal.signal(signal.SIGTERM, shutdown_handler.signal_handler)
    signal.signal(signal.SIGINT, shutdown_handler.signal_handler)

    stats_collector = StatisticsCollector(experiment_name, args.a, args.b, output_dir)
    stats_collector.start()
    
    dict_a = defaultdict(list)
    dict_b = defaultdict(list)

    @atexit.register
    def cleanup():
        logging.info("Cleaning up...")
        stats_collector.stop()
        final_unmatched = sum(len(v) for v in dict_a.values()) + sum(len(v) for v in dict_b.values())
        logging.info(f"Final unmatched entries at exit: {final_unmatched}")
        stats_collector.write_final_summary()
        if os.path.exists(pid_file):
            os.remove(pid_file)

    if not os.path.exists(args.o):
        with open(args.o, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['timedifference_ns', 'protocol_num', 'state_num', 'debug_info'])
            
    csvfile = None
    try:
        csvfile = open(args.o, 'a', newline='')
        writer = csv.writer(csvfile)
        last_flush_time = time.time()
        with open(args.l, 'r') as f:
            while not shutdown_handler.is_shutdown_requested():
                line = f.readline()
                if line:
                    stats_collector.update_stats(total_lines=1)
                    entry = parse_line(line)
                    if entry:
                        process_entry(entry, dict_a, dict_b, writer, stats_collector, args.d)
                else:
                    time.sleep(0.1)
                if time.time() - last_flush_time >= 5:
                    csvfile.flush()
                    last_flush_time = time.time()
        logging.info(f"[{experiment_name}] Processing completed normally.")
    except KeyboardInterrupt:
        logging.info(f"[{experiment_name}] Interrupted by user.")
    except Exception as e:
        logging.error(f"[{experiment_name}] Error during processing: {e}", exc_info=True)
    finally:
        if csvfile: csvfile.close()
        logging.info(f"[{experiment_name}] Exiting. Final summary will be generated.")

if __name__ == '__main__':
    main()
