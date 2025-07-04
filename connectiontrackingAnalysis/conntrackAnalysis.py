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

def get_tcp_state_short(state_num):
    """
    Get short name for TCP state.
    """
    tcp_short_states = {
        0: "none",
        1: "ss",  # SYN_SENT
        2: "sr",  # SYN_RECV
        3: "e",   # ESTABLISHED
        4: "fw",  # FIN_WAIT
        5: "cw",  # CLOSE_WAIT
        6: "la",  # LAST_ACK
        7: "tw",  # TIME_WAIT
        8: "c",   # CLOSE
        9: "ss2"  # SYN_SENT2
    }
    return tcp_short_states.get(state_num, f"s{state_num}")

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
        # Convert to UTC naive datetime to avoid comparison issues
        if timestamp.tzinfo is not None:
            timestamp = timestamp.astimezone(datetime.timezone.utc).replace(tzinfo=None)
            
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
        'dstip': dstip, 'dstport': dstport, 'payload': payload_str, 'timestamp_nano': timestamp_nano,
        'entry_time': time.time()  # Add processing time for timeout tracking
    }

class StatisticsCollector:
    """
    Thread-safe statistics collector that runs in a separate thread.
    """
    def __init__(self, experiment_name, device_a, device_b, output_dir, conn_timeout=60, username="ajettesla"):
        self.experiment_name = experiment_name
        self.device_a = device_a
        self.device_b = device_b
        self.output_dir = output_dir
        self.conn_timeout = conn_timeout
        self.username = username
        self.stats_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.lock = threading.Lock()

        self.stats = {
            'total_lines': 0, 'packets_a': 0, 'packets_b': 0, 
            'matches': {
                'syn_sent': 0,       # ss -> ss
                'syn_recv': 0,       # sr -> sr
                'established': 0,    # e -> e
                'total': 0
            }, 
            'unmatched': 0,
            'unmatched_by_state': {
                'syn_sent': 0,      # State 1
                'syn_recv': 0,      # State 2
                'established': 0,   # State 3
                'other_states': 0   # All other states
            },
            'timed_out': 0,
            'timed_out_by_state': {
                'syn_sent': 0,      # State 1
                'syn_recv': 0,      # State 2
                'established': 0,   # State 3
                'other_states': 0   # All other states
            },
            'neg_diff_matches': 0, 'pos_diff_matches': 0,
            'neg_diff_min_us': 0.0, 'neg_diff_max_us': 0.0,
            'neg_diff_us_buckets': Counter(),
            'state_transitions': {
                'syn_sent_to_syn_recv': 0,        # ss -> sr
                'syn_sent_to_established': 0,     # ss -> e
                'total': 0
            },
            'established_stats': {
                'matched': 0,          # Matched ESTABLISHED
                'unmatched': 0,        # Unmatched ESTABLISHED
                'timed_out': 0,        # Timed out ESTABLISHED
                'device_a_only': 0,    # Only seen in device A
                'device_b_only': 0     # Only seen in device B
            },
            'errors': {
                'stat_inconsistencies': 0,  # Track statistical inconsistencies
                'negative_counters': 0      # Track attempts to decrement below zero
            }
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
                    if key in self.stats:
                        if isinstance(self.stats[key], dict) and isinstance(value, dict):
                            for subkey, subvalue in value.items():
                                self.stats[key][subkey] += subvalue
                        else:
                            self.stats[key] += value
            elif update_type == 'negative_match':
                diff_us = update['diff_us']
                self.stats['neg_diff_matches'] += 1
                if self.stats['neg_diff_min_us'] == 0 or diff_us < self.stats['neg_diff_min_us']:
                    self.stats['neg_diff_min_us'] = diff_us
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
            elif update_type == 'state_transition':
                transition_type = update.get('transition_type')
                if transition_type in self.stats['state_transitions']:
                    self.stats['state_transitions'][transition_type] += 1
                    self.stats['state_transitions']['total'] += 1
                    # Add to grand total matches
                    self.stats['matches']['total'] += 1
            elif update_type == 'established_match':
                self.stats['established_stats']['matched'] += 1
                # Already counted in matches['established']
            elif update_type == 'established_stats':
                # Handle established state counters with protection against negative values
                for key, value in update.items():
                    if key in self.stats['established_stats']:
                        # Check if we're trying to decrement below zero
                        if value < 0 and self.stats['established_stats'][key] + value < 0:
                            # Log the issue
                            logging.debug(f"Prevented negative counter: {key} (current: {self.stats['established_stats'][key]}, delta: {value})")
                            # Only decrement to zero, not below
                            self.stats['established_stats'][key] = 0
                            # Track this error
                            self.stats['errors']['negative_counters'] += 1
                        else:
                            self.stats['established_stats'][key] += value
                    else:
                        logging.warning(f"Unknown established stat key: {key}")
            elif update_type == 'timeout':
                state_num = update.get('state_num', 0)
                if state_num == 1:
                    self.stats['timed_out_by_state']['syn_sent'] += 1
                elif state_num == 2:
                    self.stats['timed_out_by_state']['syn_recv'] += 1
                elif state_num == 3:
                    self.stats['timed_out_by_state']['established'] += 1
                    self.stats['established_stats']['timed_out'] += 1
                else:
                    self.stats['timed_out_by_state']['other_states'] += 1
                self.stats['timed_out'] += 1

    def _log_periodic_stats(self):
        with self.lock:
            runtime = time.time() - self.start_time
            lines = self.stats['total_lines']
            packets_a = self.stats['packets_a']
            packets_b = self.stats['packets_b']
            
            # Direct state matches
            syn_sent_matches = self.stats['matches']['syn_sent']
            syn_recv_matches = self.stats['matches']['syn_recv']
            established_matches = self.stats['matches']['established']
            direct_total = syn_sent_matches + syn_recv_matches + established_matches
            
            # State transitions
            syn_sent_to_syn_recv = self.stats['state_transitions']['syn_sent_to_syn_recv']
            syn_sent_to_established = self.stats['state_transitions']['syn_sent_to_established']
            transition_total = self.stats['state_transitions']['total']
            
            # Total combined matches
            total_matches = direct_total + transition_total
            self.stats['matches']['total'] = total_matches
            
            neg_matches = self.stats['neg_diff_matches']
            pos_matches = self.stats['pos_diff_matches']
            timed_out = self.stats['timed_out']
            
            # ESTABLISHED specific stats
            established_matched = self.stats['established_stats']['matched']
            established_timed_out = self.stats['established_stats']['timed_out']
            established_unmatched = self.stats['established_stats']['unmatched']
            established_a_only = self.stats['established_stats']['device_a_only']
            established_b_only = self.stats['established_stats']['device_b_only']
            
            # Error tracking
            negative_counters = self.stats['errors']['negative_counters']
            
            rate = lines / runtime if runtime > 0 else 0
        
        logging.info(
            f"[{self.experiment_name}] Runtime: {runtime:.1f}s, Lines/sec: {rate:.1f}, "
            f"Packets A: {packets_a}, B: {packets_b}, "
            f"Matches: {total_matches} (ss->ss: {syn_sent_matches}, sr->sr: {syn_recv_matches}, "
            f"e->e: {established_matches}), Timed out: {timed_out}"
        )
        logging.info(
            f"[{self.experiment_name}] Transitions: ss->sr: {syn_sent_to_syn_recv}, "
            f"ss->e: {syn_sent_to_established}"
        )
        logging.info(
            f"[{self.experiment_name}] ESTABLISHED conn stats: Matched: {established_matched}, "
            f"Unmatched: {established_unmatched}, Timed out: {established_timed_out}, "
            f"Device A only: {established_a_only}, Device B only: {established_b_only}"
        )
        
        if negative_counters > 0:
            logging.warning(f"[{self.experiment_name}] Fixed {negative_counters} negative counter attempts")
        
        logging.info(
            f"[{self.experiment_name}] Total breakdown: Direct matches: {direct_total}, "
            f"Transition matches: {transition_total}, Total: {total_matches}"
        )

    def update_stats(self, update_type='basic', **kwargs):
        kwargs['type'] = update_type
        try:
            self.stats_queue.put(kwargs, timeout=0.1)
        except queue.Full:
            pass

    def write_final_summary(self, custom_timestamp=None):
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
            
            # Direct state matches
            syn_sent_matches = self.stats['matches']['syn_sent']
            syn_recv_matches = self.stats['matches']['syn_recv']
            established_matches = self.stats['matches']['established']
            direct_total = syn_sent_matches + syn_recv_matches + established_matches
            
            # State transitions
            syn_sent_to_syn_recv = self.stats['state_transitions']['syn_sent_to_syn_recv']
            syn_sent_to_established = self.stats['state_transitions']['syn_sent_to_established']
            transition_total = self.stats['state_transitions']['total']
            
            # Total combined matches
            total_matches = direct_total + transition_total
            self.stats['matches']['total'] = total_matches
            
            # Recalculate unmatched packets (total_packets - packets_in_matches)
            packets_in_matches = 2 * total_matches
            unmatched_count = total_packets - packets_in_matches
            self.stats['unmatched'] = unmatched_count
            
            timed_out_count = self.stats['timed_out']
            pos_matches = self.stats['pos_diff_matches']
            neg_matches = self.stats['neg_diff_matches']
            accounted_packets = packets_in_matches + unmatched_count + timed_out_count
            
            # ESTABLISHED specific stats
            established_matched = self.stats['established_stats']['matched']
            established_timed_out = self.stats['established_stats']['timed_out']
            established_unmatched = self.stats['unmatched_by_state']['established']
            established_device_a = self.stats['established_stats']['device_a_only']
            established_device_b = self.stats['established_stats']['device_b_only']

            with open(summary_log, 'w') as f:
                f.write("="*80 + "\n")
                f.write(f"CONNTRACK ANALYSIS EXPERIMENT SUMMARY\n")
                f.write(f"Experiment Name: {self.experiment_name}\n")
                if custom_timestamp:
                    current_time = custom_timestamp
                else:
                    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
                f.write(f"Completion Time: {current_time}\n")
                f.write(f"Runtime: {runtime:.2f} seconds\n")
                f.write(f"User: {self.username}\n")
                f.write(f"Device A: {self.device_a}\n")
                f.write(f"Device B: {self.device_b}\n")
                f.write(f"IP Range Filter: 172.16.1.0/24\n")
                f.write("="*80 + "\n\n")

                f.write("PACKET PROCESSING STATISTICS:\n")
                f.write(f"Total log lines read: {self.stats['total_lines']}\n")
                f.write(f"Total packets from {self.device_a} (A): {total_packets_a}\n")
                f.write(f"Total packets from {self.device_b} (B): {total_packets_b}\n")
                f.write(f"Total packets processed: {total_packets}\n\n")

                f.write("MATCHING RESULTS BY STATE:\n")
                f.write(f"Same state matches:\n")
                f.write(f"  - ss->ss (SYN_SENT): {syn_sent_matches}\n")
                f.write(f"  - sr->sr (SYN_RECV): {syn_recv_matches}\n")
                f.write(f"  - e->e (ESTABLISHED): {established_matches}\n")
                f.write(f"  Direct state matches subtotal: {direct_total}\n\n")
                
                f.write(f"State transition matches:\n")
                f.write(f"  - ss->sr (SYN_SENT to SYN_RECV): {self.stats['state_transitions']['syn_sent_to_syn_recv']}\n")
                f.write(f"  - ss->e (SYN_SENT to ESTABLISHED): {self.stats['state_transitions']['syn_sent_to_established']}\n")
                f.write(f"  State transitions subtotal: {transition_total}\n\n")
                
                f.write(f"TOTAL MATCH PAIRS FOUND: {total_matches}\n")
                f.write(f"  - Positive time diff (B > A): {pos_matches}\n")
                f.write(f"  - Negative time diff (A > B): {neg_matches}\n")
                f.write(f"Packets involved in matches: {packets_in_matches}\n")
                f.write(f"Unmatched packets: {unmatched_count}\n")
                f.write(f"Timed out connections: {timed_out_count}\n\n")
                
                f.write("UNMATCHED CONNECTIONS BY STATE:\n")
                f.write(f"  - SYN_SENT: {self.stats['unmatched_by_state']['syn_sent']}\n")
                f.write(f"  - SYN_RECV: {self.stats['unmatched_by_state']['syn_recv']}\n")
                f.write(f"  - ESTABLISHED: {self.stats['unmatched_by_state']['established']}\n")
                f.write(f"  - Other States: {self.stats['unmatched_by_state']['other_states']}\n\n")
                
                f.write("TIMED OUT CONNECTIONS BY STATE:\n")
                f.write(f"  - SYN_SENT: {self.stats['timed_out_by_state']['syn_sent']}\n")
                f.write(f"  - SYN_RECV: {self.stats['timed_out_by_state']['syn_recv']}\n")
                f.write(f"  - ESTABLISHED: {self.stats['timed_out_by_state']['established']}\n")
                f.write(f"  - Other States: {self.stats['timed_out_by_state']['other_states']}\n\n")
                
                f.write("ESTABLISHED CONNECTION STATISTICS:\n")
                f.write(f"  - Successfully matched: {established_matched}\n")
                f.write(f"  - Unmatched: {established_unmatched}\n")
                f.write(f"  - Timed out: {established_timed_out}\n")
                f.write(f"  - Only seen in device A: {established_device_a}\n")
                f.write(f"  - Only seen in device B: {established_device_b}\n\n")
                
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

                f.write("VERIFICATION (Ideal: 2*matched + unmatched + timed_out = total):\n")
                f.write(f"2 * {total_matches} + {unmatched_count} + {timed_out_count} = {accounted_packets}\n")
                f.write(f"Total packets processed: {total_packets}\n")
                f.write(f"Difference: {total_packets - accounted_packets}\n")
                if total_packets > 0:
                    match_rate = (2 * total_matches) / total_packets * 100
                    f.write(f"Match rate: {match_rate:.2f}%\n")
                f.write("\n")

                f.write(f"PROCESSING RATE: {self.stats['total_lines'] / runtime:.1f} lines/sec\n")
                f.write("="*80 + "\n")
        logging.info(f"Final summary written to: {summary_log}")

# Track direct matches and already processed connections
direct_matches_found = set()

def process_entry(entry, entries_by_hash, processed_hashes, writer, stats_collector, debug_mode):
    """Process a single entry using efficient hash-based lookup"""
    hash_value = entry['hash']
    device = entry['device']
    state_num = entry['state_num']
    is_device_a = device == stats_collector.device_a
    
    # Update basic statistics
    stats_collector.update_stats(
        packets_a=1 if is_device_a else 0, 
        packets_b=1 if not is_device_a else 0
    )
    
    # Track ESTABLISHED state separately - only increment the first time we see a hash
    conn_key = f"{hash_value}"
    device_key = 'device_a' if is_device_a else 'device_b'
    
    # Only increment "only seen in device X" counters if this is a new connection
    # and if the state is ESTABLISHED
    if state_num == 3 and conn_key not in entries_by_hash:
        if is_device_a:
            stats_collector.update_stats(update_type='established_stats', device_a_only=1)
        else:
            stats_collector.update_stats(update_type='established_stats', device_b_only=1)
    
    # Hash key to uniquely identify this connection
    entry_key = f"{conn_key}_{state_num}_{device}"
    
    # Skip if we've already processed this exact entry
    if entry_key in processed_hashes:
        return
    
    processed_hashes.add(entry_key)
    
    # Add this entry to the hash dictionary
    if conn_key not in entries_by_hash:
        entries_by_hash[conn_key] = {'device_a': {}, 'device_b': {}}
    
    if state_num not in entries_by_hash[conn_key][device_key]:
        entries_by_hash[conn_key][device_key][state_num] = []
    entries_by_hash[conn_key][device_key][state_num].append(entry)
    
    # Check if this connection already has a direct match (to avoid duplicate processing)
    direct_match_key = f"{conn_key}_{state_num}_direct"
    if direct_match_key in direct_matches_found:
        return
    
    # STEP 1: First look for direct state matches (same state on both devices)
    if (state_num in entries_by_hash[conn_key]['device_a'] and 
        state_num in entries_by_hash[conn_key]['device_b'] and
        entries_by_hash[conn_key]['device_a'][state_num] and 
        entries_by_hash[conn_key]['device_b'][state_num]):
        
        # For direct state matches, find the best timestamp match
        entry_a = entries_by_hash[conn_key]['device_a'][state_num][0]
        entry_b = entries_by_hash[conn_key]['device_b'][state_num][0]
        
        time_diff_ns = entry_b['timestamp_nano'] - entry_a['timestamp_nano']
        
        # Generate state information
        state_short = f"{get_tcp_state_short(state_num)}->{get_tcp_state_short(state_num)}"
        state_name = get_tcp_state_name(state_num)
        
        # Write to CSV
        debug_str = f"{entry_a['payload']} -> {entry_b['payload']}" if debug_mode else ''
        writer.writerow([
            time_diff_ns, 
            entry_a['proto_num'], 
            state_short,
            state_name,
            debug_str
        ])
        
        # Update stats for direct state matches
        match_stats = {
            'syn_sent': 1 if state_num == 1 else 0,
            'syn_recv': 1 if state_num == 2 else 0,
            'established': 1 if state_num == 3 else 0,
            'total': 1
        }
        stats_collector.update_stats(matches=match_stats)
        
        # Update ESTABLISHED specific stats - we found a direct match
        if state_num == 3:
            stats_collector.update_stats(update_type='established_match')
            # We need to be careful about decrementing the device-only counters
            # Only decrement if the counters are positive
            stats_collector.update_stats(update_type='established_stats', device_a_only=-1)
            stats_collector.update_stats(update_type='established_stats', device_b_only=-1)
        
        if time_diff_ns < 0:
            stats_collector.update_stats(
                update_type='negative_match', 
                diff_us=time_diff_ns / 1000.0
            )
        else:
            stats_collector.update_stats(pos_diff_matches=1)
            
        # Remove matched entries from the collections
        entries_by_hash[conn_key]['device_a'][state_num].pop(0)
        entries_by_hash[conn_key]['device_b'][state_num].pop(0)
        
        # Mark as having a direct match to avoid transition matching
        direct_matches_found.add(direct_match_key)
        
        # Remove empty lists
        if not entries_by_hash[conn_key]['device_a'][state_num]:
            del entries_by_hash[conn_key]['device_a'][state_num]
        if not entries_by_hash[conn_key]['device_b'][state_num]:
            del entries_by_hash[conn_key]['device_b'][state_num]
            
        return
    
    # STEP 2: If no direct match, only then check for specific transitions
    if device == stats_collector.device_b:
        check_for_state_transitions(conn_key, entry, entries_by_hash, direct_matches_found, writer, stats_collector, debug_mode)
    
    # Cleanup empty hash keys
    if entries_by_hash.get(conn_key):
        if not entries_by_hash[conn_key]['device_a'] and not entries_by_hash[conn_key]['device_b']:
            del entries_by_hash[conn_key]

def check_for_state_transitions(conn_key, entry, entries_by_hash, direct_matches_found, writer, stats_collector, debug_mode):
    """Check for state transitions between different states"""
    hash_value = entry['hash']
    device = entry['device']
    state_num = entry['state_num']
    
    # Only run this for Device B entries
    if device != stats_collector.device_b:
        return
    
    # IMPORTANT: Skip transition matching if this connection already has a direct match
    direct_match_exists = False
    for s in range(1, 4):  # Check states 1, 2, 3
        if f"{conn_key}_{s}_direct" in direct_matches_found:
            direct_match_exists = True
            break
    
    if direct_match_exists:
        # There's already a direct match for this connection, so skip transition matching
        return
    
    # Only check for SYN_SENT to SYN_RECV and SYN_SENT to ESTABLISHED transitions
    # For SYN_RECV in B, check for SYN_SENT in A
    if state_num == 2:  # B has SYN_RECV
        # Skip if SYN_RECV already has a direct match in A
        if 2 in entries_by_hash[conn_key]['device_a'] and entries_by_hash[conn_key]['device_a'][2]:
            return
            
        if 1 in entries_by_hash[conn_key]['device_a'] and entries_by_hash[conn_key]['device_a'][1]:
            entry_a = entries_by_hash[conn_key]['device_a'][1][0]
            entry_b = entry
            
            time_diff_ns = entry_b['timestamp_nano'] - entry_a['timestamp_nano']
            
            # Write state transition to CSV
            debug_str = f"{entry_a['payload']} -> {entry_b['payload']}" if debug_mode else ''
            writer.writerow([
                time_diff_ns, 
                entry_a['proto_num'], 
                "ss->sr",
                f"{get_tcp_state_name(1)}->{get_tcp_state_name(2)}",
                debug_str
            ])
            
            # Update state transition statistics
            stats_collector.update_stats(
                update_type='state_transition',
                transition_type='syn_sent_to_syn_recv'
            )
            
            if time_diff_ns < 0:
                stats_collector.update_stats(
                    update_type='negative_match', 
                    diff_us=time_diff_ns / 1000.0
                )
            else:
                stats_collector.update_stats(pos_diff_matches=1)
                
            # Remove the matched entry
            entries_by_hash[conn_key]['device_a'][1].pop(0)
            
            # Cleanup empty list
            if not entries_by_hash[conn_key]['device_a'][1]:
                del entries_by_hash[conn_key]['device_a'][1]
                
            return
    
    # For ESTABLISHED in B, only check for SYN_SENT in A (skip SYN_RECV in A)
    elif state_num == 3:  # B has ESTABLISHED
        # Skip if ESTABLISHED already has a direct match in A
        if 3 in entries_by_hash[conn_key]['device_a'] and entries_by_hash[conn_key]['device_a'][3]:
            return
            
        # Check only for SYN_SENT in A (skip SYN_RECV in A as requested)
        if 1 in entries_by_hash[conn_key]['device_a'] and entries_by_hash[conn_key]['device_a'][1]:
            entry_a = entries_by_hash[conn_key]['device_a'][1][0]
            entry_b = entry
            
            time_diff_ns = entry_b['timestamp_nano'] - entry_a['timestamp_nano']
            
            # Write state transition to CSV
            debug_str = f"{entry_a['payload']} -> {entry_b['payload']}" if debug_mode else ''
            writer.writerow([
                time_diff_ns, 
                entry_a['proto_num'], 
                "ss->e",
                f"{get_tcp_state_name(1)}->{get_tcp_state_name(3)}",
                debug_str
            ])
            
            # Update state transition statistics
            stats_collector.update_stats(
                update_type='state_transition',
                transition_type='syn_sent_to_established'
            )
            
            # Update ESTABLISHED specific stats - found a transition match
            stats_collector.update_stats(update_type='established_match')
            # Only try to decrement if we're sure it's positive
            stats_collector.update_stats(update_type='established_stats', device_b_only=-1)
            
            if time_diff_ns < 0:
                stats_collector.update_stats(
                    update_type='negative_match', 
                    diff_us=time_diff_ns / 1000.0
                )
            else:
                stats_collector.update_stats(pos_diff_matches=1)
                
            # Remove the matched entry
            entries_by_hash[conn_key]['device_a'][1].pop(0)
            
            # Cleanup empty list
            if not entries_by_hash[conn_key]['device_a'][1]:
                del entries_by_hash[conn_key]['device_a'][1]
                
            return

def check_timeouts(entries_by_hash, stats_collector, current_time, timeout_seconds):
    """Check for timed out entries and remove them"""
    timed_out_count = 0
    expired_hashes = []
    
    # First pass: collect all expired entries
    for conn_key, devices in entries_by_hash.items():
        for device_key in ['device_a', 'device_b']:
            expired_states = []
            for state_num, entries_list in devices[device_key].items():
                expired_entries = []
                for i, entry in enumerate(entries_list):
                    if 'entry_time' in entry and (current_time - entry['entry_time']) > timeout_seconds:
                        expired_entries.append(i)
                        
                        # Update stats based on state
                        stats_collector.update_stats(
                            update_type='timeout',
                            state_num=state_num
                        )
                        
                        # If it's an ESTABLISHED connection that's timing out, update established stats
                        if state_num == 3:
                            if device_key == 'device_a':
                                # Ensure we don't decrement below zero
                                stats_collector.update_stats(update_type='established_stats', device_a_only=-1)
                            else:
                                stats_collector.update_stats(update_type='established_stats', device_b_only=-1)
                        
                        timed_out_count += 1
                
                # Remove expired entries (in reverse to not mess up indices)
                for idx in sorted(expired_entries, reverse=True):
                    entries_list.pop(idx)
                
                # If all entries for this state are removed, mark the state for deletion
                if not entries_list:
                    expired_states.append(state_num)
            
            # Remove empty state collections
            for state_num in expired_states:
                del devices[device_key][state_num]
                
        # Check if this hash is now empty (both devices)
        if not devices['device_a'] and not devices['device_b']:
            expired_hashes.append(conn_key)
    
    # Remove all empty hash entries
    for conn_key in expired_hashes:
        del entries_by_hash[conn_key]
    
    return timed_out_count

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

def update_unmatched_stats(entries_by_hash, stats_collector):
    """Update statistics for unmatched entries by state"""
    unmatched_stats = {
        'syn_sent': 0,
        'syn_recv': 0,
        'established': 0,
        'other_states': 0
    }
    
    for conn_key, devices in entries_by_hash.items():
        for device_key in ['device_a', 'device_b']:
            for state_num, entries_list in devices[device_key].items():
                count = len(entries_list)
                if state_num == 1:
                    unmatched_stats['syn_sent'] += count
                elif state_num == 2:
                    unmatched_stats['syn_recv'] += count
                elif state_num == 3:
                    unmatched_stats['established'] += count
                else:
                    unmatched_stats['other_states'] += count
    
    stats_collector.update_stats(unmatched_by_state=unmatched_stats)

def main():
    parser = argparse.ArgumentParser(description="Process conntrack logs for matching entries.")
    parser.add_argument('-a', help="Name of device A (e.g., connt1)", required=True)
    parser.add_argument('-b', help="Name of device B (e.g., connt2)", required=True)
    parser.add_argument('-l', help="Path to log file to process", required=True)
    parser.add_argument('-o', help="Path to output CSV file", required=True)
    parser.add_argument('-e', help="Experiment name for logging and summary")
    parser.add_argument('-d', action='store_true', help="Enable debug mode")
    parser.add_argument('-k', action='store_true', help="Kill all running conntrackAnalysis.py processes")
    parser.add_argument('-D', action='store_true', help="Run in daemon mode")
    parser.add_argument('-L', help="Log file path for daemon (default: /tmp/conntrackAnalysis.log)")
    parser.add_argument('-t', type=int, default=60, help="Connection timeout in seconds (default: 60)")
    parser.add_argument('-u', help="Username for report (default: ajettesla)")
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

    # Use the provided username or default to "ajettesla"
    username = args.u if args.u else "ajettesla"
    
    # Get the current timestamp if needed for the report
    current_timestamp = "2025-07-04 14:48:59"  # Default from user input
    
    stats_collector = StatisticsCollector(experiment_name, args.a, args.b, output_dir, args.t, username)
    stats_collector.start()
    
    # Use simple dictionaries instead of complex data structures
    entries_by_hash = {}
    processed_hashes = set()

    @atexit.register
    def cleanup():
        logging.info("Cleaning up...")
        stats_collector.stop()
        
        # Update unmatched statistics by state
        update_unmatched_stats(entries_by_hash, stats_collector)
        
        logging.info("Writing final summary...")
        stats_collector.write_final_summary(current_timestamp)
        if os.path.exists(pid_file):
            os.remove(pid_file)

    # Create or open the CSV file
    if not os.path.exists(args.o):
        with open(args.o, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['time_diff_ns', 'protocol_num', 'state', 'state_name', 'debug_info'])
            
    csvfile = None
    try:
        csvfile = open(args.o, 'a', newline='')
        writer = csv.writer(csvfile)
        last_flush_time = time.time()
        last_timeout_check = time.time()
        last_stats_update = time.time()
        last_file_pos = 0
        
        with open(args.l, 'r') as f:
            # Read the file until the end and then wait for more data
            no_new_data_since = None
            
            while not shutdown_handler.is_shutdown_requested():
                line = f.readline()
                if line:
                    no_new_data_since = None  # Reset timer since we got new data
                    last_file_pos = f.tell()  # Remember where we are
                    
                    stats_collector.update_stats(total_lines=1)
                    entry = parse_line(line)
                    if entry:
                        process_entry(entry, entries_by_hash, processed_hashes, writer, stats_collector, args.d)
                else:
                    # No new data - check if file has grown
                    current_size = os.fstat(f.fileno()).st_size
                    if current_size > last_file_pos:
                        # File has grown but we're at EOF, seek to the position we remember
                        f.seek(last_file_pos)
                        continue
                    
                    # No new data and file hasn't grown
                    if no_new_data_since is None:
                        no_new_data_since = time.time()
                        logging.info(f"No new data, waiting for 30 seconds before exit...")
                    elif time.time() - no_new_data_since > 30:
                        logging.info(f"No new data for 30 seconds, exiting.")
                        break
                    
                    time.sleep(0.1)  # Sleep a bit to avoid high CPU usage
                
                # Check for timeouts periodically
                current_time = time.time()
                if current_time - last_timeout_check >= 5.0:
                    timed_out = check_timeouts(entries_by_hash, stats_collector, current_time, args.t)
                    if timed_out > 0:
                        logging.debug(f"Removed {timed_out} timed out entries")
                    last_timeout_check = current_time
                
                # Update unmatched statistics periodically
                if current_time - last_stats_update >= 10.0:
                    update_unmatched_stats(entries_by_hash, stats_collector)
                    last_stats_update = current_time
                
                # Flush CSV periodically
                if current_time - last_flush_time >= 5.0:
                    csvfile.flush()
                    last_flush_time = current_time
                    
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
