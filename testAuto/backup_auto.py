#!/usr/bin/env python3

import argparse
import os
import sys
import subprocess
import time
import threading
import signal
import random
import string
import datetime
import getpass
import json

from helper import (
    SSHConnector, 
    RemoteProgramRunner, 
    monitor_log_file_watchdog, 
    progress_tracker,
    colored,
    get_current_hostname,
    run_command_locally,
    run_command_remotely,
    run_command_with_timeout,
    pre_kill_conflicting_processes,
    cleanup_logging_scripts,
    verify_critical_processes_running,
    get_client_threads,
    periodic_progress_display,
    monitor_remote_log_file,
    RESET, RED, GREEN, YELLOW, BLUE, CYAN, MAGENTA, BOLD
)

# Global variables for cleanup and logging
current_experiment_name = None
current_experiment_id = None
current_concurrency = None
current_iteration = None
monitoring_threads = []
monitoring_stop_events = []
original_stdout = None
original_stderr = None
log_file = None
demon_mode = False  # Add global demon flag

# State file path for persistence between script executions
STATE_FILE = "/tmp/auto_experiment_state.json"

# Current date/time and user (updated per your requirements)
CURRENT_TIMESTAMP = "2025-06-19 11:39:07"  # UTC time
CURRENT_USER = "ajettesla"  # User login

# Default monitoring time in seconds
DEFAULT_MONITORING_TIME = 250

# Custom output class to write to both file and stdout
class TeeOutput:
    def __init__(self, file_stream, original_stream):
        self.file_stream = file_stream
        self.original_stream = original_stream
        
    def write(self, data):
        self.file_stream.write(data)
        self.original_stream.write(data)
        
    def flush(self):
        self.file_stream.flush()
        self.original_stream.flush()
        
    # Ensure compatibility with other stdout/stderr methods
    def isatty(self):
        return self.original_stream.isatty()
        
    def fileno(self):
        return self.original_stream.fileno()

def generate_experiment_id(length=5):
    """Generate a random alphanumeric identifier for the experiment"""
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def load_experiment_state():
    """Load experiment state from file"""
    if not os.path.exists(STATE_FILE):
        return None
    
    try:
        with open(STATE_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        print(f"Warning: Failed to load state file {STATE_FILE}")
        return None

def save_experiment_state(state):
    """Save experiment state to file"""
    try:
        with open(STATE_FILE, 'w') as f:
            json.dump(state, f, indent=2)
        # Make the file readable/writable by all users
        os.chmod(STATE_FILE, 0o666)
        print(f"Saved experiment state to {STATE_FILE}")
        return True
    except IOError as e:
        print(f"Error: Failed to save state file {STATE_FILE}: {e}")
        return False

def clear_experiment_state():
    """Clear experiment state file"""
    if os.path.exists(STATE_FILE):
        try:
            os.remove(STATE_FILE)
            print(f"Cleared experiment state file {STATE_FILE}")
            return True
        except IOError as e:
            print(f"Error: Failed to clear state file {STATE_FILE}: {e}")
            return False
    return True

def get_experiment_path(experiment_name, experiment_id, concurrency, iteration=None):
    """Get path for experiment with ID included"""
    base_path = f"/var/log/exp/{experiment_name}_{experiment_id}{concurrency}"
    if iteration:
        return f"{base_path}/{iteration}"
    return base_path

def signal_handler(signum, frame):
    """Handle Ctrl+C (SIGINT) and perform cleanup"""
    # Stop all monitoring threads
    for stop_event in monitoring_stop_events:
        stop_event.set()
    
    for thread in monitoring_threads:
        if thread.is_alive():
            thread.join(timeout=5)
    
    # Cleanup logging scripts if experiment was running
    if current_experiment_name and current_experiment_id and current_concurrency and current_iteration:
        cleanup_logging_scripts(current_experiment_name, current_concurrency, current_iteration, current_experiment_id)
    
    # Close log file if it was redirected
    if log_file and demon_mode:
        log_file.close()
        # Restore original stdout/stderr
        sys.stdout = original_stdout
        sys.stderr = original_stderr
    
    # Print FAILURE to appropriate output
    original_stdout.write("FAILURE\n")
    original_stdout.flush()
    
    sys.exit(130)

def setup_logging(experiment_name, experiment_id, demon, timestamp=CURRENT_TIMESTAMP, user=CURRENT_USER):
    """Set up logging to both file and stdout when in demon mode"""
    global original_stdout, original_stderr, log_file, demon_mode
    
    demon_mode = demon
    
    # Save original stdout/stderr
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    
    if demon:
        # Create log file with timestamp and experiment ID
        log_timestamp = timestamp.replace(" ", "_").replace(":", "")
        log_path = f"/tmp/{experiment_name}_{experiment_id}_{log_timestamp}_auto.log"
        log_file = open(log_path, 'w', buffering=1)
        
        # Write header to log file
        header = (
            f"=== Experiment Log ===\n"
            f"Date/Time: {timestamp}\n"
            f"User: {user}\n"
            f"Host: {get_current_hostname()}\n"
            f"Experiment: {experiment_name}\n"
            f"Experiment ID: {experiment_id}\n"
            f"==============================\n\n"
        )
        log_file.write(header)
        
        # Create Tee output that writes to both file and original stdout/stderr
        sys.stdout = TeeOutput(log_file, original_stdout)
        sys.stderr = TeeOutput(log_file, original_stderr)
        
        # Also print header to stdout
        original_stdout.write(header)
        
        return log_path
    else:
        # In normal mode, keep stdout/stderr as they are
        return None

def check_function():
    print(colored("[check] Step: Service Restart/Check/Flush", BOLD))
    service_hosts = {
        "convsrc8": ["tcp_server", "udp_server"],
        "convsrc5": ["tcp_server", "udp_server"]
    }
    logger_hosts = ["connt1", "connt2"]
    logger_host = ["connt1"]
    ssh_connector = SSHConnector()

    # Service restart/check for tcp_server/udp_server
    for host, services in service_hosts.items():
        client = ssh_connector.connect(host)
        tag = f"[{host} ssh]" if client else f"[{host} localhost]"
        for service in services:
            cmd_restart = f"sudo systemctl restart {service}"
            cmd_check   = f"sudo systemctl is-active {service}"
            if client is None:
                ok, _, err = run_command_locally(cmd_restart, tag)
                if not ok:
                    print(colored(f"{tag} {service} restart failed! {err}", RED))
                    return 1
                ok, out, err = run_command_locally(cmd_check, tag)
            else:
                ok, _, err = run_command_remotely(client, cmd_restart, tag)
                if not ok:
                    print(colored(f"{tag} {service} restart failed! {err}", RED))
                    if client: client.close()
                    return 2
                ok, out, err = run_command_remotely(client, cmd_check, tag)
            if not ok or "active" not in out:
                print(colored(f"{tag} {service} is not active! Output: {out} Error: {err}", RED))
                if client: client.close()
                return 3
        if client: client.close()

    # Conntrackd service management
    print(colored("[check] Step: Conntrackd Service Management", BOLD))
    for host in logger_host:
        client = ssh_connector.connect(host)
        tag = f"[{host} ssh]" if client else f"[{host} localhost]"
        
        cmd_check_status = "sudo systemctl is-active conntrackd"
        if client is None:
            status, output, err = run_command_locally(cmd_check_status, tag)
        else:
            status, output, err = run_command_remotely(client, cmd_check_status, tag)
        
        if status and "active" in output.strip():
            print(colored(f"{tag} conntrackd service is already active.", GREEN))
        else:
            print(colored(f"{tag} conntrackd service is not active. Starting it...", YELLOW))
            
            cmd_start = "sudo systemctl start conntrackd"
            if client is None:
                start_status, start_output, start_err = run_command_locally(cmd_start, tag)
            else:
                start_status, start_output, start_err = run_command_remotely(client, cmd_start, tag)
            
            if not start_status:
                print(colored(f"{tag} Failed to start conntrackd service!", RED))
                if client: client.close()
                return 9
            
            time.sleep(3)
            print(colored(f"{tag} conntrackd service started successfully.", GREEN))
        
        if client: client.close()

    # Chrony service management (added to check time synchronization)
    print(colored("[check] Step: Chrony Service Management", BOLD))
    for host in logger_hosts:
        client = ssh_connector.connect(host)
        tag = f"[{host} ssh]" if client else f"[{host} localhost]"
        
        cmd_check_status = "sudo systemctl is-active chrony"
        if client is None:
            status, output, err = run_command_locally(cmd_check_status, tag)
        else:
            status, output, err = run_command_remotely(client, cmd_check_status, tag)
        
        if status and "active" in output.strip():
            print(colored(f"{tag} chrony service is already active.", GREEN))
        else:
            print(colored(f"{tag} chrony service is not active. Starting it...", YELLOW))
            
            cmd_start = "sudo systemctl start chrony"
            if client is None:
                start_status, start_output, start_err = run_command_locally(cmd_start, tag)
            else:
                start_status, start_output, start_err = run_command_remotely(client, cmd_start, tag)
            
            if not start_status:
                print(colored(f"{tag} Failed to start chrony service!", RED))
                if client: client.close()
                return 10
            
            time.sleep(3)
            print(colored(f"{tag} chrony service started successfully.", GREEN))
        
        if client: client.close()

    # Truncate logs
    print(colored("[check] Step: Truncate Logs", BOLD))
    ssh_convsrc2 = ssh_connector.connect("convsrc2")
    for logfile in ["/var/log/conntrack.log"]:
        cmd_truncate = f"sudo truncate -s 0 {logfile}"
        if ssh_convsrc2 is None:
            ok, _, err = run_command_locally(cmd_truncate, "[convsrc2 localhost]")
        else:
            ok, _, err = run_command_remotely(ssh_convsrc2, cmd_truncate, "[convsrc2 ssh]")
        if not ok:
            print(colored(f"Failed to truncate {logfile}: {err}", RED))
            if ssh_convsrc2: ssh_convsrc2.close()
            return 8
        else:
            print(colored(f"Successfully truncated {logfile}", GREEN))
    if ssh_convsrc2: ssh_convsrc2.close()

    # Conntrack logger service management
    print(colored("[check] Step: Conntrack Logger Service Management", BOLD))
    for host in logger_hosts:
        client = ssh_connector.connect(host)
        tag = f"[{host} ssh]" if client else f"[{host} localhost]"
        cmd_restart = "sudo systemctl restart conntrack_logger"
        cmd_check   = "sudo systemctl is-active conntrack_logger"
        cmd_flush   = "sudo conntrack -F"
        
        if client is None:
            ok, _, err = run_command_locally(cmd_restart, tag)
            if not ok:
                print(colored(f"{tag} conntrack_logger restart failed! {err}", RED))
                return 4
            ok, out, err = run_command_locally(cmd_check, tag)
        else:
            ok, _, err = run_command_remotely(client, cmd_restart, tag)
            if not ok:
                print(colored(f"{tag} conntrack_logger restart failed! {err}", RED))
                if client: client.close()
                return 5
            ok, out, err = run_command_remotely(client, cmd_check, tag)

        if not ok or "active" not in out:
            print(colored(f"{tag} conntrack_logger is not active!", RED))
            if client: client.close()
            return 6

        print(colored(f"{tag} conntrack_logger service is active.", GREEN))

        if client is None:
            ok, _, err = run_command_locally(cmd_flush, tag)
        else:
            ok, _, err = run_command_remotely(client, cmd_flush, tag)
        if not ok:
            print(colored(f"{tag} conntrack flush failed! {err}", RED))
            if client: client.close()
            return 7
        
        if client: client.close()

    print(colored("[check] All services active and conntrack tables flushed.", GREEN))

    # Log monitoring (removed PTP monitoring completely)
    print(colored("[check] Step: Log Monitoring", BOLD))
    
    conntrack_stop_event = threading.Event()
    monitor_results = {}

    conntrack_monitor_thread = threading.Thread(
        target=monitor_log_file_watchdog,
        kwargs=dict(
            filepath="/var/log/conntrack.log",
            keyword_expr="'connt1' 'connt2'",
            timeout=120,
            print_output=False,
            result_dict=monitor_results,
            stop_event=conntrack_stop_event,
        ),
        name="conntrack-monitor"
    )

    print(colored("[check] Started log monitors.", CYAN))
    conntrack_monitor_thread.start()

    print(colored("[check] Step: Start Client Threads", BOLD))
    client_threads = get_client_threads(10, 1, 1)
    for th in client_threads:
        th.start()

    for th in client_threads:
        th.join()

    print(colored("[check] All client threads completed.", CYAN))

    conntrack_monitor_thread.join()

    conntrack_matches = monitor_results.get("conntrack-monitor", 0)
    total_matches = conntrack_matches

    print(f"[check] Total matches: {total_matches}")

    if total_matches == 2:
        print(colored("[check] MATCH found! Proceeding...", GREEN))
        return 2
    else:
        print(colored("[check] Required matches not found!", RED))
        return 0

def pre_experimentation(experiment_name, concurrency, iteration, experiment_id):
    global current_experiment_name, current_concurrency, current_iteration, current_experiment_id
    current_experiment_name = experiment_name
    current_experiment_id = experiment_id
    current_concurrency = concurrency
    current_iteration = iteration
    
    exp_path = get_experiment_path(experiment_name, experiment_id, concurrency, iteration)
    print(f"[pre-exp] Running pre_experimentation for {exp_path}")
    
    # Flush conntrack tables
    logger_hosts = ["connt1", "connt2"]
    ssh_connector = SSHConnector()
    
    for host in logger_hosts:
        client = ssh_connector.connect(host)
        tag = f"[{host} ssh]" if client else f"[{host} localhost]"
        cmd_flush = "sudo conntrack -F"
        if client is None:
            ok, _, err = run_command_locally(cmd_flush, tag)
        else:
            ok, _, err = run_command_remotely(client, cmd_flush, tag)
        if not ok:
            print(f"ERROR: {tag} conntrack flush failed! {err}")
            if client: client.close()
            return False
        if client: client.close()
    
    print("[pre-exp] Conntrack tables flushed.")
    
    # Setup logging scripts
    CAlog = f"/tmp/CA_{experiment_id}.log"
    base_path = get_experiment_path(experiment_name, experiment_id, concurrency)
    
    # Create output directories first
    for host in ["connt1", "convsrc2"]:
        client = ssh_connector.connect(host)
        tag = f"[{host} ssh]" if client else f"[{host} localhost]"
        cmd_mkdir = f"sudo mkdir -p {base_path}"
        if client is None:
            ok, _, err = run_command_locally(cmd_mkdir, tag)
        else:
            ok, _, err = run_command_remotely(client, cmd_mkdir, tag)
        if not ok:
            print(f"ERROR: {tag} Failed to create directory {base_path}: {err}")
            if client: client.close()
            return False
        if client: client.close()
    
    # Define the logging script configurations with corrected path for conntrackAnalysis.py
    log_configs = [
        ("connt1", f"sudo ./start.sh -i {iteration} -l {base_path}/{iteration} -p conntrackd --iface enp3s0 -d", "start.sh", "/opt/MasterThesis/CMNpsutil/", True),
        ("convsrc2", f"sudo ./conntrackAnalysis.py -a connt1 -b connt2 -l /var/log/conntrack.log -o {base_path}/{iteration}_ca.csv -D -L {CAlog}", "conntrackAnalysis.py", "/opt/MasterThesis/connectiontrackingAnalysis/", True)
    ]
    
    print("[pre-exp] Setting up logging scripts")
    
    for host, cmd, program_file, working_dir, is_daemon in log_configs:
        client = ssh_connector.connect(host)
        tag = f"[{host} ssh]" if client else f"[{host} localhost]"

        # Check if program exists first
        check_cmd = f"cd {working_dir} && ls -la ./{program_file}"
        if client is None:
            check_status, check_output, check_stderr = run_command_locally(check_cmd, tag)
        else:
            check_status, check_output = run_command_with_timeout(client, check_cmd, 5, hostname=host)
        
        if not check_status:
            print(f"ERROR: [{host}] Script {program_file} not found in {working_dir}: {check_stderr if client is None else check_output}")
            if client: client.close()
            return False
        
        # Kill any existing processes
        programs_to_kill = ["start.sh", "cm_monitor.py", "n_monitor.py"] if program_file == "start.sh" else ["conntrackAnalysis.py"]
        pre_kill_conflicting_processes(client, host, programs_to_kill)

        # Run the command with verbose output
        print(f"[{host}] Executing: cd {working_dir} && {cmd}")
        full_cmd = f"cd {working_dir} && {cmd}"
        if client is None:
            status, output, stderr = run_command_locally(full_cmd, tag)
            if not status:
                print(f"ERROR: [{host}] Failed to start logging script: {stderr}")
                cleanup_logging_scripts(experiment_name, concurrency, iteration, experiment_id)
                if client: client.close()
                return False
            else:
                print(f"[{host}] Command output: {output}")
        else:
            # Use a longer timeout for conntrackAnalysis.py because it might take longer to start
            timeout = 60 if program_file == "conntrackAnalysis.py" else 30
            status, output = run_command_with_timeout(client, full_cmd, timeout, hostname=host)
            if not status:
                print(f"ERROR: [{host}] Failed to start logging script: {output}")
                cleanup_logging_scripts(experiment_name, concurrency, iteration, experiment_id)
                if client: client.close()
                return False
            else:
                print(f"[{host}] Command output: {output}")

        # Give the processes time to start
        time.sleep(15)

        # Check if processes are running
        if is_daemon:
            search_cmd = f"pgrep -f {program_file}"
            if client is None:
                status, output, stderr = run_command_locally(search_cmd, tag)
            else:
                status, output = run_command_with_timeout(client, search_cmd, 5, hostname=host)
                
            if not status or not output.strip():
                # If we didn't find the process, try a more permissive search
                alt_search_cmd = f"ps aux | grep {program_file} | grep -v grep"
                if client is None:
                    alt_status, alt_output, alt_stderr = run_command_locally(alt_search_cmd, tag)
                    print(f"[{host}] Process search output: {alt_output}")
                else:
                    alt_status, alt_output = run_command_with_timeout(client, alt_search_cmd, 5, hostname=host)
                    print(f"[{host}] Process search output: {alt_output}")
                
                print(f"ERROR: [{host}] Could not detect PID for {program_file}")
                cleanup_logging_scripts(experiment_name, concurrency, iteration, experiment_id)
                if client: client.close()
                return False

            pids = output.strip().splitlines()
            print(f"[{host}] {program_file} running with PID: {pids[0]}")

        if client: client.close()

    print(f"[pre-exp] Setup completed for {experiment_name}_{experiment_id}{concurrency}/{iteration}")
    verify_critical_processes_running(experiment_name, concurrency, iteration, experiment_id)
    return True

def cleanup_logging_scripts(experiment_name, concurrency, iteration, experiment_id):
    """Modified version of cleanup_logging_scripts that includes experiment_id"""
    print(f"[cleanup] Cleaning up logging scripts for {experiment_name}_{experiment_id}{concurrency}/{iteration}")
    
    ssh_connector = SSHConnector()
    
    hosts_to_cleanup = {
        "connt1": ["start.sh", "cm_monitor.py", "n_monitor.py"],
        "convsrc2": ["conntrackAnalysis.py"]
    }
    
    for host, programs in hosts_to_cleanup.items():
        client = ssh_connector.connect(host)
        tag = f"[{host} ssh]" if client else f"[{host} localhost]"
        
        for program in programs:
            cmd_find = f"pgrep -f {program}"
            if client is None:
                status, output, stderr = run_command_locally(cmd_find, tag)
            else:
                status, output = run_command_with_timeout(client, cmd_find, 5, hostname=host)
                
            if status and output.strip():
                pids = output.strip().splitlines()
                for pid in pids:
                    cmd_kill = f"sudo kill -9 {pid}"
                    if client is None:
                        kill_status, _, kill_err = run_command_locally(cmd_kill, tag)
                    else:
                        kill_status, _ = run_command_with_timeout(client, cmd_kill, 5, hostname=host)
                    
                    if kill_status:
                        print(f"[cleanup] {tag} Killed {program} (PID: {pid})")
                    else:
                        print(f"[cleanup] {tag} Failed to kill {program} (PID: {pid})")
        
        if client: client.close()
    
    print(f"[cleanup] Completed cleanup for {experiment_name}_{experiment_id}{concurrency}/{iteration}")

def verify_critical_processes_running(experiment_name, concurrency, iteration, experiment_id):
    """Modified version of verify_critical_processes_running that includes experiment_id"""
    print(f"[verify] Verifying critical processes for {experiment_name}_{experiment_id}{concurrency}/{iteration}")
    
    critical_processes = {
        "connt1": ["start.sh", "cm_monitor.py", "n_monitor.py"],
        "convsrc2": ["conntrackAnalysis.py"]
    }
    
    ssh_connector = SSHConnector()
    all_ok = True
    
    for host, processes in critical_processes.items():
        client = ssh_connector.connect(host)
        tag = f"[{host} ssh]" if client else f"[{host} localhost]"
        
        for process in processes:
            cmd_find = f"pgrep -f {process}"
            if client is None:
                status, output, stderr = run_command_locally(cmd_find, tag)
            else:
                status, output = run_command_with_timeout(client, cmd_find, 5, hostname=host)
                
            if not status or not output.strip():
                print(colored(f"[verify] ERROR: {tag} Process {process} is not running!", RED))
                all_ok = False
            else:
                print(colored(f"[verify] {tag} Process {process} is running.", GREEN))
        
        if client: client.close()
    
    if all_ok:
        print(colored(f"[verify] All critical processes are running for {experiment_name}_{experiment_id}{concurrency}/{iteration}", GREEN))
    else:
        print(colored(f"[verify] SOME CRITICAL PROCESSES ARE NOT RUNNING for {experiment_name}_{experiment_id}{concurrency}/{iteration}", RED))
    
    return all_ok

def check_conntrack_entries():
    """Check if total conntrack entries in connt1 and connt2 are < 100"""
    ssh_connector = SSHConnector()
    total_entries = 0
    
    for host in ["connt1", "connt2"]:
        client = ssh_connector.connect(host)
        tag = f"[{host} ssh]" if client else f"[{host} localhost]"
        cmd_count = "sudo conntrack -C"
        
        if client is None:
            status, output, stderr = run_command_locally(cmd_count, tag)
        else:
            status, output = run_command_with_timeout(client, cmd_count, 5, hostname=host)
        
        if status and output.strip():
            try:
                entries = int(output.strip())
                total_entries += entries
                print(f"[monitor] {tag} Conntrack entries: {entries}")
            except (ValueError, TypeError):
                print(f"[monitor] {tag} Failed to parse conntrack count: {output}")
        
        if client: client.close()
    
    print(f"[monitor] Total conntrack entries: {total_entries}")
    return total_entries < 100

def check_csv_file_growth(filepath, host):
    """Check if the number of lines in a CSV file is growing"""
    ssh_connector = SSHConnector()
    client = ssh_connector.connect(host)
    tag = f"[{host} ssh]" if client else f"[{host} localhost]"
    
    # Get initial line count
    cmd_count = f"wc -l {filepath} | awk '{{print $1}}'"
    
    if client is None:
        status, output, stderr = run_command_locally(cmd_count, tag)
    else:
        status, output = run_command_with_timeout(client, cmd_count, 5, hostname=host)
    
    if not status or not output.strip():
        print(f"[monitor] {tag} Failed to get line count for {filepath}")
        if client: client.close()
        return True  # Assume growing to be safe
    
    try:
        initial_count = int(output.strip())
    except (ValueError, TypeError):
        print(f"[monitor] {tag} Failed to parse line count: {output}")
        if client: client.close()
        return True  # Assume growing to be safe
    
    print(f"[monitor] {tag} Initial line count for {filepath}: {initial_count}")
    
    # Wait 30 seconds
    time.sleep(30)
    
    # Get new line count
    if client is None:
        status, output, stderr = run_command_locally(cmd_count, tag)
    else:
        status, output = run_command_with_timeout(client, cmd_count, 5, hostname=host)
    
    if not status or not output.strip():
        print(f"[monitor] {tag} Failed to get new line count for {filepath}")
        if client: client.close()
        return True  # Assume growing to be safe
    
    try:
        new_count = int(output.strip())
    except (ValueError, TypeError):
        print(f"[monitor] {tag} Failed to parse new line count: {output}")
        if client: client.close()
        return True  # Assume growing to be safe
    
    print(f"[monitor] {tag} New line count for {filepath}: {new_count}")
    
    if client: client.close()
    
    # If new count > initial count, file is growing
    return new_count <= initial_count

# This is a modified version of the periodic progress display function
# that doesn't use fancy box formatting and updates every 10 seconds
class SimpleProgressDisplay(threading.Thread):
    def __init__(self, stop_event):
        super().__init__()
        self.stop_event = stop_event
        self.name = "SimpleProgressDisplay"
        
    def run(self):
        while not self.stop_event.is_set():
            elapsed = time.time() - progress_tracker.start_time
            elapsed_minutes = elapsed / 60.0
            
            # Collect stats for the files we're monitoring
            stats_message = []
            total_size = 0
            total_delta = 0
            total_lines = 0
            
            for filepath, stats in progress_tracker.file_stats.items():
                if stats.get('size', 0) > 0:
                    filename = os.path.basename(filepath)
                    size_mb = stats.get('size', 0) / (1024 * 1024)
                    delta_mb = stats.get('delta_size', 0) / (1024 * 1024)
                    lines = stats.get('lines', 0)
                    
                    stats_message.append(f"{filename:<25} | {size_mb:7.2f}MB | +{delta_mb:7.2f}MB | Lines: {lines:7d}")
                    
                    total_size += stats.get('size', 0)
                    total_delta += stats.get('delta_size', 0)
                    total_lines += lines
            
            # Print a simple progress report
            print(f"\n[Progress] Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Elapsed: {elapsed_minutes:.1f} minutes")
            print("-" * 70)
            
            # Only show file stats and total if we have data
            if stats_message:
                for line in stats_message:
                    print(line)
                print("-" * 70)
                
                total_size_mb = total_size / (1024 * 1024)
                total_delta_mb = total_delta / (1024 * 1024)
                print(f"TOTAL: {total_size_mb:.2f}MB | +{total_delta_mb:.2f}MB | Lines: {total_lines}")
            
            try:
                self.stop_event.wait(timeout=10)  # Update every 10 seconds
            except:
                break

def experimentation(experiment_name, concurrency, iteration, experiment_id):
    global monitoring_threads, monitoring_stop_events
    
    print(f"[exp] Running experimentation for {experiment_name}_{experiment_id}{concurrency}/{iteration}")
    
    base_path = get_experiment_path(experiment_name, experiment_id, concurrency)
    ca_csv_file = f"{base_path}/{iteration}_ca.csv"
    log_files_to_monitor = [
        {"filepath": ca_csv_file, "host": "convsrc2"},
        {"filepath": f"{base_path}/{iteration}_conntrackd_cm_monitor.csv", "host": "connt1"},
        {"filepath": f"{base_path}/{iteration}_conntrackd_n_monitor.csv", "host": "connt1"}
    ]

    print("[exp] Starting log file monitoring")
    
    progress_tracker.file_stats.clear()
    progress_tracker.start_time = time.time()
    progress_tracker.last_full_display = 0
    
    monitor_results = {}
    monitoring_threads = []
    monitoring_stop_events = []
    
    # Set up silent monitoring (with print_output=False)
    for log_info in log_files_to_monitor:
        stop_event = threading.Event()
        monitoring_stop_events.append(stop_event)
        
        t = threading.Thread(
            target=monitor_remote_log_file,
            kwargs={
                "filepath": log_info["filepath"],
                "host": log_info["host"],
                "keyword_expr": "",
                "timeout": None,
                "print_output": False,  # Set to False to disable detailed messages
                "result_dict": monitor_results,
                "stop_event": stop_event,
            },
            name=f"ExpMonitor-{log_info['host']}-{os.path.basename(log_info['filepath'])}"
        )
        monitoring_threads.append(t)
        t.start()
    
    # Use the simplified progress display that updates every 10 seconds
    progress_display_stop = threading.Event()
    progress_thread = SimpleProgressDisplay(progress_display_stop)
    progress_thread.start()
    
    print("[exp] Starting client threads")
    client_threads = get_client_threads(250000, concurrency, 4)
    for th in client_threads:
        th.start()

    for th in client_threads:
        th.join()

    print("[exp] Client threads completed, beginning monitoring period")
    
    # Start monitoring with continuous condition checks
    monitoring_time = DEFAULT_MONITORING_TIME  # Default maximum monitoring time
    start_time = time.time()
    check_interval = 30  # Check conditions every 30 seconds
    
    # Continue monitoring until max time reached or both conditions met
    while (time.time() - start_time) < monitoring_time:
        time_elapsed = time.time() - start_time
        time_remaining = monitoring_time - time_elapsed
        
        # Check condition 1: Total conntrack entries < 100
        print(f"[exp] Checking condition 1: Conntrack entries < 100 (Time elapsed: {time_elapsed:.1f}s)")
        condition1_met = check_conntrack_entries()
        
        if condition1_met:
            print(colored("[exp] Condition 1 met: Low conntrack entries detected", YELLOW))
            
            # Check condition 2: CA.csv file not growing
            print(f"[exp] Checking condition 2: CSV file growth (Time elapsed: {time_elapsed:.1f}s)")
            condition2_met = check_csv_file_growth(ca_csv_file, "convsrc2")
            
            if condition2_met:
                print(colored("[exp] Condition 2 met: CSV file not growing", YELLOW))
                print(colored("[exp] Both conditions met! Ending monitoring early.", GREEN))
                # Both conditions met, end monitoring early
                break
            else:
                print(colored("[exp] Condition 2 NOT met: CSV file is still growing", YELLOW))
                if time_remaining > check_interval:
                    print(f"[exp] Continuing monitoring for up to {time_remaining:.1f} more seconds...")
                    time.sleep(check_interval)
                else:
                    # Less than check_interval seconds remaining, just wait the rest
                    time.sleep(time_remaining)
        else:
            print(colored("[exp] Condition 1 NOT met: Too many conntrack entries", YELLOW))
            if time_remaining > check_interval:
                print(f"[exp] Continuing monitoring for up to {time_remaining:.1f} more seconds...")
                time.sleep(check_interval)
            else:
                # Less than check_interval seconds remaining, just wait the rest
                time.sleep(time_remaining)
    
    total_monitoring_time = time.time() - start_time
    print(f"[exp] Monitoring completed after {total_monitoring_time:.1f} seconds")
    
    progress_display_stop.set()
    for stop_event in monitoring_stop_events:
        stop_event.set()
    
    progress_thread.join(timeout=10)
    for t in monitoring_threads:
        t.join(timeout=10)
    
    print("[exp] Experimentation completed")
    
    monitoring_threads = []
    monitoring_stop_events = []
    
    return True

def post_experimentation(experiment_name, concurrency, iteration, experiment_id, update_state=True):
    global current_experiment_name, current_concurrency, current_iteration, current_experiment_id
    
    print(f"[post-exp] Cleanup for {experiment_name}_{experiment_id}{concurrency}/{iteration}")
    cleanup_logging_scripts(experiment_name, concurrency, iteration, experiment_id)
    
    # If requested, update the state file with incremented iteration
    if update_state:
        next_iteration = iteration + 1
        # Load current state
        state = load_experiment_state() or {}
        if state.get('name') == experiment_name and state.get('id') == experiment_id:
            print(f"[post-exp] Updating state file iteration to {next_iteration}")
            state['iteration'] = next_iteration
            state['timestamp'] = CURRENT_TIMESTAMP
            state['user'] = CURRENT_USER
            save_experiment_state(state)
    
    current_experiment_name = None
    current_experiment_id = None
    current_concurrency = None
    current_iteration = None
    
    print("[post-exp] Cleanup completed")
    return True

def main():
    parser = argparse.ArgumentParser(description="Automation script for experiments.")
    parser.add_argument("-n", "--name", required=True, help="Experiment name")
    parser.add_argument("-c", "--concurrency", required=True, help="Concurrency values (comma-separated)")
    parser.add_argument("-d", "--demon", action="store_true", help="demon mode - redirect output to log file")
    parser.add_argument("-i", "--iterations", type=int, default=1, help="Number of iterations (default: 1, ignored in --cont mode)")
    
    # Add new experiment continuation control
    continuation_group = parser.add_mutually_exclusive_group()
    continuation_group.add_argument("--new", action="store_true", help="Start a new experiment, clear existing state")
    continuation_group.add_argument("--cont", action="store_true", help="Continue an existing experiment if state matches")
    
    args = parser.parse_args()

    experiment_name = args.name
    requested_iterations = args.iterations  # Only used in non-cont mode
    demon = args.demon
    
    # Parse concurrency values
    try:
        concurrency_values = [int(x.strip()) for x in args.concurrency.split(',')]
    except ValueError:
        print("ERROR: Invalid concurrency values")
        sys.exit(1)
    
    # Handle experiment state
    global current_experiment_id
    
    continuing_experiment = False
    current_iteration_count = 1  # Default starting iteration
    
    if args.new:
        # Clear any existing state and create new
        clear_experiment_state()
        current_experiment_id = generate_experiment_id()
        # In --new mode, always start with iteration 1
        state = {
            'name': experiment_name,
            'id': current_experiment_id,
            'concurrency': concurrency_values,
            'iteration': current_iteration_count,
            'timestamp': CURRENT_TIMESTAMP,
            'user': CURRENT_USER
        }
        save_experiment_state(state)
        print(f"Created new experiment ID: {current_experiment_id}")
    elif args.cont:
        # Check for existing state
        state = load_experiment_state()
        if state and state.get('name') == experiment_name:
            # Check if concurrency values match
            stored_concurrency = state.get('concurrency', [])
            if set(stored_concurrency) == set(concurrency_values):
                # Continue with existing state
                current_experiment_id = state.get('id')
                # Use the iteration from state
                current_iteration_count = state.get('iteration', 1)
                continuing_experiment = True
                
                # Update state with current timestamp but keep iteration
                state['timestamp'] = CURRENT_TIMESTAMP
                state['user'] = CURRENT_USER
                save_experiment_state(state)
                print(f"Continuing experiment with ID: {current_experiment_id}, iteration: {current_iteration_count}")
            else:
                print(f"WARNING: Found experiment with name '{experiment_name}' but concurrency values don't match.")
                print(f"State has: {stored_concurrency}, but you provided: {concurrency_values}")
                # Clear existing state
                clear_experiment_state()
                # Create new experiment with new ID
                current_experiment_id = generate_experiment_id()
                # Start with iteration 1 for new experiment
                state = {
                    'name': experiment_name,
                    'id': current_experiment_id,
                    'concurrency': concurrency_values,
                    'iteration': current_iteration_count,
                    'timestamp': CURRENT_TIMESTAMP,
                    'user': CURRENT_USER
                }
                save_experiment_state(state)
                print(f"Creating new experiment ID: {current_experiment_id}")
        else:
            # No matching state, create new
            current_experiment_id = generate_experiment_id()
            # Start with iteration 1 for new experiment
            state = {
                'name': experiment_name,
                'id': current_experiment_id,
                'concurrency': concurrency_values,
                'iteration': current_iteration_count,
                'timestamp': CURRENT_TIMESTAMP,
                'user': CURRENT_USER
            }
            save_experiment_state(state)
            print(f"No matching experiment found. Created new experiment ID: {current_experiment_id}")
    else:
        # No continuation option specified, generate a new ID but don't save state
        current_experiment_id = generate_experiment_id()
        print(f"Using temporary experiment ID: {current_experiment_id}")
    
    # Setup logging - write to both file and stdout in demon mode
    log_path = setup_logging(experiment_name, current_experiment_id, demon)
    
    # Register signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        print(f"[MAIN] Experiment: {experiment_name}")
        print(f"[MAIN] Experiment ID: {current_experiment_id}")
        
        if args.cont and continuing_experiment:
            print(f"[MAIN] Continuing from iteration: {current_iteration_count}")
            # In --cont mode, we use state and ignore -i option
            iterations_to_run = 1  # Just do one iteration at a time in continuation mode
        else:
            print(f"[MAIN] Starting new experiment with {requested_iterations} iterations")
            iterations_to_run = requested_iterations
        
        print(f"[MAIN] Concurrency values: {concurrency_values}")
        print(f"[MAIN] demon mode: {'ON' if demon else 'OFF'}")
        print(f"[MAIN] Current time: {CURRENT_TIMESTAMP} (UTC)")
        print(f"[MAIN] User: {CURRENT_USER}")
        
        if log_path:
            print(f"[MAIN] Log file: {log_path}")
        print(f"[MAIN] Started at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        
        ssh_connector = SSHConnector()
        client = ssh_connector.connect("connt1")

        # Create directories with experiment ID in path
        for c in concurrency_values:
            exp_dir = get_experiment_path(experiment_name, current_experiment_id, c)
            directory_cmd = f"sudo mkdir -p {exp_dir}"
            if client is None:
                subprocess.run(directory_cmd, shell=True, check=True)
            else:
                stdin, stdout, stderr = client.exec_command(directory_cmd)
                exit_code = stdout.channel.recv_exit_status()
                if exit_code != 0:
                    raise Exception(f"Failed to create directory for {exp_dir}")

        # Run experiments
        total_experiments = iterations_to_run
        current_experiment = 0
        
        for c in concurrency_values:
            for _ in range(iterations_to_run):
                current_experiment += 1
                
                # Get current iteration from state
                state = load_experiment_state()
                if state and state.get('name') == experiment_name and state.get('id') == current_experiment_id:
                    iteration_number = state.get('iteration', current_iteration_count)
                else:
                    iteration_number = current_iteration_count
                
                print(f"\nEXPERIMENT {current_experiment}/{total_experiments}: {experiment_name}_{current_experiment_id} - Concurrency {c} - Iteration {iteration_number}")
                
                check_result = check_function()
                if check_result != 2:
                    raise Exception("check_function failed")
                    
                if not pre_experimentation(experiment_name, c, iteration_number, current_experiment_id):
                    raise Exception("pre_experimentation failed")
                    
                if not experimentation(experiment_name, c, iteration_number, current_experiment_id):
                    raise Exception("experimentation failed")
                    
                # Always update state after each successful run
                if not post_experimentation(experiment_name, c, iteration_number, current_experiment_id, update_state=True):
                    raise Exception("post_experimentation failed")
                
                print(f"Experiment {current_experiment}/{total_experiments} completed successfully")
                
                # Get updated iteration from state for next loop
                state = load_experiment_state()
                if state:
                    current_iteration_count = state.get('iteration', current_iteration_count + 1)
                
                time.sleep(1)

        if client:
            client.close()
        
        # Get final state
        state = load_experiment_state()
        next_iteration = state.get('iteration', current_iteration_count) if state else current_iteration_count
        
        print(f"\nAll {total_experiments} experiments completed successfully!")
        print(f"Experiment ID: {current_experiment_id}")
        print(f"Next iteration: {next_iteration}")
        if log_path:
            print(f"Log file: {log_path}")
        
        # Close log file if in demon mode
        if log_file and demon:
            # Add footer to log file
            footer = (
                f"\n=== Experiment Complete ===\n"
                f"End Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"Experiment: {experiment_name}_{current_experiment_id}\n"
                f"Next Iteration: {next_iteration}\n"
                f"Status: SUCCESS\n"
                f"===========================\n"
            )
            log_file.write(footer)
            log_file.close()
            
            # Restore original stdout/stderr
            sys.stdout = original_stdout
            sys.stderr = original_stderr
            
            # Also print footer to stdout
            original_stdout.write(footer)
        
        # Print SUCCESS to appropriate output
        original_stdout.write("SUCCESS\n")
        original_stdout.flush()
        
    except Exception as e:
        print(f"ERROR: {str(e)}")
        
        # Close log file if in demon mode
        if log_file and demon:
            # Add error footer to log file
            footer = (
                f"\n=== Experiment Failed ===\n"
                f"End Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"Experiment: {experiment_name}_{current_experiment_id}\n"
                f"Error: {str(e)}\n"
                f"Status: FAILURE\n"
                f"========================\n"
            )
            log_file.write(footer)
            log_file.close()
            
            # Restore original stdout/stderr
            sys.stdout = original_stdout
            sys.stderr = original_stderr
            
            # Also print footer to stdout
            original_stdout.write(footer)
        
        # Print FAILURE to appropriate output
        original_stdout.write("FAILURE\n")
        original_stdout.flush()
        sys.exit(1)

if __name__ == "__main__":
    main()
