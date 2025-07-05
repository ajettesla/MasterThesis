#!/usr/bin/env python3

import os
import sys
import time
import threading
import signal
import datetime
import getpass
import logging

from config import (
    colored, RED, GREEN, YELLOW, BLUE, CYAN, MAGENTA, BOLD, RESET,
    progress_tracker, experiment_state, DEFAULT_MONITORING_TIME,
    generate_experiment_id, load_experiment_state, save_experiment_state,
    clear_experiment_state, get_experiment_path
)

from logging_utils import (
    get_current_hostname, setup_logging, cleanup_logging,
    monitor_log_file_watchdog, monitor_remote_log_file,
    SimpleProgressDisplay, configure_logging, check_and_clear_memory_usage
)

from ssh_utils import (
    SSHConnector, run_command_locally, run_command_remotely,
    run_command_with_timeout, pre_kill_conflicting_processes,
    force_kill_all_monitoring_processes, get_client_threads
)

def check_function():
    """Perform initial service checks and setup for the experiment"""
    logging.info(colored("[check] Step: Service Restart/Check/Flush", BOLD))
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
                    logging.error(colored(f"{tag} {service} restart failed! {err}", RED))
                    return 1
                ok, out, err = run_command_locally(cmd_check, tag)
            else:
                ok, _, err = run_command_remotely(client, cmd_restart, tag)
                if not ok:
                    logging.error(colored(f"{tag} {service} restart failed! {err}", RED))
                    if client: client.close()
                    return 2
                ok, out, err = run_command_remotely(client, cmd_check, tag)
            if not ok or "active" not in out:
                logging.error(colored(f"{tag} {service} is not active! Output: {out} Error: {err}", RED))
                if client: client.close()
                return 3
        if client: client.close()

    # Conntrackd service management
    logging.info(colored("[check] Step: Conntrackd Service Management", BOLD))
    for host in logger_host:
        client = ssh_connector.connect(host)
        tag = f"[{host} ssh]" if client else f"[{host} localhost]"

        cmd_check_status = "sudo systemctl is-active conntrackd"
        if client is None:
            status, output, err = run_command_locally(cmd_check_status, tag)
        else:
            status, output, err = run_command_remotely(client, cmd_check_status, tag)

        if status and "active" in output.strip():
            logging.info(colored(f"{tag} conntrackd service is already active.", GREEN))
        else:
            logging.warning(colored(f"{tag} conntrackd service is not active. Starting it...", YELLOW))

            cmd_start = "sudo systemctl start conntrackd"
            if client is None:
                start_status, start_output, start_err = run_command_locally(cmd_start, tag)
            else:
                start_status, start_output, start_err = run_command_remotely(client, cmd_start, tag)

            if not start_status:
                logging.error(colored(f"{tag} Failed to start conntrackd service!", RED))
                if client: client.close()
                return 9

            time.sleep(3)
            logging.info(colored(f"{tag} conntrackd service started successfully.", GREEN))

        if client: client.close()

    # Chrony service management (added to check time synchronization)
    logging.info(colored("[check] Step: Chrony Service Management", BOLD))
    for host in logger_hosts:
        client = ssh_connector.connect(host)
        tag = f"[{host} ssh]" if client else f"[{host} localhost]"

        cmd_check_status = "sudo systemctl is-active chrony"
        if client is None:
            status, output, err = run_command_locally(cmd_check_status, tag)
        else:
            status, output, err = run_command_remotely(client, cmd_check_status, tag)

        if status and "active" in output.strip():
            logging.info(colored(f"{tag} chrony service is already active.", GREEN))
        else:
            logging.warning(colored(f"{tag} chrony service is not active. Starting it...", YELLOW))

            cmd_start = "sudo systemctl start chrony"
            if client is None:
                start_status, start_output, start_err = run_command_locally(cmd_start, tag)
            else:
                start_status, start_output, start_err = run_command_remotely(client, cmd_start, tag)

            if not start_status:
                logging.error(colored(f"{tag} Failed to start chrony service!", RED))
                if client: client.close()
                return 10

            time.sleep(3)
            logging.info(colored(f"{tag} chrony service started successfully.", GREEN))

        if client: client.close()

    # Truncate logs
    logging.info(colored("[check] Step: Truncate Logs", BOLD))
    ssh_convsrc2 = ssh_connector.connect("convsrc2")
    for logfile in ["/var/log/conntrack.log"]:
        cmd_truncate = f"sudo truncate -s 0 {logfile}"
        if ssh_convsrc2 is None:
            ok, _, err = run_command_locally(cmd_truncate, "[convsrc2 localhost]")
        else:
            ok, _, err = run_command_remotely(ssh_convsrc2, cmd_truncate, "[convsrc2 ssh]")
        if not ok:
            logging.error(colored(f"Failed to truncate {logfile}: {err}", RED))
            if ssh_convsrc2: ssh_convsrc2.close()
            return 8
        else:
            logging.info(colored(f"Successfully truncated {logfile}", GREEN))
    if ssh_convsrc2: ssh_convsrc2.close()

    # Conntrack logger service management
    logging.info(colored("[check] Step: Conntrack Logger Service Management", BOLD))
    for host in logger_hosts:
        client = ssh_connector.connect(host)
        tag = f"[{host} ssh]" if client else f"[{host} localhost]"
        cmd_restart = "sudo systemctl restart conntrack_logger"
        cmd_check   = "sudo systemctl is-active conntrack_logger"
        cmd_flush   = "sudo conntrack -F"

        if client is None:
            ok, _, err = run_command_locally(cmd_restart, tag)
            if not ok:
                logging.error(colored(f"{tag} conntrack_logger restart failed! {err}", RED))
                return 4
            ok, out, err = run_command_locally(cmd_check, tag)
        else:
            ok, _, err = run_command_remotely(client, cmd_restart, tag)
            if not ok:
                logging.error(colored(f"{tag} conntrack_logger restart failed! {err}", RED))
                if client: client.close()
                return 5
            ok, out, err = run_command_remotely(client, cmd_check, tag)

        if not ok or "active" not in out:
            logging.error(colored(f"{tag} conntrack_logger is not active!", RED))
            if client: client.close()
            return 6

        logging.info(colored(f"{tag} conntrack_logger service is active.", GREEN))

        if client is None:
            ok, _, err = run_command_locally(cmd_flush, tag)
        else:
            ok, _, err = run_command_remotely(client, cmd_flush, tag)
        if not ok:
            logging.error(colored(f"{tag} conntrack flush failed! {err}", RED))
            if client: client.close()
            return 7

        if client: client.close()

    logging.info(colored("[check] All services active and conntrack tables flushed.", GREEN))

    # Log monitoring (removed PTP monitoring completely)
    logging.info(colored("[check] Step: Log Monitoring", BOLD))

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

    logging.info(colored("[check] Started log monitors.", CYAN))
    conntrack_monitor_thread.start()

    logging.info(colored("[check] Step: Start Client Threads", BOLD))
    client_threads = get_client_threads(10, 1, 1)
    for th in client_threads:
        th.start()

    for th in client_threads:
        th.join()

    logging.info(colored("[check] All client threads completed.", CYAN))

    conntrack_monitor_thread.join()

    conntrack_matches = monitor_results.get("conntrack-monitor", 0)
    total_matches = conntrack_matches

    logging.info(f"[check] Total matches: {total_matches}")

    if total_matches == 2:
        logging.info(colored("[check] MATCH found! Proceeding...", GREEN))
        return 2
    else:
        logging.info(colored("[check] Required matches not found!", RED))
        return 0

def graceful_shutdown():
    """Perform graceful shutdown operations"""
    logging.info("Starting graceful shutdown...")

    # Stop all monitoring threads
    for stop_event in experiment_state.monitoring_stop_events:
        if stop_event:
            stop_event.set()

    # Join threads with timeout
    for thread in experiment_state.monitoring_threads:
        if thread and thread.is_alive():
            thread.join(timeout=2)

    # Skip remote force-kill in signal handler (avoid SSH hangs)
    logging.info("Skipping remote force-kill in signal handler")

    # Cleanup experiment state
    if (experiment_state.current_experiment_name and experiment_state.current_experiment_id and 
        experiment_state.current_concurrency and experiment_state.current_iteration):
        cleanup_logging_scripts(
            experiment_state.current_experiment_name, 
            experiment_state.current_concurrency, 
            experiment_state.current_iteration, 
            experiment_state.current_experiment_id
        )

    # Close log file
    cleanup_logging()

    logging.info("Graceful shutdown completed")

def setup_signal_handlers():
    """Set up signal handlers for graceful shutdown"""
    def signal_handler(signum, frame):
        sig_name = signal.Signals(signum).name
        logging.info(f"Received signal {sig_name} ({signum})")

        if signum in (signal.SIGINT, signal.SIGTERM):
            logging.info("Initiating graceful shutdown...")
            graceful_shutdown()

            # Print status to original stdout
            if experiment_state.original_stdout:
                experiment_state.original_stdout.write("FAILURE - Terminated by signal\n")
                experiment_state.original_stdout.flush()

            sys.exit(128 + signum)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    if hasattr(signal, 'SIGHUP'):
        signal.signal(signal.SIGHUP, signal_handler)

def cleanup_logging_scripts(experiment_name, concurrency, iteration, experiment_id):
    """Cleanup logging scripts that were started for the experiment"""
    logging.info(f"[cleanup] Cleaning up logging scripts for {experiment_name}_{experiment_id}{concurrency}/{iteration}")
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
                        logging.info(f"[cleanup] {tag} Killed {program} (PID: {pid})")
                    else:
                        logging.info(f"[cleanup] {tag} Failed to kill {program} (PID: {pid})")
        if client: client.close()
    logging.info(f"[cleanup] Completed cleanup for {experiment_name}_{experiment_id}{concurrency}/{iteration}")


def verify_critical_processes_running(experiment_name, concurrency, iteration, experiment_id):
    """Verify that all critical processes are running for the experiment"""
    logging.info(f"[verify] Verifying critical processes for {experiment_name}_{experiment_id}{concurrency}/{iteration}")
    
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
                logging.error(colored(f"[verify] ERROR: {tag} Process {process} is not running!", RED))
                all_ok = False
            else:
                logging.info(colored(f"[verify] {tag} Process {process} is running.", GREEN))
        
        if client: client.close()
    
    if all_ok:
        logging.info(colored(f"[verify] All critical processes are running for {experiment_name}_{experiment_id}{concurrency}/{iteration}", GREEN))
    else:
        logging.error(colored(f"[verify] SOME CRITICAL PROCESSES ARE NOT RUNNING for {experiment_name}_{experiment_id}{concurrency}/{iteration}", RED))
    
    return all_ok

def check_csv_file_growth(filepath, host):
    """Check if the CSV file growth is less than 5 lines in the last interval"""
    ssh_connector = SSHConnector()
    client = ssh_connector.connect(host)
    tag = f"[{host} ssh]" if client else f"[{host} localhost]"
    
    # Get initial line count
    cmd_count = f"wc -l {filepath} 2>/dev/null | awk '{{print $1}}'"
    
    if client is None:
        status, output, stderr = run_command_locally(cmd_count, tag)
    else:
        status, output = run_command_with_timeout(client, cmd_count, 5, hostname=host)
    
    if not status or not output.strip():
        logging.debug(f"[monitor] {tag} Failed to get line count for {filepath}")
        if client: client.close()
        return False  # Not ready to close
    
    try:
        initial_count = int(output.strip())
    except (ValueError, TypeError):
        logging.debug(f"[monitor] {tag} Failed to parse line count: {output}")
        if client: client.close()
        return False  # Not ready to close
    
    logging.debug(f"[monitor] {tag} Initial line count for {filepath}: {initial_count}")
    
    time.sleep(10)
    
    # Get new line count
    if client is None:
        status, output, stderr = run_command_locally(cmd_count, tag)
    else:
        status, output = run_command_with_timeout(client, cmd_count, 5, hostname=host)
    
    if not status or not output.strip():
        logging.debug(f"[monitor] {tag} Failed to get new line count for {filepath}")
        if client: client.close()
        return False  # Not ready to close
    
    try:
        new_count = int(output.strip())
    except (ValueError, TypeError):
        logging.debug(f"[monitor] {tag} Failed to parse new line count: {output}")
        if client: client.close()
        return False  # Not ready to close
    
    if client: client.close()
    
    # Calculate delta
    delta = new_count - initial_count
    logging.info(f"[monitor] {tag} CSV file delta: {delta} lines")
    
    # If delta < 5, file growth is slow enough to consider condition met
    return delta < 5

def check_conntrack_entries_delta():
    """Check if the delta of conntrack entries is < 100 in the last interval"""
    ssh_connector = SSHConnector()
    
    # Initialize counts
    initial_counts = {}
    
    # Get initial counts
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
                initial_counts[host] = entries
                logging.debug(f"[monitor] {tag} Initial conntrack entries: {entries}")
            except (ValueError, TypeError):
                logging.debug(f"[monitor] {tag} Failed to parse conntrack count: {output}")
                initial_counts[host] = 0
        else:
            initial_counts[host] = 0
        
        if client: client.close()
    
    # Wait 30 seconds
    time.sleep(10)
    
    # Get new counts
    final_counts = {}
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
                final_counts[host] = entries
                logging.debug(f"[monitor] {tag} Final conntrack entries: {entries}")
            except (ValueError, TypeError):
                logging.debug(f"[monitor] {tag} Failed to parse conntrack count: {output}")
                final_counts[host] = initial_counts.get(host, 0)  # Use initial count if parsing fails
        else:
            final_counts[host] = initial_counts.get(host, 0)  # Use initial count if command fails
        
        if client: client.close()
    
    # Calculate deltas
    delta_connt1 = abs(final_counts.get("connt1", 0) - initial_counts.get("connt1", 0))
    delta_connt2 = abs(final_counts.get("connt2", 0) - initial_counts.get("connt2", 0))
    total_delta = delta_connt1 + delta_connt2
    
    logging.info(f"[monitor] Conntrack delta - connt1: {delta_connt1}, connt2: {delta_connt2}, total: {total_delta}")
    
    # Return True if the total delta is less than 100
    return total_delta < 100

def pre_experimentation(experiment_name, concurrency, iteration, experiment_id):
    """Prepare for experiment execution"""
    experiment_state.current_experiment_name = experiment_name
    experiment_state.current_experiment_id = experiment_id
    experiment_state.current_concurrency = concurrency
    experiment_state.current_iteration = iteration
    
    exp_path = get_experiment_path(experiment_name, experiment_id, concurrency, iteration)
    logging.info(f"[pre-exp] Running pre_experimentation for {exp_path}")
    
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
            logging.error(f"ERROR: {tag} conntrack flush failed! {err}")
            if client: client.close()
            return False
        if client: client.close()
    
    logging.info("[pre-exp] Conntrack tables flushed.")
    
    # Setup logging scripts
    CAlog = f"/tmp/exp/CA_{experiment_id}{experiment_name}{concurrency}.log"
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
            logging.error(f"ERROR: {tag} Failed to create directory {base_path}: {err}")
            if client: client.close()
            return False
        if client: client.close()
    
    # Define the logging script configurations with corrected path for conntrackAnalysis.py
    log_configs = [
        ("connt1", f"sudo ./start.sh -i {iteration} -l {base_path}/{iteration} -p conntrackd --iface enp3s0 -d", "start.sh", "/opt/MasterThesis/CMNpsutil/", True),
        ("convsrc2", f"sudo ./conntrackAnalysis.py -a connt1 -b connt2 -l /var/log/conntrack.log -o {base_path}/{iteration}_ca.csv -D -L {CAlog}", "conntrackAnalysis.py", "/opt/MasterThesis/connectiontrackingAnalysis/", True),
    ]
    
    logging.info("[pre-exp] Setting up logging scripts")
    
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
            logging.error(f"ERROR: [{host}] Script {program_file} not found in {working_dir}")
            if client: client.close()
            return False
        
        # Kill any existing processes
        programs_to_kill = ["start.sh", "cm_monitor.py", "n_monitor.py"] if program_file == "start.sh" else ["conntrackAnalysis.py"]
        pre_kill_conflicting_processes(client, host, programs_to_kill)

        # Run the command with verbose output
        logging.info(f"[{host}] Executing: cd {working_dir} && {cmd}")
        full_cmd = f"cd {working_dir} && {cmd}"
        if client is None:
            status, output, stderr = run_command_locally(full_cmd, tag)
            if not status:
                logging.error(f"ERROR: [{host}] Failed to start logging script: {stderr}")
                cleanup_logging_scripts(experiment_name, concurrency, iteration, experiment_id)
                if client: client.close()
                return False
            else:
                logging.info(f"[{host}] Command output: {output}")
        else:
            # Use a longer timeout for conntrackAnalysis.py because it might take longer to start
            timeout = 60 if program_file == "conntrackAnalysis.py" else 30
            status, output = run_command_with_timeout(client, full_cmd, timeout, hostname=host)
            if not status:
                logging.error(f"ERROR: [{host}] Failed to start logging script: {output}")
                cleanup_logging_scripts(experiment_name, concurrency, iteration, experiment_id)
                if client: client.close()
                return False
            else:
                logging.info(f"[{host}] Command output: {output}")

        # Give the processes time to start
        time.sleep(10)

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
                    logging.info(f"[{host}] Process search output: {alt_output}")
                else:
                    alt_status, alt_output = run_command_with_timeout(client, alt_search_cmd, 5, hostname=host)
                    logging.info(f"[{host}] Process search output: {alt_output}")
                
                logging.error(f"ERROR: [{host}] Could not detect PID for {program_file}")
                cleanup_logging_scripts(experiment_name, concurrency, iteration, experiment_id)
                if client: client.close()
                return False

            pids = output.strip().splitlines()
            logging.info(f"[{host}] {program_file} running with PID: {pids[0]}")

        if client: client.close()

    logging.info(f"[pre-exp] Setup completed for {experiment_name}_{experiment_id}{concurrency}/{iteration}")
    verify_critical_processes_running(experiment_name, concurrency, iteration, experiment_id)
    return True

def experimentation(experiment_name, concurrency, iteration, experiment_id):
    """Run the experiment with the given parameters"""
    logging.info(f"[exp] Running experimentation for {experiment_name}_{experiment_id}{concurrency}/{iteration}")
    
    base_path = get_experiment_path(experiment_name, experiment_id, concurrency)
    ca_csv_file = f"{base_path}/{iteration}_ca.csv"
    log_files_to_monitor = [
        {"filepath": ca_csv_file, "host": "convsrc2"},
        {"filepath": f"{base_path}/{iteration}_conntrackd_cm_monitor.csv", "host": "connt1"},
        {"filepath": f"{base_path}/{iteration}_conntrackd_n_monitor.csv", "host": "connt1"}
    ]

    logging.info("[exp] Starting log file monitoring")
    
    progress_tracker.file_stats.clear()
    progress_tracker.start_time = time.time()
    progress_tracker.last_full_display = 0
    
    monitor_results = {}
    experiment_state.monitoring_threads = []
    experiment_state.monitoring_stop_events = []
    
    # Set up silent monitoring (with print_output=False)
    for log_info in log_files_to_monitor:
        stop_event = threading.Event()
        experiment_state.monitoring_stop_events.append(stop_event)
        
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
        experiment_state.monitoring_threads.append(t)
        t.start()
    
    # Use the customized progress display that updates every 5 seconds
    progress_display_stop = threading.Event()
    progress_thread = SimpleProgressDisplay(progress_display_stop)
    progress_thread.start()
    
    logging.info("[exp] Starting client threads")
    client_threads = get_client_threads(500000, concurrency, 4)
    for th in client_threads:
        th.start()

    for th in client_threads:
        th.join()

    logging.info("[exp] Client threads completed, beginning monitoring period")
    
    # Start monitoring with continuous condition checks
    monitoring_time = DEFAULT_MONITORING_TIME  # Default maximum monitoring time
    start_time = time.time()
    check_interval = 30  # Check conditions every 30 seconds
    
    # Continue monitoring until max time reached or both conditions met
    while (time.time() - start_time) < monitoring_time:
        time_elapsed = time.time() - start_time
        time_remaining = monitoring_time - time_elapsed
        
        # Check condition 1: CSV file growth < 5 lines
        logging.info(f"[exp] Checking condition 1: CSV file growth < 5 lines (Time elapsed: {time_elapsed:.1f}s)")
        condition1_met = check_csv_file_growth(ca_csv_file, "convsrc2")
        
        if condition1_met:
            logging.info(colored("[exp] Condition 1 met: CSV file growth < 5 lines", YELLOW))
            
            # Check condition 2: Conntrack entries delta < 100
            logging.info(f"[exp] Checking condition 2: Conntrack entries delta < 100 (Time elapsed: {time_elapsed:.1f}s)")
            condition2_met = check_conntrack_entries_delta()
            
            if condition2_met:
                logging.info(colored("[exp] Condition 2 met: Conntrack entries delta < 100", YELLOW))
                logging.info(colored("[exp] Both conditions met! Ending monitoring early.", GREEN))
                # Both conditions met, end monitoring early
                break
            else:
                logging.info(colored("[exp] Condition 2 NOT met: Conntrack entries delta >= 100", YELLOW))
                if time_remaining > check_interval:
                    logging.info(f"[exp] Continuing monitoring for up to {time_remaining:.1f} more seconds...")
                    time.sleep(check_interval)
                else:
                    # Less than check_interval seconds remaining, just wait the rest
                    time.sleep(time_remaining)
        else:
            logging.info(colored("[exp] Condition 1 NOT met: CSV file still growing rapidly", YELLOW))
            if time_remaining > check_interval:
                logging.info(f"[exp] Continuing monitoring for up to {time_remaining:.1f} more seconds...")
                time.sleep(check_interval)
            else:
                # Less than check_interval seconds remaining, just wait the rest
                time.sleep(time_remaining)
    
    total_monitoring_time = time.time() - start_time
    logging.info(f"[exp] Monitoring completed after {total_monitoring_time:.1f} seconds")
    
    progress_display_stop.set()
    for stop_event in experiment_state.monitoring_stop_events:
        stop_event.set()
    
    progress_thread.join(timeout=10)
    for t in experiment_state.monitoring_threads:
        t.join(timeout=10)
    
    logging.info("[exp] Experimentation completed")
    
    experiment_state.monitoring_threads = []
    experiment_state.monitoring_stop_events = []
    
    return True

def post_experimentation(experiment_name, concurrency, iteration, experiment_id, update_state=True):
    """Clean up after experiment and update state if required"""
    logging.info(f"[post-exp] Cleanup for {experiment_name}_{experiment_id}{concurrency}/{iteration}")
    cleanup_logging_scripts(experiment_name, concurrency, iteration, experiment_id)
    
     # If requested, update the state file with the next iteration
    if update_state:
        next_iteration = iteration + 1
        state = load_experiment_state()
        if state and state.get('name') == experiment_name and state.get('id') == experiment_id:
            logging.info(f"[post-exp] Updating state file iteration to {next_iteration}")
            state['iteration'] = next_iteration
            # update timestamp and user dynamically
            state['timestamp'] = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            state['user'] = getpass.getuser()
            save_experiment_state(state)
        else:
            # no matching state, create fresh entry
            logging.warning("[post-exp] State file missing or mismatched -- creating fresh state")
            state = {
                'name': experiment_name,
                'id': experiment_id,
                'concurrency': ([concurrency] 
                                 if not isinstance(concurrency, list) 
                                 else concurrency),
                'iteration': next_iteration,
                'timestamp': datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                'user': getpass.getuser()
            }
            save_experiment_state(state)
 

    
    
    experiment_state.current_experiment_name = None
    experiment_state.current_experiment_id = None
    experiment_state.current_concurrency = None
    experiment_state.current_iteration = None
    
    logging.info("[post-exp] Cleanup completed")
    return True
