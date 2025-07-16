#!/usr/bin/env python3

import os
import sys
import time
import threading
import signal
import datetime
import getpass
import logging
import random

from config import (
    progress_tracker, experiment_state, DEFAULT_MONITORING_TIME,
    generate_experiment_id, load_experiment_state, save_experiment_state,
    clear_experiment_state, get_experiment_path, print_step, print_status,
    log_debug, log_info, log_warning, log_error, get_automation_mode
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
    automation_mode = get_automation_mode()
    
    # For quiet mode, define the 5 key statements we want to output
    if automation_mode and automation_mode.quiet_mode:
        print(" CHECK 1: Starting environment verification", flush=True)
        
    if automation_mode and automation_mode.super_mode:
        log_debug("[check] Step: Service Restart/Check/Flush - Starting environment verification (SUPER mode)")
    else:
        log_debug("[check] Step: Service Restart/Check/Flush - Starting environment verification")
    
    # Print step info based on mode
    if not automation_mode or not automation_mode.quiet_mode:
        print_step("CHECK", "STARTED", "Verifying environment services")
    else:
        # For quiet mode, add to summary collection
        if hasattr(automation_mode, 'results'):
            automation_mode.results.append("[INFO] Starting environment checks")
    
    service_hosts = {
        "convsrc8": ["tcp_server", "udp_server"],
        "convsrc5": ["tcp_server", "udp_server"]
    }
    logger_hosts = ["connt1", "connt2"]
    logger_host = ["connt1"]
    ssh_connector = SSHConnector()

    log_debug(f"[check] Target service hosts: {list(service_hosts.keys())}")
    log_debug(f"[check] Logger hosts: {logger_hosts}")

    # Service restart/check for tcp_server/udp_server
    for host, services in service_hosts.items():
        log_debug(f"[check] Processing host {host} with services {services}")
        client = ssh_connector.connect(host)
        tag = f"[{host} ssh]" if client else f"[{host} localhost]"
        
        for service in services:
            log_debug(f"[check] {tag} Processing service {service}")
            cmd_restart = f"sudo systemctl restart {service}"
            cmd_check   = f"sudo systemctl is-active {service}"
            
            if client is None:
                log_debug(f"[check] {tag} Running restart command locally: {cmd_restart}")
                ok, _, err = run_command_locally(cmd_restart, tag)
                if not ok:
                    log_error(f"{tag} {service} restart failed! {err}")
                    # Always show errors in all modes
                    print_step("CHECK", "FAILED", f"Service {service} restart failed on {host}")
                    return 1
                log_debug(f"[check] {tag} Running check command locally: {cmd_check}")
                ok, out, err = run_command_locally(cmd_check, tag)
            else:
                log_debug(f"[check] {tag} Running restart command remotely: {cmd_restart}")
                ok, _, err = run_command_remotely(client, cmd_restart, tag)
                if not ok:
                    log_error(f"{tag} {service} restart failed! {err}")
                    # Always show errors in all modes
                    print_step("CHECK", "FAILED", f"Service {service} restart failed on {host}")
                    if client: client.close()
                    return 2
                log_debug(f"[check] {tag} Running check command remotely: {cmd_check}")
                ok, out, err = run_command_remotely(client, cmd_check, tag)
            
            if not ok or "active" not in out:
                log_error(f"{tag} {service} is not active! Output: {out} Error: {err}")
                # Always show errors in all modes
                print_step("CHECK", "FAILED", f"Service {service} not active on {host}")
                if client: client.close()
                return 3
            
            # Print success for super mode and normal mode
            if automation_mode:
                if automation_mode.super_mode and not automation_mode.quiet_mode:
                    print(f"Service {service} on {host}: active", flush=True)
                elif not automation_mode.quiet_mode:
                    print(f"Service {service} on {host}: active")
            else:
                log_debug(f"[check] {tag} Service {service} is active")
        
        if client: client.close()
        log_debug(f"[check] Completed processing host {host}")

    # Conntrackd service management
    log_debug("[check] Step: Conntrackd Service Management")
    for host in logger_host:
        log_debug(f"[check] Processing conntrackd on host {host}")
        client = ssh_connector.connect(host)
        tag = f"[{host} ssh]" if client else f"[{host} localhost]"

        cmd_check_status = "sudo systemctl is-active conntrackd"
        if client is None:
            log_debug(f"[check] {tag} Checking conntrackd status locally")
            status, output, err = run_command_locally(cmd_check_status, tag)
        else:
            log_debug(f"[check] {tag} Checking conntrackd status remotely")
            status, output, err = run_command_remotely(client, cmd_check_status, tag)

        if status and "active" in output.strip():
            log_debug(f"{tag} conntrackd service is already active.")
            if automation_mode and automation_mode.super_mode and not automation_mode.quiet_mode:
                print(f"Conntrackd on {host}: already active", flush=True)
        else:
            log_warning(f"{tag} conntrackd service is not active. Starting it...")
            if not automation_mode or not automation_mode.quiet_mode:
                print_step("CHECK", "STARTING", f"Conntrackd service on {host}")
            log_debug(f"[check] {tag} Starting conntrackd service")

            cmd_start = "sudo systemctl start conntrackd"
            if client is None:
                start_status, start_output, start_err = run_command_locally(cmd_start, tag)
            else:
                start_status, start_output, start_err = run_command_remotely(client, cmd_start, tag)

            if not start_status:
                log_error(f"{tag} Failed to start conntrackd service!")
                # Always show errors in all modes
                print_step("CHECK", "FAILED", f"Could not start conntrackd on {host}")
                if client: client.close()
                return 9

            time.sleep(3)
            log_debug(f"{tag} conntrackd service started successfully.")
            if not automation_mode or not automation_mode.quiet_mode:
                print(f"Conntrackd on {host}: started", flush=True)

        if client: client.close()

    # Chrony service management
    log_debug("[check] Step: Chrony Service Management")
    for host in logger_hosts:
        log_debug(f"[check] Processing chrony on host {host}")
        client = ssh_connector.connect(host)
        tag = f"[{host} ssh]" if client else f"[{host} localhost]"

        cmd_check_status = "sudo systemctl is-active chrony"
        if client is None:
            log_debug(f"[check] {tag} Checking chrony status locally")
            status, output, err = run_command_locally(cmd_check_status, tag)
        else:
            log_debug(f"[check] {tag} Checking chrony status remotely")
            status, output, err = run_command_remotely(client, cmd_check_status, tag)

        if status and "active" in output.strip():
            log_debug(f"{tag} chrony service is already active.")
            if automation_mode and automation_mode.super_mode and not automation_mode.quiet_mode:
                print(f"Chrony on {host}: already active", flush=True)
        else:
            log_warning(f"{tag} chrony service is not active. Starting it...")
            if not automation_mode or not automation_mode.quiet_mode:
                print_step("CHECK", "STARTING", f"Chrony service on {host}")
            log_debug(f"[check] {tag} Starting chrony service")

            cmd_start = "sudo systemctl start chrony"
            if client is None:
                start_status, start_output, start_err = run_command_locally(cmd_start, tag)
            else:
                start_status, start_output, start_err = run_command_remotely(client, cmd_start, tag)

            if not start_status:
                log_error(f"{tag} Failed to start chrony service!")
                # Always show errors in all modes
                print_step("CHECK", "FAILED", f"Could not start chrony on {host}")
                if client: client.close()
                return 10

            time.sleep(3)
            log_debug(f"{tag} chrony service started successfully.")
            if not automation_mode or not automation_mode.quiet_mode:
                print(f"Chrony on {host}: started", flush=True)

        if client: client.close()

    # Truncate logs
    log_debug("[check] Step: Truncate Logs")
    ssh_convsrc2 = ssh_connector.connect("convsrc2")
    for logfile in ["/var/log/conntrack.log"]:
        log_debug(f"[check] Truncating log file {logfile}")
        cmd_truncate = f"sudo truncate -s 0 {logfile}"
        if ssh_convsrc2 is None:
            log_debug(f"[check] Truncating {logfile} locally")
            ok, _, err = run_command_locally(cmd_truncate, "[convsrc2 localhost]")
        else:
            log_debug(f"[check] Truncating {logfile} remotely")
            ok, _, err = run_command_remotely(ssh_convsrc2, cmd_truncate, "[convsrc2 ssh]")
        if not ok:
            log_error(f"Failed to truncate {logfile}: {err}")
            # Always show errors in all modes
            print_step("CHECK", "FAILED", f"Could not truncate {logfile}")
            if ssh_convsrc2: ssh_convsrc2.close()
            return 8
        else:
            log_debug(f"Successfully truncated {logfile}")
            if automation_mode and automation_mode.super_mode and not automation_mode.quiet_mode:
                print(f"Log truncated: {logfile}", flush=True)

    # Conntrack logger service management
    # Print status in super and normal modes
    if not automation_mode or not automation_mode.quiet_mode:
        print_step("CHECK", "CHECKING", "Conntrack logger service")
    log_debug("[check] Step: Conntrack Logger Service Management")
    
    for host in logger_hosts:
        log_debug(f"[check] Processing conntrack_logger on host {host}")
        client = ssh_connector.connect(host)
        tag = f"[{host} ssh]" if client else f"[{host} localhost]"
        cmd_restart = "sudo systemctl restart conntrack_logger"
        cmd_check   = "sudo systemctl is-active conntrack_logger"
        cmd_flush   = "sudo conntrack -F"

        if client is None:
            log_debug(f"[check] {tag} Restarting conntrack_logger locally")
            ok, _, err = run_command_locally(cmd_restart, tag)
            if not ok:
                log_error(f"{tag} conntrack_logger restart failed! {err}")
                # Always show errors in all modes
                print_step("CHECK", "FAILED", f"Could not restart conntrack_logger on {host}")
                return 4
            log_debug(f"[check] {tag} Checking conntrack_logger status locally")
            ok, out, err = run_command_locally(cmd_check, tag)
        else:
            log_debug(f"[check] {tag} Restarting conntrack_logger remotely")
            ok, _, err = run_command_remotely(client, cmd_restart, tag)
            if not ok:
                log_error(f"{tag} conntrack_logger restart failed! {err}")
                # Always show errors in all modes
                print_step("CHECK", "FAILED", f"Could not restart conntrack_logger on {host}")
                if client: client.close()
                return 5
            log_debug(f"[check] {tag} Checking conntrack_logger status remotely")
            ok, out, err = run_command_remotely(client, cmd_check, tag)

        if not ok or "active" not in out:
            log_error(f"{tag} conntrack_logger is not active!")
            # Always show errors in all modes
            print_step("CHECK", "FAILED", f"Conntrack_logger not active on {host}")
            if client: client.close()
            return 6

        log_debug(f"{tag} conntrack_logger service is active.")
        if automation_mode and automation_mode.super_mode and not automation_mode.quiet_mode:
            print(f"Conntrack logger on {host}: active", flush=True)

        # Print status in super and normal modes
        if not automation_mode or not automation_mode.quiet_mode:
            print_step("CHECK", "FLUSHING", f"Conntrack tables on {host}")
        log_debug(f"[check] {tag} Flushing conntrack tables")
        
        if client is None:
            ok, _, err = run_command_locally(cmd_flush, tag)
        else:
            ok, _, err = run_command_remotely(client, cmd_flush, tag)
        if not ok:
            log_error(f"{tag} conntrack flush failed! {err}")
            # Always show errors in all modes
            print_step("CHECK", "FAILED", f"Could not flush conntrack tables on {host}")
            if client: client.close()
            return 7

        if client: client.close()
        if automation_mode and automation_mode.super_mode and not automation_mode.quiet_mode:
            print(f"Conntrack tables on {host}: flushed", flush=True)

    log_debug("[check] All services active and conntrack tables flushed.")

    # Print status in super and normal modes
    if not automation_mode or not automation_mode.quiet_mode:
        print_step("CHECK", "", "Connection logs")
    log_debug("[check] Step: Log Monitoring")

    conntrack_stop_event = threading.Event()
    monitor_results = {}

    log_debug("[check] Starting conntrack monitor thread")
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

    log_debug("[check] Started log monitors.")
    conntrack_monitor_thread.start()

    # Print status in super and normal modes
    if not automation_mode or not automation_mode.quiet_mode:
        print_step("CHECK", "STARTING", "Test client threads")
    log_debug("[check] Step: Start Client Threads")
    
    client_threads = get_client_threads(10, 1, 1)
    log_debug(f"[check] Created {len(client_threads)} client threads")
    for th in client_threads:
        th.start()

    log_debug("[check] Waiting for client threads to complete")
    for th in client_threads:
        th.join()

    log_debug("[check] All client threads completed.")
    conntrack_monitor_thread.join()

    conntrack_matches = monitor_results.get("conntrack-monitor", 0)
    total_matches = conntrack_matches

    log_debug(f"[check] Monitor results: {monitor_results}")
    log_info(f"[check] Total matches: {total_matches}")

    if total_matches == 2:
        log_info("[check] MATCH found! Proceeding...")
        # Show success in all modes
        if automation_mode and automation_mode.quiet_mode:
            # For quiet mode, add result to the summary collection
            if hasattr(automation_mode, 'results'):
                automation_mode.results.append("[INFO] Environment check passed - All services and connectivity verified")
        else:
            # For normal and super mode, print to stdout
            print_step("CHECK", "PASSED", "All services and connectivity verified")
        
        # Fifth checkpoint for quiet mode
        if automation_mode and automation_mode.quiet_mode:
            print(" CHECK5: Validating connections - CHECK PASSED", flush=True)
        
        return 2
    else:
        log_info("[check] Required matches not found!")
        # Show failure in all modes
        print_step("CHECK", "FAILED", f"Only {total_matches}/2 connections detected")
        return 0

def graceful_shutdown():
    """Perform graceful shutdown operations"""
    automation_mode = get_automation_mode()
    
    if not automation_mode or not automation_mode.quiet_mode:
        print_status("SHUTDOWN: Starting graceful shutdown procedure...")
    log_info("Starting graceful shutdown...")

    # Stop all monitoring threads
    for stop_event in experiment_state.monitoring_stop_events:
        if stop_event:
            stop_event.set()

    # Join threads with timeout
    for thread in experiment_state.monitoring_threads:
        if thread and thread.is_alive():
            thread.join(timeout=2)

    # Skip remote force-kill in signal handler (avoid SSH hangs)
    log_info("Skipping remote force-kill in signal handler")

    # Cleanup experiment state
    if (experiment_state.current_experiment_name and experiment_state.current_experiment_id and 
        experiment_state.current_concurrency and experiment_state.current_iteration):
        if not automation_mode or not automation_mode.quiet_mode:
            print_status("SHUTDOWN: Cleaning up experiment processes...")
        cleanup_logging_scripts(
            experiment_state.current_experiment_name, 
            experiment_state.current_concurrency, 
            experiment_state.current_iteration, 
            experiment_state.current_experiment_id
        )

    # Close log file
    cleanup_logging()

    log_info("Graceful shutdown completed")
    if not automation_mode or not automation_mode.quiet_mode:
        print_status("SHUTDOWN: Graceful shutdown completed")

def setup_signal_handlers():
    """Set up signal handlers for graceful shutdown"""
    def signal_handler(signum, frame):
        automation_mode = get_automation_mode()
        
        sig_name = signal.Signals(signum).name
        logging.info(f"Received signal {sig_name} ({signum})")
        
        # Print signal info in super and normal modes
        if not automation_mode or not automation_mode.quiet_mode:
            print_status(f"SIGNAL: Received {sig_name} ({signum})")

        if signum in (signal.SIGINT, signal.SIGTERM):
            if not automation_mode or not automation_mode.quiet_mode:
                print_status("SHUTDOWN: Initiating graceful shutdown...")
            graceful_shutdown()

            # Print status to stdout in all modes (important termination info)
            print_status("FAILURE - Terminated by signal")

            sys.exit(128 + signum)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    if hasattr(signal, 'SIGHUP'):
        signal.signal(signal.SIGHUP, signal_handler)

def cleanup_logging_scripts(experiment_name, concurrency, iteration, experiment_id):
    """Cleanup logging scripts that were started for the experiment"""
    automation_mode = get_automation_mode()
    
    # Print status in super and normal modes
    if not automation_mode or not automation_mode.quiet_mode:
        print_step("CLEANUP", "STARTED", "Terminating logging scripts")
    log_info(f"[cleanup] Cleaning up logging scripts for {experiment_name}_{experiment_id}{concurrency}/{iteration}")
    
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
                # Print kill info in super and normal modes
                if not automation_mode or not automation_mode.quiet_mode:
                    print_step("CLEANUP", "KILLING", f"{program} on {host} (PIDs: {', '.join(pids)})")
                for pid in pids:
                    cmd_kill = f"sudo kill -9 {pid}"
                    if client is None:
                        kill_status, _, kill_err = run_command_locally(cmd_kill, tag)
                    else:
                        kill_status, _ = run_command_with_timeout(client, cmd_kill, 5, hostname=host)
                    if kill_status:
                        logging.info(f"[cleanup] {tag} Killed {program} (PID: {pid})")
                        if automation_mode and automation_mode.super_mode:
                            print(f"Killed {program} on {host} (PID: {pid})", flush=True)
                    else:
                        logging.info(f"[cleanup] {tag} Failed to kill {program} (PID: {pid})")
                        if automation_mode and automation_mode.super_mode:
                            print(f"Failed to kill {program} on {host} (PID: {pid}) (failed)", flush=True)
        if client: client.close()
        
    logging.info(f"[cleanup] Completed cleanup for {experiment_name}_{experiment_id}{concurrency}/{iteration}")
    
    # Print completion in super and normal modes
    if not automation_mode or not automation_mode.quiet_mode:
        print_step("CLEANUP", "COMPLETE", "All logging scripts terminated")


def verify_critical_processes_running(experiment_name, concurrency, iteration, experiment_id):
    """Verify that all critical processes are running for the experiment"""
    automation_mode = get_automation_mode()
    
    # Print status in super and normal modes
    if not automation_mode or not automation_mode.quiet_mode:
        print_step("VERIFY", "STARTED", "Checking critical processes")
    log_info(f"[verify] Verifying critical processes for {experiment_name}_{experiment_id}{concurrency}/{iteration}")
    
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
                logging.error(f"[verify] ERROR: {tag} Process {process} is not running!")
                # Show warnings in all modes
                print_step("VERIFY", "WARNING", f"Process {process} not running on {host}")
                all_ok = False
            else:
                logging.info(f"[verify] {tag} Process {process} is running.")
                # Show detailed success in super mode only
                if automation_mode and automation_mode.super_mode and not automation_mode.quiet_mode:
                    print(f"Process {process} on {host} is running", flush=True)

        if client: client.close()
    
    if all_ok:
        logging.info(f"[verify] All critical processes are running for {experiment_name}_{experiment_id}{concurrency}/{iteration}")
        # Print success in super and normal modes
        if not automation_mode or not automation_mode.quiet_mode:
            print_step("VERIFY", "PASSED", "All critical processes running")
    else:
        logging.error(f"[verify] SOME CRITICAL PROCESSES ARE NOT RUNNING for {experiment_name}_{experiment_id}{concurrency}/{iteration}")
        # Show warning in all modes
        print_step("VERIFY", "WARNING", "Some critical processes not running")
    
    return all_ok

def experimentation(experiment_name, concurrency, iteration, experiment_id):
    automation_mode = get_automation_mode()
    
    # First print for quiet mode
    if automation_mode and automation_mode.quiet_mode:
        print("EXPERIMENT 1: Starting experimentation", flush=True)
        print(f"CONFIG: experiment={experiment_name}, concurrency={concurrency}, iteration={iteration}, id={experiment_id}", flush=True)
    
    # Print step info in super and normal modes
    if not automation_mode or not automation_mode.quiet_mode:
        print_step("EXPERIMENT", "STARTED", f"Running experiment with concurrency={concurrency}")
    log_info(f"[exp] Running experimentation for {experiment_name}_{experiment_id}{concurrency}/{iteration}")
    
    try:
        base_path = get_experiment_path(experiment_name, experiment_id, concurrency)
        ca_csv_file = f"{base_path}/{iteration}_ca.csv"
        log_files_to_monitor = [
            {"filepath": ca_csv_file, "host": "convsrc2"},
            {"filepath": f"{base_path}/{iteration}_conntrackd_cm_monitor.csv", "host": "connt1"},
            {"filepath": f"{base_path}/{iteration}_conntrackd_n_monitor.csv", "host": "connt1"}
        ]

        log_info("[exp] Starting log file monitoring")
        
        # Setup and file monitoring
        try:
            progress_tracker.file_stats.clear()
            progress_tracker.start_time = time.time()
            progress_tracker.last_full_display = 0
            
            monitor_results = {}
            experiment_state.monitoring_threads = []
            experiment_state.monitoring_stop_events = []
            
            # Start monitoring log files
            for entry in log_files_to_monitor:
                stop_event = threading.Event()
                experiment_state.monitoring_stop_events.append(stop_event)
                
                t = threading.Thread(
                    target=monitor_remote_log_file,
                    kwargs={
                        "filepath": entry["filepath"],
                        "host": entry["host"],
                        "keyword_expr": "",
                        "timeout": None,
                        "print_output": False,
                        "result_dict": monitor_results,
                        "stop_event": stop_event,
                    },
                    name=f"ExpMonitor-{entry['host']}-{os.path.basename(entry['filepath'])}"
                )
                experiment_state.monitoring_threads.append(t)
                t.start()
        except Exception as e:
            log_error(f"[exp] Error setting up log monitoring: {str(e)}")
            print_step("EXPERIMENT", "FAILED", f"Error setting up log monitoring: {str(e)}")
            return False
        
        # Setup progress display
        try:
            progress_display_stop = threading.Event()
            progress_thread = SimpleProgressDisplay(progress_display_stop)
            progress_thread.csv_check_file = ca_csv_file
            progress_thread.csv_check_host = "convsrc2"
            progress_thread.start()
        except Exception as e:
            log_error(f"[exp] Error setting up progress display: {str(e)}")
            print_step("EXPERIMENT", "FAILED", f"Error setting up progress display: {str(e)}")
            # Stop any monitoring threads already started
            for stop_event in experiment_state.monitoring_stop_events:
                stop_event.set()
            return False
        
        # Launch client threads
        try:
            # Print launching info in super and normal modes
            if not automation_mode or not automation_mode.quiet_mode:
                print_step("EXPERIMENT", "LAUNCHING", f"Client threads with concurrency={concurrency}")
            log_info("[exp] Starting client threads")
            
            client_threads = get_client_threads(500000, concurrency, 4)
            for th in client_threads:
                th.start()

            for th in client_threads:
                th.join()
        except Exception as e:
            log_error(f"[exp] Error launching client threads: {str(e)}")
            print_step("EXPERIMENT", "FAILED", f"Error launching client threads: {str(e)}")
            # Stop progress display and monitoring threads
            progress_display_stop.set()
            for stop_event in experiment_state.monitoring_stop_events:
                stop_event.set()
            return False

        log_info("[exp] Client threads completed, beginning monitoring period")
        
        # Print info in super and normal modes
        if not automation_mode or not automation_mode.quiet_mode:
            print("Client threads completed, monitoring connections...", flush=True)
        
        # Monitor connections and conditions
        try:
            monitoring_time = DEFAULT_MONITORING_TIME
            start_time = time.time()
            check_interval = 5  # Check conditions every 5 seconds
            check_counter = 0   # Counter for reducing print frequency
            print_probability = 0.2  # Only print 20% of the time for "not met" conditions
            
            while (time.time() - start_time) < monitoring_time:
                time_elapsed = time.time() - start_time
                time_remaining = monitoring_time - time_elapsed
                check_counter += 1
                
                # Determine if we should print status this time
                should_print_status = (random.random() < print_probability)
                
                # Check conditions - catch any exceptions in the monitoring checks
                try:
                    log_debug(f"[exp] Checking condition 1: CSV file growth < 5 lines (Time elapsed: {time_elapsed:.1f}s)")
                    condition1_met = progress_thread.check_csv_growth_condition(ca_csv_file, "convsrc2")
                    
                    if condition1_met:
                        log_info("[exp] Condition 1 met: CSV file growth < 5 lines")
                        # Always show when condition 1 is met (significant event)
                        if not automation_mode or not automation_mode.quiet_mode:
                            print_step("EXPERIMENT", "CONDITION 1 MET", "CSV file growth stabilized")
                        
                        # Check conntrack condition using the progress display
                        log_debug(f"[exp] Checking condition 2: Conntrack entries delta < 100 (Time elapsed: {time_elapsed:.1f}s)")
                        condition2_met = progress_thread.check_conntrack_delta_condition()
                        
                        if condition2_met:
                            log_info("[exp] Condition 2 met: Conntrack entries delta < 100")
                            log_info("[exp] Both conditions met! Ending monitoring early.")
                            # Always show when both conditions are met (significant event)
                            if not automation_mode or not automation_mode.quiet_mode:
                                print_step("EXPERIMENT", "STABILIZED", "Both conditions met - ending monitoring early")
                            break
                        else:
                            log_info("[exp] Condition 2 NOT met: Conntrack entries delta >= 100")
                            # Only show condition 2 not met occasionally
                            if should_print_status and automation_mode and automation_mode.super_mode:
                                print("Condition 2 NOT met: Conntrack entries delta still too high", flush=True)
                    else:
                        log_info("[exp] Condition 1 NOT met: CSV file still growing rapidly")
                        # Only show condition 1 not met occasionally
                        if should_print_status and automation_mode and automation_mode.super_mode:
                            print("Condition 1 NOT met: CSV file still growing rapidly", flush=True)
                except Exception as e:
                    log_error(f"[exp] Error checking conditions: {str(e)}")
                    # Continue monitoring even if condition check fails
                
                # Wait before next check
                if time_remaining > check_interval:
                    time.sleep(check_interval)
                else:
                    time.sleep(time_remaining)
        except Exception as e:
            log_error(f"[exp] Error during monitoring: {str(e)}")
            print_step("EXPERIMENT", "FAILED", f"Error during monitoring: {str(e)}")
            # Still try to stop threads gracefully
            try:
                progress_display_stop.set()
                for stop_event in experiment_state.monitoring_stop_events:
                    stop_event.set()
            except:
                pass
            return False
        
        # Monitoring complete - cleanup
        try:
            total_monitoring_time = time.time() - start_time
            log_info(f"[exp] Monitoring completed after {total_monitoring_time:.1f} seconds")
            
            # Show completion info in super and normal modes
            if not automation_mode or not automation_mode.quiet_mode:
                print_step("EXPERIMENT", "COMPLETED", f"Total monitoring time: {total_monitoring_time:.1f} seconds")
            
            # Stop all monitoring threads
            progress_display_stop.set()
            for stop_event in experiment_state.monitoring_stop_events:
                stop_event.set()
            
            # Wait for threads to complete
            progress_thread.join(timeout=10)
            for t in experiment_state.monitoring_threads:
                t.join(timeout=10)
        except Exception as e:
            log_error(f"[exp] Error stopping monitoring threads: {str(e)}")
            # Continue - this is just cleanup so we can still consider the experiment successful

        log_info("[exp] Experimentation completed")
        
        experiment_state.monitoring_threads = []
        experiment_state.monitoring_stop_events = []
        
        # Fifth print for quiet mode
        if automation_mode and automation_mode.quiet_mode:
            print("EXPERIMENT 5: Experimentation completed successfully", flush=True)
            print(f"DURATION: {total_monitoring_time:.1f} seconds, Total CSV lines: {sum(monitor_results.values() if monitor_results else [0])}", flush=True)
        
        return True

    except Exception as e:
        log_error(f"[exp] Critical error during experimentation: {str(e)}")
        print_step("EXPERIMENT", "FAILED", f"Critical error: {str(e)}")
        return False

def post_experimentation(experiment_name, concurrency, iteration, experiment_id, update_state=True):
    """Clean up after experiment with improved error handling"""
    automation_mode = get_automation_mode()
    
    # First print for quiet mode
    if automation_mode and automation_mode.quiet_mode:
        print("POST-EXPERIMENT 1: Starting cleanup process", flush=True)
        print(f"CLEANUP: experiment={experiment_name}, concurrency={concurrency}, iteration={iteration}, id={experiment_id}", flush=True)
    
    log_info(f"[post-exp] Cleanup for {experiment_name}_{experiment_id}{concurrency}/{iteration}")
    
    try:
        # Define base_path for output directory
        base_path = get_experiment_path(experiment_name, experiment_id, concurrency)
        
        # Print cleaning info in super and normal modes
        if not automation_mode or not automation_mode.quiet_mode:
            print_step("POST-EXPERIMENT", "CLEANING", "Terminating logging scripts")
        
        # Try cleanup operations with additional error handling
        try:
            cleanup_logging_scripts(experiment_name, concurrency, iteration, experiment_id)
        except Exception as e:
            log_error(f"[post-exp] Error during cleanup: {str(e)}")
            print_step("POST-EXPERIMENT", "WARNING", f"Error during cleanup: {str(e)}")
            # Continue with other operations despite cleanup error
        
        # Update state file if requested
        if update_state:
            try:
                next_iteration = iteration + 1
                
                # Third print for quiet mode
                if automation_mode and automation_mode.quiet_mode:
                    print("POST-EXPERIMENT 3: Updating state files", flush=True)
                    from config import STATE_FILE
                    print(f"STATE FILE: {STATE_FILE} updating iteration to {next_iteration}", flush=True)
                
                # Print updating info in super and normal modes
                if not automation_mode or not automation_mode.quiet_mode:
                    print_step("POST-EXPERIMENT", "UPDATING", f"State file to iteration {next_iteration}")
                
                state = load_experiment_state()
                if state and state.get('name') == experiment_name and state.get('id') == experiment_id:
                    log_info(f"[post-exp] Updating state file iteration to {next_iteration}")
                    state['iteration'] = next_iteration
                    state['timestamp'] = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                    state['user'] = getpass.getuser()
                    
                    if not save_experiment_state(state):
                        log_error("[post-exp] Failed to save state file")
                        print_step("POST-EXPERIMENT", "WARNING", "Failed to save state file")
                    else:
                        # Show success in super mode only
                        if automation_mode and automation_mode.super_mode and not automation_mode.quiet_mode:
                            print(f"State file updated: iteration set to {next_iteration}", flush=True)
                else:
                    log_warning("[post-exp] State file missing or mismatched -- creating fresh state")
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
                    
                    if not save_experiment_state(state):
                        log_error("[post-exp] Failed to save new state file")
                        print_step("POST-EXPERIMENT", "WARNING", "Failed to save new state file")
                    else:
                        # Show warning in super mode only
                        if automation_mode and automation_mode.super_mode and not automation_mode.quiet_mode:
                            print(f"Created new state file: iteration set to {next_iteration}", flush=True)
            except Exception as e:
                log_error(f"[post-exp] Error updating state file: {str(e)}")
                print_step("POST-EXPERIMENT", "WARNING", f"State file error: {str(e)}")
                # Continue despite state file errors
        
        log_info("[post-exp] Cleanup completed")
        
        # Print completion in super and normal modes
        if not automation_mode or not automation_mode.quiet_mode:
            print_step("POST-EXPERIMENT", "COMPLETE", "All cleanup tasks finished")
        
        # Fifth print for quiet mode
        if automation_mode and automation_mode.quiet_mode:
            print("POST-EXPERIMENT 5: All cleanup tasks completed", flush=True)
            print(f"RESULT DIR: {base_path}", flush=True)
        
        return True
    
    except Exception as e:
        log_error(f"[post-exp] Critical error during post-experimentation: {str(e)}")
        print_step("POST-EXPERIMENT", "FAILED", f"Critical error: {str(e)}")
        return False

def pre_experimentation(experiment_name, concurrency, iteration, experiment_id):
    """Set up environment for an experiment by starting monitoring scripts."""
    automation_mode = get_automation_mode()
    
    # First print for quiet mode
    if automation_mode and automation_mode.quiet_mode:
        print("PRE-EXPERIMENT 1: Setting up environment", flush=True)
        print(f"ENV CONFIG: experiment={experiment_name}, concurrency={concurrency}, iteration={iteration}", flush=True)
    
    # Print step info based on mode
    if not automation_mode or not automation_mode.quiet_mode:
        print_step("PRE-EXPERIMENT", "STARTED", f"Setting up experiment: {experiment_name}")
    
    log_info(f"[pre-exp] Setting up environment for {experiment_name} with concurrency={concurrency}, iteration={iteration}")
    
    try:
        # Store experiment state for error handling
        experiment_state.current_experiment_name = experiment_name
        experiment_state.current_experiment_id = experiment_id
        experiment_state.current_concurrency = concurrency
        experiment_state.current_iteration = iteration
        
        # Flush conntrack tables on logger hosts
        if not automation_mode or not automation_mode.quiet_mode:
            print_step("PRE-EXPERIMENT", "FLUSHING", "Conntrack tables")
        
        logger_hosts = ["connt1", "connt2"]
        ssh_connector = SSHConnector()
        
        for host in logger_hosts:
            try:
                client = ssh_connector.connect(host)
                tag = f"[{host} ssh]" if client else f"[{host} localhost]"
                cmd_flush = "sudo conntrack -F"
                if client is None:
                    ok, _, err = run_command_locally(cmd_flush, tag)
                else:
                    ok, _, err = run_command_remotely(client, cmd_flush, tag)
                if not ok:
                    log_error(f"{tag} conntrack flush failed! {err}")
                    # Always show errors in all modes
                    print_step("PRE-EXPERIMENT", "FAILED", f"Could not flush conntrack tables on {host}")
                    if client: client.close()
                    return False
                if client: client.close()
            except Exception as e:
                log_error(f"[pre-exp] Error connecting to {host} or flushing conntrack tables: {str(e)}")
                print_step("PRE-EXPERIMENT", "FAILED", f"Error with {host}: {str(e)}")
                return False
        
        # Create directories for log files
        try:
            CAlog = f"/tmp/exp/CA_{experiment_id}_i{iteration}_c{concurrency}.log"
            base_path = get_experiment_path(experiment_name, experiment_id, concurrency)
            
            # Second print for quiet mode
            if automation_mode and automation_mode.quiet_mode:
                print("PRE-EXPERIMENT 2: Creating log directories", flush=True)
                print(f"LOG PATHS: {base_path}, CA_log={CAlog}", flush=True)
            
            if not automation_mode or not automation_mode.quiet_mode:
                print_step("PRE-EXPERIMENT", "CREATING", "Log directories")
            
            for host in ["connt1", "convsrc2"]:
                client = ssh_connector.connect(host)
                tag = f"[{host} ssh]" if client else f"[{host} localhost]"
                cmd_mkdir = f"sudo mkdir -p {base_path}"
                if client is None:
                    ok, _, err = run_command_locally(cmd_mkdir, tag)
                else:
                    ok, _, err = run_command_remotely(client, cmd_mkdir, tag)
                if not ok:
                    log_error(f"{tag} Failed to create directory {base_path}: {err}")
                    # Always show errors in all modes
                    print_step("PRE-EXPERIMENT", "FAILED", f"Could not create directory {base_path} on {host}")
                    if client: client.close()
                    return False
                if client: client.close()
        except Exception as e:
            log_error(f"[pre-exp] Error creating directories: {str(e)}")
            print_step("PRE-EXPERIMENT", "FAILED", f"Error creating directories: {str(e)}")
            return False
        
        # Start monitoring scripts
        try:
            # Fourth print for quiet mode
            if automation_mode and automation_mode.quiet_mode:
                print("PRE-EXPERIMENT 4: Starting monitoring scripts", flush=True)
                print(f"MONITOR SCRIPTS: connt1 (start.sh, cm_monitor.py, n_monitor.py), convsrc2 (conntrackAnalysis.py)", flush=True)
            
            # Configure and start logging scripts
            log_configs = [
                ("connt1", f"sudo ./start.sh -i 1 -l {base_path}/{iteration} -p conntrackd --iface enp3s0 -d", "start.sh", "/opt/MasterThesis/CMNpsutil/", True),
                ("connt2", f"sudo ./start.sh -i 1 -l {base_path}/{iteration} -p conntrackd --iface enp1s0 -d", "start.sh", "/opt/MasterThesis/CMNpsutil/", True),
                ("convsrc2", f"sudo ./conntrackAnalysis.py -a connt1 -b connt2 -l /var/log/conntrack.log -o {base_path}/{iteration}_ca.csv -D -L {CAlog}", "conntrackAnalysis.py", "/opt/MasterThesis/connectiontrackingAnalysis/", True)
            ]
            
            if not automation_mode or not automation_mode.quiet_mode:
                print_step("PRE-EXPERIMENT", "STARTING", "Monitoring scripts")
            log_info("[pre-exp] Setting up logging scripts")
            
            for host, cmd, program_file, working_dir, is_daemon in log_configs:
                client = ssh_connector.connect(host)
                tag = f"[{host} ssh]" if client else f"[{host} localhost]"

                # Verify script exists
                check_cmd = f"cd {working_dir} && ls -la ./{program_file}"
                if client is None:
                    check_status, check_output, check_stderr = run_command_locally(check_cmd, tag)
                else:
                    check_status, check_output = run_command_with_timeout(client, check_cmd, 5, hostname=host)
                
                if not check_status:
                    log_error(f"[{host}] Script {program_file} not found in {working_dir}")
                    # Always show errors in all modes
                    print_step("PRE-EXPERIMENT", "FAILED", f"Script {program_file} not found on {host}")
                    if client: client.close()
                    return False
                
                # Kill any existing instances of the program
                programs_to_kill = ["start.sh", "cm_monitor.py", "n_monitor.py"] if program_file == "start.sh" else ["conntrackAnalysis.py"]
                pre_kill_conflicting_processes(client, host, programs_to_kill)

                # Start the monitoring program
                log_info(f"[{host}] Executing: cd {working_dir} && {cmd}")
                full_cmd = f"cd {working_dir} && {cmd}"
                if client is None:
                    status, output, stderr = run_command_locally(full_cmd, tag)
                    if not status:
                        log_error(f"[{host}] Failed to start logging script: {stderr}")
                        # Always show errors in all modes
                        print_step("PRE-EXPERIMENT", "FAILED", f"Could not start {program_file} on {host}")
                        cleanup_logging_scripts(experiment_name, concurrency, iteration, experiment_id)
                        if client: client.close()
                        return False
                    else:
                        log_info(f"[{host}] Command output: {output}")
                else:
                    timeout = 60 if program_file == "conntrackAnalysis.py" else 30
                    status, output = run_command_with_timeout(client, full_cmd, timeout, hostname=host)
                    if not status:
                        log_error(f"[{host}] Failed to start logging script: {output}")
                        # Always show errors in all modes
                        print_step("PRE-EXPERIMENT", "FAILED", f"Could not start {program_file} on {host}")
                        cleanup_logging_scripts(experiment_name, concurrency, iteration, experiment_id)
                        if client: client.close()
                        return False
                    else:
                        log_info(f"[{host}] Command output: {output}")

                # Wait for the scripts to initialize
                time.sleep(10)

                # Verify that the programs are running
                if is_daemon:
                    search_cmd = f"pgrep -f {program_file}"
                    if client is None:
                        status, output, stderr = run_command_locally(search_cmd, tag)
                    else:
                        status, output = run_command_with_timeout(client, search_cmd, 5, hostname=host)
                        
                    if not status or not output.strip():
                        alt_search_cmd = f"ps aux | grep {program_file} | grep -v grep"
                        if client is None:
                            alt_status, alt_output, alt_stderr = run_command_locally(alt_search_cmd, tag)
                            log_info(f"[{host}] Process search output: {alt_output}")
                        else:
                            alt_status, alt_output = run_command_with_timeout(client, alt_search_cmd, 5, hostname=host)
                            log_info(f"[{host}] Process search output: {alt_output}")
                        
                        log_error(f"[{host}] Could not detect PID for {program_file}")
                        # Always show errors in all modes
                        print_step("PRE-EXPERIMENT", "FAILED", f"Could not detect running {program_file} on {host}")
                        cleanup_logging_scripts(experiment_name, concurrency, iteration, experiment_id)
                        if client: client.close()
                        return False

                    pids = output.strip().splitlines()
                    log_info(f"[{host}] {program_file} running with PID: {pids[0]}")
                    # In super and normal modes, show process info
                    if not automation_mode or not automation_mode.quiet_mode:
                        print_step("PRE-EXPERIMENT", "RUNNING", f"{program_file} on {host} (PID: {pids[0]})")

                if client: client.close()

            log_info(f"[pre-exp] Setup completed for {experiment_name}_{experiment_id}{concurrency}/{iteration}")
            result = verify_critical_processes_running(experiment_name, concurrency, iteration, experiment_id)
            
            # Print completion in super and normal modes
            if not automation_mode or not automation_mode.quiet_mode:
                print_step("PRE-EXPERIMENT", "COMPLETE", "Environment prepared successfully")
            
            # Fifth print for quiet mode
            if automation_mode and automation_mode.quiet_mode:
                print("PRE-EXPERIMENT 5: Environment prepared successfully", flush=True)
                print(f"DATA DIR: {base_path}", flush=True)
            
            return result  # Return result of verification, which will be True/False
        except Exception as e:
            log_error(f"[pre-exp] Error verifying processes: {str(e)}")
            print_step("PRE-EXPERIMENT", "FAILED", f"Error verifying processes: {str(e)}")
            return False
    
    except Exception as e:
        log_error(f"[pre-exp] Critical error during pre-experimentation: {str(e)}")
        print_step("PRE-EXPERIMENT", "FAILED", f"Critical error: {str(e)}")
        return False
