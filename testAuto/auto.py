#!/usr/bin/env python3

import argparse
import os
import sys
import subprocess
import time
import threading
import signal

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
current_concurrency = None
current_iteration = None
monitoring_threads = []
monitoring_stop_events = []
original_stdout = None
original_stderr = None
log_file = None

def signal_handler(signum, frame):
    """Handle Ctrl+C (SIGINT) and perform cleanup"""
    # Stop all monitoring threads
    for stop_event in monitoring_stop_events:
        stop_event.set()
    
    for thread in monitoring_threads:
        if thread.is_alive():
            thread.join(timeout=5)
    
    # Cleanup logging scripts if experiment was running
    if current_experiment_name and current_concurrency and current_iteration:
        cleanup_logging_scripts(current_experiment_name, current_concurrency, current_iteration)
    
    # Close log file
    if log_file:
        log_file.close()
    
    # Print FAILURE to terminal
    if original_stdout:
        original_stdout.write("FAILURE\n")
        original_stdout.flush()
    
    sys.exit(130)

def setup_logging(experiment_name):
    """Redirect all stdout/stderr to log file"""
    global original_stdout, original_stderr, log_file
    
    # Save original stdout/stderr
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    
    # Create log file
    log_path = f"/tmp/{experiment_name}_auto.log"
    log_file = open(log_path, 'w', buffering=1)
    
    # Redirect stdout and stderr to log file
    sys.stdout = log_file
    sys.stderr = log_file
    
    return log_path

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

    # Log monitoring
    print(colored("[check] Step: Log Monitoring", BOLD))
    
    conntrack_stop_event = threading.Event()
    ptp_stop_event = threading.Event()
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
    ptp_monitor_thread = threading.Thread(
        target=monitor_log_file_watchdog,
        kwargs=dict(
            filepath="/var/log/ptp.log",
            keyword_expr="'connt1' 'connt2'",
            timeout=120,
            print_output=False,
            result_dict=monitor_results,
            stop_event=ptp_stop_event,
        ),
        name="ptp-monitor"
    )

    print(colored("[check] Started log monitors.", CYAN))
    conntrack_monitor_thread.start()
    ptp_monitor_thread.start()

    print(colored("[check] Step: Start Client Threads", BOLD))
    client_threads = get_client_threads(10, 1, 1)
    for th in client_threads:
        th.start()

    for th in client_threads:
        th.join()

    print(colored("[check] All client threads completed.", CYAN))

    conntrack_monitor_thread.join()
    ptp_monitor_thread.join()

    conntrack_matches = monitor_results.get("conntrack-monitor", 0)
    ptp_matches = monitor_results.get("ptp-monitor", 0)
    total_matches = conntrack_matches + ptp_matches

    print(f"[check] Total matches: {total_matches}")

    if total_matches == 4:
        print(colored("[check] MATCH found! Proceeding...", GREEN))
        return 4
    else:
        print(colored("[check] Required matches not found!", RED))
        return 0

def pre_experimentation(experiment_name, concurrency, iteration):
    global current_experiment_name, current_concurrency, current_iteration
    current_experiment_name = experiment_name
    current_concurrency = concurrency
    current_iteration = iteration
    
    print(f"[pre-exp] Running pre_experimentation for {experiment_name}{concurrency}/{iteration}")
    
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
    CAlog = f"/tmp/CA.log"
    log_configs = [
        ("connt1", f"sudo ./start.sh -i {iteration} -l /var/log/exp/{experiment_name}{concurrency}/{iteration} -p conntrackd --iface enp3s0 -d", "start.sh", "/opt/MasterThesis/CMNpsutil/", True),
        ("convsrc2", f"sudo ./conntrackAnalysis.py -a connt1 -b connt2 -l /var/log/conntrack.log -o /var/log/exp/{experiment_name}{concurrency}/{iteration}_ca.csv -d -D -L {CAlog}", "conntrackAnalysis.py", "/opt/MasterThesis/connectiontrackingAnalysis/", False),
    ]
    
    print("[pre-exp] Setting up logging scripts")
    
    for host, cmd, program_file, working_dir, is_daemon in log_configs:
        client = ssh_connector.connect(host)
        tag = f"[{host} ssh]" if client else f"[{host} localhost]"

        programs_to_kill = ["start.sh", "cm_monitor.py", "n_monitor.py"] if program_file == "start.sh" else ["conntrackAnalysis.py"]
        pre_kill_conflicting_processes(client, host, programs_to_kill)

        full_cmd = f"cd {working_dir} && {cmd}"
        if client is None:
            status, output, stderr = run_command_locally(full_cmd, tag)
        else:
            status, output = run_command_with_timeout(client, full_cmd, 30, hostname=host)

        if not status:
            print(f"ERROR: [{host}] Failed to start logging script")
            cleanup_logging_scripts(experiment_name, concurrency, iteration)
            if client: client.close()
            return False

        time.sleep(10)

        if is_daemon:
            search_cmd = f"pgrep -f {program_file}"
            if client is None:
                status, output, stderr = run_command_locally(search_cmd, tag)
            else:
                status, output = run_command_with_timeout(client, search_cmd, 5, hostname=host)
                
            if not status or not output.strip():
                print(f"ERROR: [{host}] Could not detect PID for {program_file}")
                cleanup_logging_scripts(experiment_name, concurrency, iteration)
                if client: client.close()
                return False

            pids = output.strip().splitlines()
            print(f"[{host}] {program_file} running with PID: {pids[0]}")

        if client: client.close()

    print(f"[pre-exp] Setup completed for {experiment_name}{concurrency}/{iteration}")
    verify_critical_processes_running(experiment_name, concurrency, iteration)
    return True

def experimentation(experiment_name, concurrency, iteration):
    global monitoring_threads, monitoring_stop_events
    
    print(f"[exp] Running experimentation for {experiment_name}{concurrency}/{iteration}")
    
    log_files_to_monitor = [
        {"filepath": f"/var/log/exp/{experiment_name}{concurrency}/{iteration}_ca.csv", "host": "convsrc2"},
        {"filepath": f"/var/log/exp/{experiment_name}{concurrency}/{iteration}_conntrackd_cm_monitor.csv", "host": "connt1"},
        {"filepath": f"/var/log/exp/{experiment_name}{concurrency}/{iteration}_conntrackd_n_monitor.csv", "host": "connt1"}
    ]

    print("[exp] Starting log file monitoring")
    
    progress_tracker.file_stats.clear()
    progress_tracker.start_time = time.time()
    progress_tracker.last_full_display = 0
    
    monitor_results = {}
    monitoring_threads = []
    monitoring_stop_events = []
    
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
                "print_output": False,
                "result_dict": monitor_results,
                "stop_event": stop_event,
            },
            name=f"ExpMonitor-{log_info['host']}-{os.path.basename(log_info['filepath'])}"
        )
        monitoring_threads.append(t)
        t.start()
    
    progress_display_stop = threading.Event()
    progress_thread = threading.Thread(
        target=periodic_progress_display,
        args=(progress_display_stop, 90),
        name="PeriodicProgressDisplay"
    )
    progress_thread.start()
    
    print("[exp] Starting client threads")
    client_threads = get_client_threads(250000, concurrency, 4)
    for th in client_threads:
        th.start()

    for th in client_threads:
        th.join()

    print("[exp] Client threads completed, monitoring for 500 seconds")
    
    time.sleep(500)
    
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

def post_experimentation(experiment_name, concurrency, iteration):
    global current_experiment_name, current_concurrency, current_iteration
    
    print(f"[post-exp] Cleanup for {experiment_name}{concurrency}/{iteration}")
    cleanup_logging_scripts(experiment_name, concurrency, iteration)
    
    current_experiment_name = None
    current_concurrency = None
    current_iteration = None
    
    print("[post-exp] Cleanup completed")
    return True

def main():
    parser = argparse.ArgumentParser(description="Automation script for experiments.")
    parser.add_argument("-n", "--name", required=True, help="Experiment name")
    parser.add_argument("-i", "--iterations", required=True, type=int, help="Number of iterations")
    parser.add_argument("-c", "--concurrency", required=True, help="Concurrency values (comma-separated)")
    parser.add_argument("-d", "--debug", action="store_true", help="Debug mode (currently unused)")
    args = parser.parse_args()

    experiment_name = args.name
    iterations = args.iterations
    
    # Parse concurrency values
    try:
        concurrency_values = [int(x.strip()) for x in args.concurrency.split(',')]
    except ValueError:
        print("ERROR: Invalid concurrency values")
        sys.exit(1)
    
    # Setup logging - redirect stdout/stderr to log file
    log_path = setup_logging(experiment_name)
    
    # Register signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        print(f"[MAIN] Experiment: {experiment_name}")
        print(f"[MAIN] Iterations: {iterations}")
        print(f"[MAIN] Concurrency values: {concurrency_values}")
        print(f"[MAIN] Started at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        
        ssh_connector = SSHConnector()
        client = ssh_connector.connect("connt1")

        # Create directories
        for c in concurrency_values:
            directory_cmd = f"sudo mkdir -p /var/log/exp/{experiment_name}{c}"
            if client is None:
                subprocess.run(directory_cmd, shell=True, check=True)
            else:
                stdin, stdout, stderr = client.exec_command(directory_cmd)
                exit_code = stdout.channel.recv_exit_status()
                if exit_code != 0:
                    raise Exception(f"Failed to create directory for {experiment_name}{c}")

        # Run experiments
        total_experiments = len(concurrency_values) * iterations
        current_experiment = 0
        
        for c in concurrency_values:
            for i in range(iterations):
                current_experiment += 1
                iteration_number = i + 1
                
                print(f"\nEXPERIMENT {current_experiment}/{total_experiments}: {experiment_name} - Concurrency {c} - Iteration {iteration_number}")
                
                check_result = check_function()
                if check_result != 4:
                    raise Exception("check_function failed")
                    
                if not pre_experimentation(experiment_name, c, iteration_number):
                    raise Exception("pre_experimentation failed")
                    
                if not experimentation(experiment_name, c, iteration_number):
                    raise Exception("experimentation failed")
                    
                if not post_experimentation(experiment_name, c, iteration_number):
                    raise Exception("post_experimentation failed")
                
                print(f"Experiment {current_experiment}/{total_experiments} completed successfully")
                time.sleep(1)

        if client:
            client.close()
        
        print(f"\nAll {total_experiments} experiments completed successfully!")
        print(f"Log file: {log_path}")
        
        # Close log file
        if log_file:
            log_file.close()
        
        # Print SUCCESS to terminal
        original_stdout.write("SUCCESS\n")
        original_stdout.flush()
        
    except Exception as e:
        print(f"ERROR: {str(e)}")
        
        # Close log file
        if log_file:
            log_file.close()
        
        # Print FAILURE to terminal
        original_stdout.write("FAILURE\n")
        original_stdout.flush()
        sys.exit(1)

if __name__ == "__main__":
    main()
