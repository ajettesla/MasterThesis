#!/usr/bin/env python3

import argparse
import os
import sys
import subprocess
import time
import threading
import signal
import re

from helper import SSHConnector, RemoteProgramRunner, monitor_log_file_watchdog, progress_tracker

# --- Colors ---
RESET  = "\033[0m"
RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
BLUE   = "\033[34m"
CYAN   = "\033[36m"
MAGENTA= "\033[35m"
BOLD   = "\033[1m"

# Global variables for cleanup
current_experiment_name = None
current_concurrency = None
current_iteration = None
monitoring_threads = []
monitoring_stop_events = []

def colored(msg, color):
    return f"{color}{msg}{RESET}"

def get_current_hostname():
    """Get the current hostname where the script is running"""
    try:
        return subprocess.check_output(['hostname'], text=True).strip()
    except:
        return "unknown"

def signal_handler(signum, frame):
    """Handle Ctrl+C (SIGINT) and perform cleanup"""
    print(f"\n{YELLOW}[SIGNAL] Received signal {signum}. Performing cleanup...{RESET}")
    
    # Stop all monitoring threads
    print(f"{YELLOW}[SIGNAL] Stopping monitoring threads...{RESET}")
    for stop_event in monitoring_stop_events:
        stop_event.set()
    
    for thread in monitoring_threads:
        if thread.is_alive():
            thread.join(timeout=5)
    
    # Cleanup logging scripts if experiment was running
    if current_experiment_name and current_concurrency and current_iteration:
        print(f"{YELLOW}[SIGNAL] Cleaning up experiment {current_experiment_name}{current_concurrency}/{current_iteration}...{RESET}")
        cleanup_logging_scripts(current_experiment_name, current_concurrency, current_iteration)
    
    print(f"{GREEN}[SIGNAL] Cleanup completed. Exiting...{RESET}")
    sys.exit(0)

def run_command_locally(cmd: str, hosttag="[localhost]"):
    print(f"{CYAN}{hosttag} Executing:{RESET} {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return (result.returncode == 0, result.stdout, result.stderr)

def run_command_remotely(client, cmd: str, hosttag):
    print(f"{MAGENTA}{hosttag} Executing:{RESET} {cmd}")
    stdin, stdout, stderr = client.exec_command(cmd)
    exit_code = stdout.channel.recv_exit_status()
    out = stdout.read().decode()
    err = stderr.read().decode()
    return (exit_code == 0, out, err)

def run_command_with_timeout(client, command, timeout, hostname="unknown"):
    if client is None:
        # Local execution
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout)
            return (result.returncode == 0, result.stdout)
        except subprocess.TimeoutExpired:
            return (False, f"Timeout exceeded ({timeout}s)")
        except Exception as e:
            return (False, str(e))
    else:
        # Remote execution
        try:
            stdin, stdout, stderr = client.exec_command(command)
            start = time.time()
            while not stdout.channel.exit_status_ready():
                if time.time() - start > timeout:
                    stdout.channel.close()
                    print(f"{RED}[{hostname}] Timeout exceeded while running: {command}{RESET}")
                    return False, f"Timeout exceeded while running: {command}"
                time.sleep(0.5)
            out = stdout.read().decode()
            err = stderr.read().decode()
            return True, out if out else err
        except Exception as e:
            print(f"{RED}[{hostname}] Exception during command: {command}\n{e}{RESET}")
            return False, str(e)

def build_and_run_client(hostname, command):
    runner = RemoteProgramRunner(
        hostname=hostname,
        command=command,
        working_dir="/opt/MasterThesis/trafGen",
        max_duration=120,
        cleanup=True,
        verbose=True,
        timeout=60,
    )
    result = runner.run()
    return result

def get_client_threads(concurrency_n, concurrency_c, tcp_timeout_t):
    client_threads = [
        threading.Thread(
            target=build_and_run_client,
            kwargs=dict(
                hostname="convsrc1",
                command=f"sudo ./tcp_client_er -s 172.16.1.1 -p 2000 -n {concurrency_n} -c {concurrency_c} -w 1 -a 172.16.1.10-22 -k -r 10000-65000 -t {tcp_timeout_t}"
            ),
            name="Client-tcp-convsrc1"
        ),
        threading.Thread(
            target=build_and_run_client,
            kwargs=dict(
                hostname="convsrc1",
                command=f"./udp_client_sub -s 172.16.1.1 -p 3000 -n {concurrency_n} -c {concurrency_c} -a 172.16.1.10-22 -r 10000-65000"
            ),
            name="Client-udp-convsrc1"
        ),
        threading.Thread(
            target=build_and_run_client,
            kwargs=dict(
                hostname="convsrc2",
                command=f"./udp_client_sub -s 172.16.1.1 -p 3000 -n {concurrency_n} -c {concurrency_c} -a 172.16.1.26-39 -r 10000-65000"
            ),
            name="Client-udp-convsrc2"
        ),
        threading.Thread(
            target=build_and_run_client,
            kwargs=dict(
                hostname="convsrc2",
                command=f"sudo ./tcp_client_er -s 172.16.1.1 -p 2000 -n {concurrency_n} -c {concurrency_c} -w 1 -a 172.16.1.26-39 -k -r 10000-65000 -t {tcp_timeout_t}"
            ),
            name="Client-tcp-convsrc2"
        )
    ]
    return client_threads

def pre_kill_conflicting_processes(client, host, programs):
    """Kill conflicting processes with force"""
    for prog in programs:
        check_cmd = f"pgrep -f {prog}"
        if client is None:
            status, output, _ = run_command_locally(check_cmd, f"[{host} localhost]")
        else:
            status, output = run_command_with_timeout(client, check_cmd, 5, hostname=host)
        
        if status and output.strip():
            pids = output.strip().splitlines()
            print(f"{YELLOW}[{host}] Found running '{prog}' with PIDs: {', '.join(pids)}. Killing...{RESET}")
            for pid in pids:
                kill_cmd = f"sudo kill -9 {pid}"
                if client is None:
                    run_command_locally(kill_cmd, f"[{host} localhost]")
                else:
                    run_command_with_timeout(client, kill_cmd, 5, hostname=host)
            time.sleep(1)
        else:
            print(f"{GREEN}[{host}] No '{prog}' processes running.{RESET}")

def cleanup_logging_scripts(experiment_name, concurrency, iteration):
    print(f"{MAGENTA}[cleanup] Starting comprehensive cleanup for {experiment_name}{concurrency}/{iteration}...{RESET}")
    
    CAlog = f"/tmp/CA.log"
    log_configs = [
        (
            "connt1",
            f"sudo ./start.sh -i {iteration} -l /var/log/exp/{experiment_name}{concurrency}/{iteration} -p conntrackd --iface enp3s0 -d",
            "start.sh",
            "/opt/MasterThesis/CMNpsutil/"
        ),
        (
            "convsrc2",
            f"sudo ./conntrackAnalysis.py -a connt1 -b connt2 -l /var/log/conntrack.log -o /var/log/exp/{experiment_name}{concurrency}/{iteration}_ca.csv -d -D -L {CAlog}",
            "conntrackAnalysis.py",
            "/opt/MasterThesis/connectiontrackingAnalysis/"
        ),
    ]
    
    ssh_connector = SSHConnector()
    
    for host, _, program_file, working_dir in log_configs:
        print(f"{YELLOW}[cleanup] [{host}] Attempting graceful shutdown of {program_file}...{RESET}")

        client = ssh_connector.connect(host)
        tag = f"[{host} ssh]" if client else f"[{host} localhost]"
        
        kill_cmd = f"cd {working_dir} && sudo ./{program_file} -k"
        if client is None:
            status, output, _ = run_command_locally(kill_cmd, tag)
        else:
            status, output = run_command_with_timeout(client, kill_cmd, 5, hostname=host)

        if status:
            print(f"{GREEN}[cleanup] [{host}] Sent graceful shutdown to {program_file}{RESET}")
        else:
            print(f"{RED}[cleanup] [{host}] Failed to send graceful shutdown.{RESET}")
            print(f"{RED}[cleanup] [{host}] Output: {output.strip()}{RESET}")

        if client:
            client.close()

    # Wait 5 seconds for graceful shutdown
    print(f"{YELLOW}[cleanup] Waiting 5 seconds for graceful shutdown...{RESET}")
    time.sleep(5)

    # Now force kill all monitoring processes on all hosts
    force_kill_all_monitoring_processes()

def force_kill_all_monitoring_processes():
    """Force kill all monitoring processes across all hosts"""
    print(f"{MAGENTA}[cleanup] Force killing all monitoring processes...{RESET}")
    
    ssh_connector = SSHConnector()
    
    # Define all monitoring processes to kill on each host
    monitoring_processes = {
        "connt1": ["start.sh", "cm_monitor.py", "n_monitor.py"],
        "connt2": ["start.sh", "cm_monitor.py", "n_monitor.py"],
        "convsrc2": ["conntrackAnalysis.py"],
        "convsrc1": [],
        "convsrc8": [],
        "convsrc5": [],
    }
    
    for host, processes in monitoring_processes.items():
        if not processes:
            continue
            
        print(f"{YELLOW}[cleanup] [{host}] Force killing monitoring processes...{RESET}")
        client = ssh_connector.connect(host)
        tag = f"[{host} ssh]" if client else f"[{host} localhost]"
        
        for process in processes:
            # First try SIGTERM
            kill_cmd = f"sudo pkill -f {process}"
            if client is None:
                status, output, _ = run_command_locally(kill_cmd, tag)
            else:
                status, output = run_command_with_timeout(client, kill_cmd, 3, hostname=host)
            
            time.sleep(1)
            
            # Then force kill with SIGKILL
            force_kill_cmd = f"sudo pkill -9 -f {process}"
            if client is None:
                status, output, _ = run_command_locally(force_kill_cmd, tag)
            else:
                status, output = run_command_with_timeout(client, force_kill_cmd, 3, hostname=host)
            
            print(f"{GREEN}[cleanup] [{host}] Force killed {process}{RESET}")
        
        if client:
            client.close()
    
    print(f"{GREEN}[cleanup] Force kill completed for all monitoring processes.{RESET}")

def verify_critical_processes_running(experiment_name, concurrency, iteration):
    """Verify that all critical processes are running - exit if any are missing"""
    print(colored("[verify] Checking that all critical processes are running...", BOLD))
    
    ssh_connector = SSHConnector()
    critical_services = {
        "connt1": ["conntrackd"],
      # "connt2": ["conntrackd"],
    }
    critical_processes = {
        "connt1": ["start.sh", "cm_monitor.py", "n_monitor.py"],
        "convsrc2": ["conntrackAnalysis.py"]
    }
    
    all_running = True
    failed_items = []
    
    # Check systemctl services
    for host, services in critical_services.items():
        client = ssh_connector.connect(host)
        tag = f"[{host} ssh]" if client else f"[{host} localhost]"
        
        for service in services:
            check_cmd = f"sudo systemctl is-active {service}"
            if client is None:
                status, output, stderr = run_command_locally(check_cmd, tag)
            else:
                status, output, stderr = run_command_remotely(client, check_cmd, tag)
            
            if not status or "active" not in output.strip():
                print(f"{RED}[{host}] CRITICAL: Service '{service}' is NOT active! Status: {output.strip()}{RESET}")
                failed_items.append(f"{host}:{service} (service)")
                all_running = False
            else:
                print(f"{GREEN}[{host}] Service '{service}' is active.{RESET}")
        
        if client:
            client.close()
    
    # Check processes
    for host, processes in critical_processes.items():
        client = ssh_connector.connect(host)
        tag = f"[{host} ssh]" if client else f"[{host} localhost]"
        
        for process in processes:
            check_cmd = f"pgrep -f {process}"
            if client is None:
                status, output, stderr = run_command_locally(check_cmd, tag)
            else:
                status, output = run_command_with_timeout(client, check_cmd, 5, hostname=host)
                stderr = ""
            
            if not status or not output.strip():
                print(f"{RED}[{host}] CRITICAL: Process '{process}' is NOT running!{RESET}")
                if stderr:
                    print(f"{RED}[{host}] STDERR: {stderr}{RESET}")
                failed_items.append(f"{host}:{process} (process)")
                all_running = False
            else:
                pids = output.strip().splitlines()
                print(f"{GREEN}[{host}] Process '{process}' is running with PID(s): {', '.join(pids)}{RESET}")
        
        if client:
            client.close()
    
    if not all_running:
        print(f"{RED}[verify] FATAL ERROR: The following critical items are not running:{RESET}")
        for failed in failed_items:
            print(f"{RED}  - {failed}{RESET}")
        print(f"{RED}[verify] Unable to continue experimentation. Exiting program.{RESET}")
        sys.exit(1)
    
    print(colored("[verify] All critical services and processes are running successfully.", GREEN))
    return True

def monitor_remote_log_file(filepath, host, keyword_expr="", timeout=None, print_output=True, result_dict=None, stop_event=None):
    """Monitor log files on remote hosts using wc -l for line counting"""
    current_host = get_current_hostname()
    
    if host == current_host or host == "localhost" or host == "convsrc2":
        # Monitor locally using the existing function
        monitor_log_file_watchdog(
            filepath=filepath,
            keyword_expr=keyword_expr,
            timeout=timeout,
            print_output=print_output,
            result_dict=result_dict,
            stop_event=stop_event
        )
    else:
        # Monitor remotely using SSH and wc -l
        ssh_connector = SSHConnector()
        client = ssh_connector.connect(host)
        tag = f"[{host} ssh]" if client else f"[{host} localhost]"
        
        print(f"{BLUE}[{current_host} local check] Starting remote monitoring of {os.path.basename(filepath)} on {host} using wc -l{RESET}")
        
        keywords = set(re.findall(r"'(.*?)'", keyword_expr))
        match_mode = bool(keywords)
        seen_keywords = set()
        
        # Initialize tracking variables
        previous_line_count = 0
        current_line_count = 0
        previous_file_size = 0
        current_file_size = 0
        total_lines_grown = 0
        
        start_time = time.time()
        last_progress_time = time.time()
        progress_interval = 30  # Update progress every 30 seconds
        
        def get_remote_file_stats():
            """Get line count and file size from remote host"""
            try:
                # Get line count using wc -l
                wc_cmd = f"wc -l {filepath} 2>/dev/null | awk '{{print $1}}' || echo 0"
                if client is None:
                    return 0, 0
                
                stdin, stdout, stderr = client.exec_command(wc_cmd)
                line_output = stdout.read().decode().strip()
                try:
                    line_count = int(line_output)
                except:
                    line_count = 0
                
                # Get file size using stat
                size_cmd = f"stat -c %s {filepath} 2>/dev/null || echo 0"
                stdin, stdout, stderr = client.exec_command(size_cmd)
                size_output = stdout.read().decode().strip()
                try:
                    file_size = int(size_output)
                except:
                    file_size = 0
                
                return line_count, file_size
            except Exception as e:
                print(f"{RED}[{current_host} local check] Error getting stats for {filepath} on {host}: {e}{RESET}")
                return 0, 0
        
        def update_progress_display(force_display=False):
            """Update progress tracker with current stats"""
            nonlocal last_progress_time
            current_time = time.time()
            
            if force_display or (current_time - last_progress_time >= progress_interval):
                progress_tracker.update_file_progress(
                    f"{host}:{os.path.basename(filepath)}",
                    previous_file_size,
                    current_file_size,
                    total_lines_grown,
                    current_file_size,
                    update_display=True
                )
                last_progress_time = current_time
        
        try:
            if client is None:
                print(f"{RED}[{current_host} local check] No SSH client for remote host {host}{RESET}")
                return
            
            # Get initial file stats
            current_line_count, current_file_size = get_remote_file_stats()
            previous_line_count = current_line_count
            previous_file_size = current_file_size
            
            print(f"{CYAN}[{current_host} local check] Initial stats for {os.path.basename(filepath)} on {host}: {current_line_count} lines, {current_file_size} bytes{RESET}")
            
            # Initial progress update
            update_progress_display(force_display=True)
            
            check_interval = 5  # Check every 5 seconds
            last_check_time = time.time()
            
            while not stop_event.is_set():
                current_time = time.time()
                
                # Check file stats every 5 seconds
                if current_time - last_check_time >= check_interval:
                    # Get current stats
                    new_line_count, new_file_size = get_remote_file_stats()
                    
                    # Calculate growth
                    lines_grown = new_line_count - current_line_count
                    bytes_grown = new_file_size - current_file_size
                    
                    if lines_grown > 0 or bytes_grown > 0:
                        print(f"{GREEN}[{current_host} local check] {host}:{os.path.basename(filepath)} - Lines: +{lines_grown} (total: {new_line_count}), Size: +{bytes_grown}B (total: {new_file_size}B){RESET}")
                        
                        # Update totals
                        total_lines_grown += lines_grown
                        previous_file_size = current_file_size
                        current_line_count = new_line_count
                        current_file_size = new_file_size
                        
                        # Handle keyword matching if needed
                        if match_mode and lines_grown > 0:
                            # Get the new lines for keyword matching
                            tail_cmd = f"tail -n {lines_grown} {filepath} 2>/dev/null || echo ''"
                            stdin, stdout, stderr = client.exec_command(tail_cmd)
                            new_lines = stdout.read().decode().strip()
                            
                            for line in new_lines.splitlines():
                                line = line.strip()
                                if line:
                                    for kw in keywords:
                                        if kw in line and kw not in seen_keywords:
                                            seen_keywords.add(kw)
                                            print(f"{GREEN}[{current_host} local check] MATCH found keyword '{kw}' in {host}:{os.path.basename(filepath)}{RESET}")
                            
                            if seen_keywords == keywords:
                                print(f"{GREEN}[{current_host} local check] All keywords matched on {host}. Stopping monitor.{RESET}")
                                if result_dict is not None:
                                    result_dict[f"remote-{host}-{threading.current_thread().name}"] = len(seen_keywords)
                                stop_event.set()
                                break
                    
                    last_check_time = current_time
                
                # Update progress display periodically
                update_progress_display()
                
                # Check timeout
                if timeout:
                    elapsed = time.time() - start_time
                    if elapsed >= timeout:
                        print(f"{RED}[{current_host} local check] Timeout reached for remote monitoring of {filepath} on {host}{RESET}")
                        break
                
                time.sleep(1)  # Sleep for 1 second between checks
        
        except Exception as e:
            print(f"{RED}[{current_host} local check] Error monitoring remote file {filepath} on {host}: {e}{RESET}")
        
        finally:
            if client:
                client.close()
            
            print(f"{CYAN}[{current_host} local check] Remote monitoring finished for {os.path.basename(filepath)} on {host}. Total lines grown: {total_lines_grown}{RESET}")
            
            if result_dict is not None:
                if match_mode:
                    result_dict[f"remote-{host}-{threading.current_thread().name}"] = len(seen_keywords)
                else:
                    result_dict[f"remote-{host}-{threading.current_thread().name}"] = total_lines_grown

def check_function():
    print(colored("[check] Step: Service Restart/Check/Flush", BOLD))
    service_hosts = {
        "convsrc8": ["tcp_server", "udp_server"],
        "convsrc5": ["tcp_server", "udp_server"]
    }
    logger_hosts = ["connt1", "connt2"]
    logger_host = ["connt1"] # for conntrackd only 
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

    # ===== CONNTRACKD SERVICE MANAGEMENT =====
    print(colored("[check] Step: Conntrackd Service Management", BOLD))
    for host in logger_host:
        client = ssh_connector.connect(host)
        tag = f"[{host} ssh]" if client else f"[{host} localhost]"
        
        # Check conntrackd service status using systemctl
        cmd_check_status = "sudo systemctl is-active conntrackd"
        if client is None:
            status, output, err = run_command_locally(cmd_check_status, tag)
        else:
            status, output, err = run_command_remotely(client, cmd_check_status, tag)
        
        if status and "active" in output.strip():
            print(colored(f"{tag} conntrackd service is already active.", GREEN))
        else:
            print(colored(f"{tag} conntrackd service is not active (status: {output.strip()}). Starting it...", YELLOW))
            
            # ONLY START - DO NOT STOP FIRST
            cmd_start = "sudo systemctl start conntrackd"
            if client is None:
                start_status, start_output, start_err = run_command_locally(cmd_start, tag)
            else:
                start_status, start_output, start_err = run_command_remotely(client, cmd_start, tag)
            
            if not start_status:
                print(colored(f"{tag} Failed to start conntrackd service! Error: {start_err}", RED))
                
                # Show detailed status for debugging
                cmd_detailed_status = "sudo systemctl status conntrackd"
                if client is None:
                    detail_status, detail_output, _ = run_command_locally(cmd_detailed_status, tag)
                else:
                    detail_status, detail_output, _ = run_command_remotely(client, cmd_detailed_status, tag)
                
                print(colored(f"{tag} Detailed conntrackd status:", YELLOW))
                print(f"{detail_output}")
                
                if client: client.close()
                return 9
            
            # Wait for service to start
            time.sleep(3)
            
            # Verify service is now active
            if client is None:
                verify_status, verify_output, verify_err = run_command_locally(cmd_check_status, tag)
            else:
                verify_status, verify_output, verify_err = run_command_remotely(client, cmd_check_status, tag)
            
            if not verify_status or "active" not in verify_output.strip():
                print(colored(f"{tag} conntrackd service failed to start properly!", RED))
                print(colored(f"{tag} Status check result: {verify_output.strip()}", RED))
                
                # Show detailed status for debugging
                cmd_detailed_status = "sudo systemctl status conntrackd"
                if client is None:
                    detail_status, detail_output, _ = run_command_locally(cmd_detailed_status, tag)
                else:
                    detail_status, detail_output, _ = run_command_remotely(client, cmd_detailed_status, tag)
                
                print(colored(f"{tag} Detailed conntrackd status after start attempt:", YELLOW))
                print(f"{detail_output}")
                
                if client: client.close()
                return 10
            
            print(colored(f"{tag} conntrackd service started successfully.", GREEN))
            
            # Flush conntrack tables after successful start
            print(colored(f"{tag} Flushing conntrack tables after conntrackd start...", YELLOW))
            cmd_flush_after_start = "sudo conntrack -F"
            if client is None:
                flush_status, _, flush_err = run_command_locally(cmd_flush_after_start, tag)
            else:
                flush_status, _, flush_err = run_command_remotely(client, cmd_flush_after_start, tag)
            
            if not flush_status:
                print(colored(f"{tag} conntrack flush after start failed! {flush_err}", RED))
                if client: client.close()
                return 12
            else:
                print(colored(f"{tag} conntrack tables flushed after conntrackd start.", GREEN))
        
        # Final verification using systemctl
        cmd_final_check = "sudo systemctl is-active conntrackd"
        if client is None:
            final_status, final_output, _ = run_command_locally(cmd_final_check, tag)
        else:
            final_status, final_output, _ = run_command_remotely(client, cmd_final_check, tag)
        
        if not final_status or "active" not in final_output.strip():
            print(colored(f"{tag} CRITICAL: conntrackd service is still not active!", RED))
            
            # Show final detailed status
            cmd_detailed_status = "sudo systemctl status conntrackd"
            if client is None:
                detail_status, detail_output, _ = run_command_locally(cmd_detailed_status, tag)
            else:
                detail_status, detail_output, _ = run_command_remotely(client, cmd_detailed_status, tag)
            
            print(colored(f"{tag} Final conntrackd service status:", YELLOW))
            print(f"{detail_output}")
            
            if client: client.close()
            return 11
        else:
            print(colored(f"{tag} conntrackd service is running successfully (verified with systemctl).", GREEN))
        
        if client: client.close()

    # ===== TRUNCATE LOGS on convsrc2 =====
    print(colored("[check] Step: Truncate Logs", BOLD))
    convsrc2_tag = "[convsrc2 localhost]"
    ssh_convsrc2 = ssh_connector.connect("convsrc2")
    for logfile in ["/var/log/conntrack.log", "/var/log/ptp.log"]:
        cmd_truncate = f"sudo truncate -s 0 {logfile}"
        if ssh_convsrc2 is None:
            ok, _, err = run_command_locally(cmd_truncate, convsrc2_tag)
        else:
            ok, _, err = run_command_remotely(ssh_convsrc2, cmd_truncate, convsrc2_tag)
        if not ok:
            print(colored(f"{convsrc2_tag} Failed to truncate {logfile}: {err}", RED))
            if ssh_convsrc2: ssh_convsrc2.close()
            return 8
        else:
            print(colored(f"{convsrc2_tag} Successfully truncated {logfile}", GREEN))
    if ssh_convsrc2: ssh_convsrc2.close()

    # ===== CONNTRACK_LOGGER SERVICE MANAGEMENT =====
    print(colored("[check] Step: Conntrack Logger Service Management", BOLD))
    for host in logger_hosts:
        client = ssh_connector.connect(host)
        tag = f"[{host} ssh]" if client else f"[{host} localhost]"
        cmd_restart = "sudo systemctl restart conntrack_logger"
        cmd_check   = "sudo systemctl is-active conntrack_logger"
        cmd_flush   = "sudo conntrack -F"
        
        # Restart conntrack_logger service
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
            print(colored(f"{tag} conntrack_logger is not active! Output: {out} Error: {err}", RED))
            if client: client.close()
            return 6

        print(colored(f"{tag} conntrack_logger service is active.", GREEN))

        # FLUSH CONNTRACK TABLES (second flush after conntrack_logger restart)
        if client is None:
            ok, _, err = run_command_locally(cmd_flush, tag)
        else:
            ok, _, err = run_command_remotely(client, cmd_flush, tag)
        if not ok:
            print(colored(f"{tag} conntrack flush failed! {err}", RED))
            if client: client.close()
            return 7
        else:
            print(colored(f"{tag} conntrack tables flushed successfully.", GREEN))
        
        if client: client.close()

    print(colored("[check] All services active and conntrack tables flushed.", GREEN))

    print(colored("[check] Step: Log Monitoring", BOLD))
    
    # Separate stop events for each monitoring thread
    conntrack_stop_event = threading.Event()
    ptp_stop_event = threading.Event()
    monitor_results = {}

    conntrack_log = "/var/log/conntrack.log"
    ptp_log = "/var/log/ptp.log"

    conntrack_monitor_thread = threading.Thread(
        target=monitor_log_file_watchdog,
        kwargs=dict(
            filepath=conntrack_log,
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
            filepath=ptp_log,
            keyword_expr="'connt1' 'connt2'",
            timeout=120,
            print_output=False,
            result_dict=monitor_results,
            stop_event=ptp_stop_event,
        ),
        name="ptp-monitor"
    )

    print(colored("[check] Started log monitors for conntrack.log and ptp.log.", CYAN))
    conntrack_monitor_thread.start()
    ptp_monitor_thread.start()

    print(colored("[check] Step: Start Client Threads", BOLD))
    client_threads = get_client_threads(10, 1, 1)
    for th in client_threads:
        th.start()

    for th in client_threads:
        th.join()

    print(colored("[check] All client threads completed.", CYAN))

    print(colored("[check] Waiting for log monitoring to complete or timeout...", YELLOW))
    conntrack_monitor_thread.join()
    ptp_monitor_thread.join()

    conntrack_matches = monitor_results.get("conntrack-monitor", 0)
    ptp_matches       = monitor_results.get("ptp-monitor", 0)
    total_matches = conntrack_matches + ptp_matches

    print(
        colored(
            f"[check] Conntrack matches: {conntrack_matches} | PTP matches: {ptp_matches} | Total: {total_matches}",
            GREEN if total_matches == 4 else RED
        )
    )

    if total_matches == 4:
        print(colored("[check] MATCH found! Proceeding...", GREEN))
        return 4
    else:
        print(colored("[check] Required matches not found! Exiting...", RED))
        return 0

def pre_experimentation(experiment_name, concurrency, iteration):
    global current_experiment_name, current_concurrency, current_iteration
    current_experiment_name = experiment_name
    current_concurrency = concurrency
    current_iteration = iteration
    
    print(colored(f"[pre-exp] Running pre_experimentation for {experiment_name}{concurrency}/{iteration}...", CYAN))
    
    # First flush conntrack on connt1 and connt2
    print(colored("[pre-exp] Step: Flush Conntrack Tables", BOLD))
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
            print(colored(f"{tag} conntrack flush failed! {err}", RED))
            if client: client.close()
            return False
        if client: client.close()
    
    print(colored("[pre-exp] Conntrack tables flushed.", GREEN))
    
    # Setup logging scripts
    CAlog = f"/tmp/CA.log"
    log_configs = [
        (
            "connt1",
            f"sudo ./start.sh -i {iteration} -l /var/log/exp/{experiment_name}{concurrency}/{iteration} -p conntrackd --iface enp3s0 -d",
            "start.sh",
            "/opt/MasterThesis/CMNpsutil/",
            True
        ),
        (
            "convsrc2",
            f"sudo ./conntrackAnalysis.py -a connt1 -b connt2 -l /var/log/conntrack.log -o /var/log/exp/{experiment_name}{concurrency}/{iteration}_ca.csv -d -D -L {CAlog}",
            "conntrackAnalysis.py",
            "/opt/MasterThesis/connectiontrackingAnalysis/",
            False
        ),
    ]
    
    print(colored("[pre-exp] Step: Setup Logging Scripts", BOLD))
    
    for host, cmd, program_file, working_dir, is_daemon in log_configs:
        print(f"{YELLOW}[{host}] Starting logging script: {cmd}{RESET}")

        client = ssh_connector.connect(host)
        tag = f"[{host} ssh]" if client else f"[{host} localhost]"

        # Step 0: Kill previous conflicting processes
        programs_to_kill = ["start.sh", "cm_monitor.py", "n_monitor.py"]
        if program_file == "conntrackAnalysis.py":
            programs_to_kill = ["conntrackAnalysis.py"]

        pre_kill_conflicting_processes(client, host, programs_to_kill)

        # Step 1: Run the command
        full_cmd = f"cd {working_dir} && {cmd}"
        if client is None:
            status, output, stderr = run_command_locally(full_cmd, tag)
        else:
            status, output = run_command_with_timeout(client, full_cmd, 30, hostname=host)
            stderr = ""

        if not status:
            print(f"{RED}[{host}] Failed to start logging script '{cmd}'.{RESET}")
            print(f"{RED}[{host}] STDOUT/STDERR:\n{output.strip()}{RESET}")
            if stderr:
                print(f"{RED}[{host}] STDERR: {stderr}{RESET}")
            print(f"{RED}Pre-experimentation phase failed for '{experiment_name}'.{RESET}")
            cleanup_logging_scripts(experiment_name, concurrency, iteration)
            if client: client.close()
            return False
        else:
            print(f"{GREEN}[{host}] Command executed. Output:\n{output.strip()}{RESET}")

        # Wait 10 seconds before checking for PID
        print(f"{YELLOW}[{host}] Waiting 10 seconds for {program_file} to start up...{RESET}")
        time.sleep(10)

        if is_daemon:
            # Step 2: Look for PID using pgrep (only for daemon processes)
            search_cmd = f"pgrep -f {program_file}"
            if client is None:
                status, output, stderr = run_command_locally(search_cmd, tag)
            else:
                status, output = run_command_with_timeout(client, search_cmd, 5, hostname=host)
                stderr = ""
                
            if not status or not output.strip():
                print(f"{RED}[{host}] Could not detect PID for '{program_file}'.{RESET}")
                print(f"{RED}[{host}] Output:\n{output.strip()}{RESET}")
                if stderr:
                    print(f"{RED}[{host}] STDERR: {stderr}{RESET}")
                print(f"{RED}Pre-experimentation phase failed for '{experiment_name}'.{RESET}")
                cleanup_logging_scripts(experiment_name, concurrency, iteration)
                if client: client.close()
                return False

            # Handle multiple PIDs
            pids = output.strip().splitlines()
            pid = pids[0]  # Take the first PID
            print(f"{GREEN}[{host}] Logging script '{program_file}' is running with PID: {pid}{RESET}")

            # Confirm PID is running
            confirm_cmd = f"ps -p {pid} -o pid="
            if client is None:
                status, ps_output, stderr = run_command_locally(confirm_cmd, tag)
            else:
                status, ps_output = run_command_with_timeout(client, confirm_cmd, 5, hostname=host)
                stderr = ""
                
            if not status or ps_output.strip() != pid:
                print(f"{RED}[{host}] Process with PID {pid} is not running.{RESET}")
                print(f"{RED}[{host}] ps output:\n{ps_output.strip()}{RESET}")
                if stderr:
                    print(f"{RED}[{host}] STDERR: {stderr}{RESET}")
                print(f"{RED}Pre-experimentation phase failed for '{experiment_name}'.{RESET}")
                cleanup_logging_scripts(experiment_name, concurrency, iteration)
                if client: client.close()
                return False
        else:
            # For non-daemon processes like conntrackAnalysis.py, just check if it created output files
            output_file = f"/var/log/exp/{experiment_name}{concurrency}/{iteration}_ca.csv"
            check_cmd = f"ls -la {output_file}"
            if client is None:
                status, ls_output, stderr = run_command_locally(check_cmd, tag)
            else:
                status, ls_output = run_command_with_timeout(client, check_cmd, 5, hostname=host)
                stderr = ""
            
            if status and output_file in ls_output:
                print(f"{GREEN}[{host}] Non-daemon script '{program_file}' appears to have started successfully (output file exists).{RESET}")
            else:
                print(f"{YELLOW}[{host}] Non-daemon script '{program_file}' - output file not yet created, but this may be normal.{RESET}")
                # Don't fail for non-daemon scripts that might start later

        if client: client.close()

    print(f"{GREEN}Pre-experimentation phase completed successfully for '{experiment_name}{concurrency}/{iteration}'.{RESET}")
    
    # After setup, verify all critical processes are running
    verify_critical_processes_running(experiment_name, concurrency, iteration)
    
    return True

def periodic_progress_display(stop_event, interval_seconds):
    """Display progress every N seconds"""
    print(f"{MAGENTA}[progress] Starting periodic progress display (every {interval_seconds/60:.1f} minutes){RESET}")
    
    # Show initial status
    time.sleep(10)  # Wait 10 seconds before first display
    progress_tracker.force_display_progress()
    
    while not stop_event.is_set():
        # Wait for the interval or until stopped
        if stop_event.wait(interval_seconds):
            break  # Stop event was set
        
        # Display progress
        progress_tracker.force_display_progress()
    
    print(f"{MAGENTA}[progress] Periodic progress display stopped{RESET}")

def experimentation(experiment_name, concurrency, iteration):
    global monitoring_threads, monitoring_stop_events
    
    print(colored(f"[exp] Running experimentation for {experiment_name}{concurrency}/{iteration}...", BLUE))
    
    # Define log files to monitor - CORRECTED: cm_monitor and n_monitor are on connt1
    log_files_to_monitor = [
        {
            "filepath": f"/var/log/exp/{experiment_name}{concurrency}/{iteration}_ca.csv",
            "host": "convsrc2"  # This one is local to convsrc2
        },
        {
            "filepath": f"/var/log/exp/{experiment_name}{concurrency}/{iteration}_conntrackd_cm_monitor.csv", 
            "host": "connt1"    # This one is on connt1 (remote)
        },
        {
            "filepath": f"/var/log/exp/{experiment_name}{concurrency}/{iteration}_conntrackd_n_monitor.csv",
            "host": "connt1"    # This one is on connt1 (remote)  
        }
    ]

    print(colored("[exp] Starting log file monitoring in growth mode with 1.5-minute progress reports...", CYAN))
    
    # Reset progress tracker for this experiment
    progress_tracker.file_stats.clear()
    progress_tracker.start_time = time.time()
    progress_tracker.last_full_display = 0  # Reset display timer
    
    monitor_results = {}
    monitoring_threads = []
    monitoring_stop_events = []
    
    for i, log_info in enumerate(log_files_to_monitor):
        filepath = log_info["filepath"]
        host = log_info["host"]
        
        stop_event = threading.Event()
        monitoring_stop_events.append(stop_event)
        
        # Create monitoring thread with host-specific monitoring
        t = threading.Thread(
            target=monitor_remote_log_file,
            kwargs={
                "filepath": filepath,
                "host": host,
                "keyword_expr": "",      # Empty = Log Growth Mode
                "timeout": None,         # No timeout in growth mode
                "print_output": False,   # Don't spam with log content
                "result_dict": monitor_results,
                "stop_event": stop_event,
            },
            name=f"ExpMonitor-{host}-{os.path.basename(filepath)}"
        )
        monitoring_threads.append(t)
        t.start()
    
    # Start dedicated progress display thread for 1.5-minute reports (90 seconds)
    progress_display_stop = threading.Event()
    progress_thread = threading.Thread(
        target=periodic_progress_display,
        args=(progress_display_stop, 90),  # 90 seconds = 1.5 minutes
        name="PeriodicProgressDisplay"
    )
    progress_thread.start()
    
    print(colored("[exp] Step: Start Client Threads", BOLD))
    
    client_threads = get_client_threads(250000, concurrency, 4)
    for th in client_threads:
        th.start()

    for th in client_threads:
        th.join()

    print(colored("[exp] All client threads completed.", CYAN))
    print(colored("[exp] Continuing log monitoring for 500 seconds with 1.5-minute progress reports...", YELLOW))
    
    # Wait exactly 500 seconds (CHANGED FROM 1000) with periodic progress
    experiment_start = time.time()
    last_status_update = 0
    experiment_duration = 500  # CHANGED: 500 seconds instead of 1000
    
    while time.time() - experiment_start < experiment_duration:
        current_time = time.time()
        elapsed = current_time - experiment_start
        remaining = experiment_duration - elapsed
        
        # Status update every minute
        if elapsed - last_status_update >= 60:
            print(f"{YELLOW}[exp] Experiment running... {remaining/60:.1f} minutes remaining{RESET}")
            last_status_update = elapsed
        
        time.sleep(10)  # Check every 10 seconds
    
    # Stop all monitoring
    progress_display_stop.set()
    for stop_event in monitoring_stop_events:
        stop_event.set()
    
    # Wait for threads to complete
    progress_thread.join(timeout=10)
    for t in monitoring_threads:
        t.join(timeout=10)
    
    # Final comprehensive report
    print(colored("[exp] Generating final experiment report...", BLUE))
    progress_tracker.force_display_progress()
    
    print(colored("[exp] Experimentation monitoring completed after 500 seconds.", BLUE))
    
    # Clear global tracking
    monitoring_threads = []
    monitoring_stop_events = []
    
    return True

def post_experimentation(experiment_name, concurrency, iteration):
    global current_experiment_name, current_concurrency, current_iteration
    
    print(colored(f"[post-exp] Running post_experimentation for {experiment_name}{concurrency}/{iteration}...", MAGENTA))
    
    # Cleanup logging scripts and all monitoring processes
    cleanup_logging_scripts(experiment_name, concurrency, iteration)
    
    # Clear global tracking
    current_experiment_name = None
    current_concurrency = None
    current_iteration = None
    
    print(colored(f"[post-exp] Post-experimentation cleanup complete for '{experiment_name}{concurrency}/{iteration}'.{RESET}", MAGENTA))
    return True

def main():
    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    parser = argparse.ArgumentParser(description="Automation script for experiment.")
    parser.add_argument("--experiment-name", required=True, help="Name of the experiment.")
    parser.add_argument("--iterations", required=True, type=int, help="Number of iterations.")
    args = parser.parse_args()

    experiment_name = args.experiment_name
    iterations = args.iterations
    concurrency_values = [200, 500, 600]
    ssh_connector = SSHConnector()
    remote_hostname = "connt1"
    client = ssh_connector.connect(remote_hostname)
    tag = f"[{remote_hostname} ssh]" if client else "[localhost]"

    for c in concurrency_values:
        directory_cmd = f"sudo mkdir -p /var/log/exp/{experiment_name}{c}"
        if client is None:
            print(colored(f"{tag} Executing locally: {directory_cmd}", CYAN))
            subprocess.run(directory_cmd, shell=True, check=True)
        else:
            print(colored(f"{tag} Executing on remote host: {directory_cmd}", MAGENTA))
            stdin, stdout, stderr = client.exec_command(directory_cmd)
            exit_code = stdout.channel.recv_exit_status()
            if exit_code != 0:
                print(colored(f"{tag} Command failed with exit code {exit_code}: {stderr.read().decode()}", RED))

        for i in range(iterations):
            iteration_number = i + 1
            print(colored(f"[main] check iteration {iteration_number} with concurrency {c}...", YELLOW))
            x = check_function()
            if x == 4:
                print(colored(f"[main] pre-exp iteration {iteration_number} with concurrency {c}...", YELLOW))
                if pre_experimentation(experiment_name, c, iteration_number):
                    print(colored(f"[main] exp iteration {iteration_number} with concurrency {c}...", YELLOW))
                    if experimentation(experiment_name, c, iteration_number):
                        print(colored(f"[main] post-exp iteration {iteration_number} with concurrency {c}...", YELLOW))
                        post_experimentation(experiment_name, c, iteration_number)
                    else:
                        print(colored("[main] experimentation() reported an error. Exiting program.", RED))
                        sys.exit(1)
                else:
                    print(colored("[main] pre_experimentation() reported an error. Exiting program.", RED))
                    sys.exit(1)
            else:
                print(colored("[main] check_function() reported an error. Exiting program.", RED))
                sys.exit(1)
            time.sleep(1)

    if client is not None:
        client.close()

if __name__ == "__main__":
    main()
