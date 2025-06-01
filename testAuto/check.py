#!/usr/bin/env python3

import paramiko
import threading
import time
import os
import re

print_lock = threading.Lock()

GREEN = "\033[32m"
RED = "\033[31m"
BLUE = "\033[34m"
YELLOW = "\033[33m"
RESET = "\033[0m"

def load_ssh_config():
    ssh_config_file = os.path.expanduser("~/.ssh/config")
    config = paramiko.SSHConfig()
    if os.path.exists(ssh_config_file):
        with open(ssh_config_file, 'r') as f:
            config.parse(f)
    else:
        raise FileNotFoundError("SSH config file not found at ~/.ssh/config")
    return config

def connect_to_host(hostname):
    config = load_ssh_config()
    host_config = config.lookup(hostname)
    if not host_config:
        raise ValueError(f"No configuration found for {hostname}")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs = {
        "hostname": host_config.get("hostname", hostname),
        "username": host_config.get("user"),
        "port": int(host_config.get("port", 22)),
    }

    if "proxyjump" in host_config:
        proxy_host = host_config["proxyjump"]
        proxy_config = config.lookup(proxy_host)
        proxy_client = paramiko.SSHClient()
        proxy_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        proxy_client.connect(
            hostname=proxy_config.get("hostname", proxy_host),
            username=proxy_config.get("user"),
            port=int(proxy_config.get("port", 22)),
        )
        proxy_transport = proxy_client.get_transport()
        dest_addr = (connect_kwargs["hostname"], connect_kwargs["port"])
        local_addr = ("127.0.0.1", 0)
        proxy_channel = proxy_transport.open_channel("direct-tcpip", dest_addr, local_addr)
        connect_kwargs["sock"] = proxy_channel

    client.connect(**connect_kwargs)
    return client

def run_command_with_timeout(client, command, timeout, hostname="unknown"):
    """
    Run a command on a remote host with a timeout.
    """
    try:
        stdin, stdout, stderr = client.exec_command(command)
        start = time.time()
        while not stdout.channel.exit_status_ready():
            if time.time() - start > timeout:
                stdout.channel.close()
                with print_lock:
                    print(f"{RED}[{hostname}] Timeout exceeded while running: {command}{RESET}")
                return False, f"Timeout exceeded while running: {command}"
            time.sleep(0.5)
        out = stdout.read().decode()
        err = stderr.read().decode()
        return True, out if out else err
    except Exception as e:
        with print_lock:
            print(f"{RED}[{hostname}] Exception during command: {command}\n{e}{RESET}")
        return False, str(e)

def check_and_start_service(client, service, hostname, verbose=True):
    """
    Check if a service is running, start it if not.
    All output is prefixed with the device name.
    """
    success, output = run_command_with_timeout(client, f"systemctl is-active {service}", 5, hostname=hostname)
    if success and "active" in output:
        if verbose:
            with print_lock:
                print(f"{GREEN}[{hostname}] {service} is already running.{RESET}")
        return
    if verbose:
        with print_lock:
            print(f"{YELLOW}[{hostname}] {service} is not running. Attempting to start...{RESET}")
    success, output = run_command_with_timeout(client, f"sudo systemctl start {service}", 10, hostname=hostname)
    if success:
        with print_lock:
            print(f"{GREEN}[{hostname}] Started {service} successfully.{RESET}")
    else:
        with print_lock:
            print(f"{RED}[{hostname}] Failed to start {service}: {output}{RESET}")

def monitor_log_file(
    hostname: str,
    filepath: str,
    timeout: int,
    keyword_expr: str,
    truncate_file: bool = False,
    print_output: bool = True,
):
    """
    Monitor a remote log file for appearance of all keywords in `keyword_expr` (across any lines).
    Stop on first match (all keywords seen) or timeout.
    Returns matched line (last seen) or None.
    All output is prefixed with the device name.
    """
    with print_lock:
        print(f"{BLUE}[{hostname}] monitor_log_file thread started (watching {filepath}){RESET}")

    client = connect_to_host(hostname)

    # Truncate log file if requested
    if truncate_file:
        run_command_with_timeout(client, f"sudo truncate -s 0 {filepath}", 5, hostname=hostname)

    # Parse keywords from the expression
    keywords = set(re.findall(r"'(.*?)'", keyword_expr))
    seen = set()

    command = f"timeout {timeout}s sudo tail -F {filepath}"
    stdin, stdout, stderr = client.exec_command(command)

    matched_line = None
    start_time = time.time()
    progress_reported = set()
    while time.time() - start_time < timeout:
        elapsed = int(time.time() - start_time)
        line = stdout.readline()
        if not line:
            time.sleep(0.1)
            continue
        line = line.strip()
        for kw in keywords:
            if kw in line:
                seen.add(kw)
        if print_output:
            with print_lock:
                print(f"[{hostname}] LOG: {line}")
        if seen == keywords:
            matched_line = line
            if print_output:
                with print_lock:
                    print(f"{BLUE}[{hostname}] All keywords {keywords} found in {filepath}.{RESET}")
            break
        # Progress print every 5 seconds
        step = elapsed // 5
        if step not in progress_reported:
            progress_reported.add(step)
            with print_lock:
                print(f"{YELLOW}[{hostname}] monitor_log_file progress: {elapsed}/{timeout} seconds elapsed{RESET}")

    if seen != keywords and print_output:
        with print_lock:
            print(f"{RED}[{hostname}] Not all keywords {keywords} found in {filepath} within {timeout} seconds.{RESET}")

    stdout.channel.close()
    client.close()
    with print_lock:
        print(f"{BLUE}[{hostname}] monitor_log_file thread finished{RESET}")
    return matched_line

def build_and_run_client(
    hostname: str,
    command: str,
    check_stuck: bool = True,
    stuck_check_interval: int = 5,
    stuck_checks: int = 6,
    program_name: str = None,
    working_dir: str = "/opt/MasterThesis/trafGen",
):
    """
    Run a client command on a remote host, monitor for stuckness, and print output.
    - Only kill the process if it is still running and stuck.
    - If the process finishes naturally, print its output and exit.
    - All output is prefixed with the device name.
    """
    with print_lock:
        print(f"{BLUE}[{hostname}] build_and_run_client thread started (running '{command}') {RESET}")

    client = connect_to_host(hostname)
    program = program_name if program_name else command.split()[0].split("./")[-1]
    log_file = f"/tmp/{program}.log"
    pid_file = f"/tmp/{program}.pid"
    full_cmd = f"cd {working_dir} && nohup {command} > {log_file} 2>&1 & echo $! > {pid_file}"

    run_command_with_timeout(client, full_cmd, 5, hostname=hostname)
    status, output = run_command_with_timeout(client, f"cat {pid_file}", 5, hostname=hostname)
    pid = output.strip() if status else None

    last_lines = []
    same_count = 0

    start_time = time.time()
    progress_reported = set()
    while time.time() - start_time < 2 * 60:  # 20 minutes
        if not pid:
            break

        # Check if process is running
        ps_status, ps_output = run_command_with_timeout(client, f"ps -p {pid}", 5, hostname=hostname)
        is_running = ps_output and (re.search(rf"\b{pid}\b", ps_output) is not None)

        if not is_running:
            with print_lock:
                print(f"{GREEN}[{hostname}] {program} completed successfully.{RESET}")
            # Print log output
            success, final_out = run_command_with_timeout(client, f"cat {log_file}", 5, hostname=hostname)
            if success:
                with print_lock:
                    print(f"{YELLOW}[{hostname}] Final output from {program}:{RESET}\n{final_out}")
            break

        # Check for stuckness
        if check_stuck:
            out_status, out = run_command_with_timeout(client, f"tail -n 5 {log_file}", 5, hostname=hostname)
            if out_status:
                lines = out.splitlines()
                if lines == last_lines:
                    same_count += 1
                    if same_count >= stuck_checks:
                        with print_lock:
                            print(f"{RED}[{hostname}] {program} appears stuck. Killing it.{RESET}")
                        run_command_with_timeout(client, f"sudo kill {pid}", 5, hostname=hostname)
                        success, final_out = run_command_with_timeout(client, f"cat {log_file}", 5, hostname=hostname)
                        if success:
                            with print_lock:
                                print(f"{YELLOW}[{hostname}] Final output from {program}:{RESET}\n{final_out}")
                        break
                else:
                    last_lines = lines
                    same_count = 0

        # Progress print every 10 seconds
        elapsed = int(time.time() - start_time)
        step = elapsed // 10
        if step not in progress_reported:
            progress_reported.add(step)
            with print_lock:
                print(f"{YELLOW}[{hostname}] build_and_run_client progress: {elapsed} seconds elapsed{RESET}")

        time.sleep(stuck_check_interval)

    client.close()
    with print_lock:
        print(f"{BLUE}[{hostname}] build_and_run_client thread finished{RESET}")

def flush_conntrack_on_hosts(hosts):
    """
    Flush conntrack table on the given hosts in parallel.
    """
    def flush_conntrack(host):
        with print_lock:
            print(f"{BLUE}[{host}] Flushing conntrack table...{RESET}")
        client = connect_to_host(host)
        run_command_with_timeout(client, "sudo conntrack -F", 5, hostname=host)
        client.close()
        with print_lock:
            print(f"{GREEN}[{host}] Conntrack table flushed.{RESET}")

    threads = []
    for h in hosts:
        t = threading.Thread(target=flush_conntrack, args=(h,), name=f"FlushConntrack-{h}")
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    with print_lock:
        print(f"{GREEN}All conntrack tables flushed.{RESET}")

def main():
    # Phase 1: Check and start services
    service_map = {
        "convsrc5": ["tcp_server.service", "udp_server.service"],
        "convsrc8": ["tcp_server.service", "udp_server.service"],
        "connt1": ["ptpd2.service", "conntrack_logger.service"],
        "connt2": ["ptpd2.service", "conntrack_logger.service"],
    }

    threads = []
    for host, services in service_map.items():
        def check_services(hostname, services):
            with print_lock:
                print(f"{BLUE}[{hostname}] Service check thread started for {services}{RESET}")
            client = connect_to_host(hostname)
            for s in services:
                check_and_start_service(client, s, hostname)
            client.close()
            with print_lock:
                print(f"{BLUE}[{hostname}] Service check thread finished{RESET}")
        t = threading.Thread(target=check_services, args=(host, services), name=f"ServiceCheck-{host}")
        threads.append(t)
        with print_lock:
            print(f"{YELLOW}Starting thread: ServiceCheck-{host} for {services}{RESET}")
        t.start()
    for t in threads:
        with print_lock:
            print(f"{YELLOW}Joining thread: {t.name}{RESET}")
        t.join()

    # === New Phase: Flush conntrack on required hosts ===
    conntrack_hosts = ["connt1", "connt2"]
    flush_conntrack_on_hosts(conntrack_hosts)

    # === Wait 5 seconds before proceeding ===
    with print_lock:
        print(f"{YELLOW}Waiting 5 seconds after conntrack flush...{RESET}")
    time.sleep(5)

    # Monitor logs in parallel before running clients
    log_threads = [
        threading.Thread(
            target=monitor_log_file,
            kwargs=dict(
                hostname="convsrc2",
                filepath="/var/log/conntrack.log",
                timeout=30,
                keyword_expr="'connt1' AND 'connt2'",
                truncate_file=True,
                print_output=True
            ),
            name="Monitor-conntrack"
        ),
        threading.Thread(
            target=monitor_log_file,
            kwargs=dict(
                hostname="convsrc2",
                filepath="/var/log/ptp.log",
                timeout=30,
                keyword_expr="'connt1' AND 'connt2'",
                truncate_file=True,
                print_output=True
            ),
            name="Monitor-ptp"
        )
    ]
    for lt in log_threads:
        with print_lock:
            print(f"{YELLOW}Starting thread: {lt.name}{RESET}")
        lt.start()

    # Run TCP/UDP clients in parallel
    client_threads = [
        threading.Thread(
            target=build_and_run_client,
            kwargs=dict(
                hostname="convsrc1",
                command="sudo ./tcp_client_er -s 172.16.1.1 -p 2000 -n 10 -c 1 -w 1 -a 172.16.1.10-22 -k -r 10000-65000 -t 1"
            ),
            name="Client-tcp-convsrc1"
        ),
        threading.Thread(
            target=build_and_run_client,
            kwargs=dict(
                hostname="convsrc1",
                command="./udp_client_sub -s 172.16.1.1 -p 3000 -n 10 -c 1 -a 172.16.1.10-22 -r 10000-65000"
            ),
            name="Client-udp-convsrc1"
        ),
        threading.Thread(
            target=build_and_run_client,
            kwargs=dict(
                hostname="convsrc2",
                command="./udp_client_sub -s 172.16.1.1 -p 3000 -n 10 -c 1 -a 172.16.1.26-39 -r 10000-65000"
            ),
            name="Client-udp-convsrc2"
        ),
        threading.Thread(
            target=build_and_run_client,
            kwargs=dict(
                hostname="convsrc2",
                command="sudo ./tcp_client_er -s 172.16.1.1 -p 2000 -n 10 -c 1 -w 1 -a 172.16.1.26-39 -k -r 10000-65000 -t 1"
            ),
            name="Client-tcp-convsrc2"
        )
    ]
    for ct in client_threads:
        with print_lock:
            print(f"{YELLOW}Starting thread: {ct.name}{RESET}")
        ct.start()
    for ct in client_threads:
        with print_lock:
            print(f"{YELLOW}Joining thread: {ct.name}{RESET}")
        ct.join()

    for lt in log_threads:
        with print_lock:
            print(f"{YELLOW}Joining thread: {lt.name}{RESET}")
        lt.join()

    with print_lock:
        print(f"\n{GREEN}All processes complete.{RESET}")

if __name__ == "__main__":
    main()
