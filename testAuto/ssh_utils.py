#!/usr/bin/env python3

import os
import time
import socket
import paramiko
import subprocess
import threading
import logging
import random
import shlex

from config import (
    colored, RED, GREEN, YELLOW, BLUE, CYAN, MAGENTA, BOLD, RESET
)
from logging_utils import get_current_hostname

def retry_with_backoff(func, max_retries=3, initial_backoff=1, max_backoff=30):
    """Retry a function with exponential backoff"""
    retries = 0
    backoff = initial_backoff
    
    while retries < max_retries:
        try:
            return func()
        except Exception as e:
            retries += 1
            if retries >= max_retries:
                raise
            
            # Calculate backoff with jitter to avoid thundering herd
            jitter = random.uniform(0, 0.1 * backoff)
            sleep_time = min(backoff + jitter, max_backoff)
            
            logging.warning(f"Attempt {retries} failed: {str(e)}. Retrying in {sleep_time:.1f}s...")
            time.sleep(sleep_time)
            
            # Exponential backoff
            backoff *= 2

class SSHConnector:
    def __init__(self, ssh_config_path=None):
        self.ssh_config_path = ssh_config_path or os.path.expanduser("~/.ssh/config")
        self.config = self._load_ssh_config()
        self.local_hostnames = self._get_local_hostnames()

    def _load_ssh_config(self):
        if not os.path.exists(self.ssh_config_path):
            raise FileNotFoundError(f"{RED}SSH config file not found at {self.ssh_config_path}{RESET}")
        config = paramiko.SSHConfig()
        with open(self.ssh_config_path, 'r') as f:
            config.parse(f)
        return config

    def _get_local_hostnames(self):
        local_names = set()
        try:
            local_names.add(subprocess.check_output(['hostname'], text=True).strip())
        except Exception:
            pass
        local_names.update({"localhost", "127.0.0.1", socket.gethostname(), socket.getfqdn()})
        return local_names

    def connect(self, hostname):
        """Connect to SSH host with retry logic"""
        hostname_lower = hostname.lower()
        if hostname_lower in self.local_hostnames:
            current_host = get_current_hostname()
            logging.info(f"{CYAN}[{current_host} local check] Hostname '{hostname}' resolved as local machine. Using local connection.{RESET}")
            return None

        def connect_to_host():
            host_config = self.config.lookup(hostname)
            if not host_config:
                raise ValueError(f"{RED}No configuration found for {hostname}{RESET}")

            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs = {
                "hostname": host_config.get("hostname", hostname),
                "username": host_config.get("user"),
                "port": int(host_config.get("port", 22)),
                "timeout": 10,  # Set connection timeout
                "banner_timeout": 15,
            }

            if "proxyjump" in host_config:
                proxy_host = host_config["proxyjump"]
                proxy_config = self.config.lookup(proxy_host)
                proxy_client = paramiko.SSHClient()
                proxy_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                proxy_client.connect(
                    hostname=proxy_config.get("hostname", proxy_host),
                    username=proxy_config.get("user"),
                    port=int(proxy_config.get("port", 22)),
                    timeout=10,
                )
                proxy_transport = proxy_client.get_transport()
                dest_addr = (connect_kwargs["hostname"], connect_kwargs["port"])
                local_addr = ("127.0.0.1", 0)
                proxy_channel = proxy_transport.open_channel("direct-tcpip", dest_addr, local_addr)
                connect_kwargs["sock"] = proxy_channel

            client.connect(**connect_kwargs)
            return client
            
        # Use retry logic for SSH connections
        try:
            return retry_with_backoff(connect_to_host, max_retries=3, initial_backoff=2)
        except Exception as e:
            logging.error(f"Failed to connect to {hostname} after retries: {str(e)}")
            raise

def run_command_locally(cmd: str, hosttag="[localhost]"):
    logging.info(f"{CYAN}{hosttag} Executing:{RESET} {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return (result.returncode == 0, result.stdout, result.stderr)

def run_command_remotely(client, cmd: str, hosttag):
    logging.info(f"{MAGENTA}{hosttag} Executing:{RESET} {cmd}")
    stdin, stdout, stderr = client.exec_command(cmd)
    exit_code = stdout.channel.recv_exit_status()
    out = stdout.read().decode()
    err = stderr.read().decode()
    return (exit_code == 0, out, err)

def run_command_with_timeout(client, command, timeout, hostname="unknown"):
    """Run a command with timeout and better error handling"""
    if client is None:
        # Local execution
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout)
            return (result.returncode == 0, result.stdout)
        except subprocess.TimeoutExpired:
            logging.error(f"Command timed out after {timeout}s: {command}")
            return (False, f"Timeout exceeded ({timeout}s)")
        except Exception as e:
            logging.error(f"Error running command locally: {str(e)}")
            return (False, str(e))
    else:
        # Remote execution
        try:
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            start = time.time()
            
            # Use select-like wait for exit with timeout
            channel = stdout.channel
            while not channel.exit_status_ready():
                if time.time() - start > timeout:
                    channel.close()
                    logging.error(f"{RED}[{hostname}] Timeout exceeded while running: {command}{RESET}")
                    return False, f"Timeout exceeded while running: {command}"
                time.sleep(0.5)
            
            exit_status = channel.recv_exit_status()
            out = stdout.read().decode()
            err = stderr.read().decode()
            
            # Only log errors for non-pgrep commands
            if exit_status != 0 and 'pgrep' not in command:
                logging.error(f"Command failed with exit status {exit_status}: {command}")
                logging.error(f"Error output: {err}")
            
            return (exit_status == 0, out if out else err)
        except Exception as e:
            logging.error(f"{RED}[{hostname}] Exception during command: {command}\n{e}{RESET}")
            return False, str(e)

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
            logging.info(f"{YELLOW}[{host}] Found running '{prog}' with PIDs: {', '.join(pids)}. Killing...{RESET}")
            for pid in pids:
                kill_cmd = f"sudo kill -9 {pid}"
                if client is None:
                    run_command_locally(kill_cmd, f"[{host} localhost]")
                else:
                    run_command_with_timeout(client, kill_cmd, 5, hostname=host)
            time.sleep(1)
        else:
            logging.info(f"{GREEN}[{host}] No '{prog}' processes running.{RESET}")

def force_kill_all_monitoring_processes():
    """Force kill all monitoring processes across all hosts"""
    logging.info(f"{MAGENTA}[cleanup] Force killing all monitoring processes...{RESET}")
    
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
            
        logging.info(f"{YELLOW}[cleanup] [{host}] Force killing monitoring processes...{RESET}")
        client = ssh_connector.connect(host)
        tag = f"[{host} ssh]" if client else f"[{host} localhost]"
        
        for process in processes:
            # First try SIGTERM
            kill_cmd = f"sudo pkill -f {process}"
            if client is None:
                run_command_locally(kill_cmd, tag)
            else:
                run_command_with_timeout(client, kill_cmd, 3, hostname=host)
            
            time.sleep(1)
            
            # Then force kill with SIGKILL
            force_kill_cmd = f"sudo pkill -9 -f {process}"
            if client is None:
                run_command_locally(force_kill_cmd, tag)
            else:
                run_command_with_timeout(client, force_kill_cmd, 3, hostname=host)
            
            logging.info(f"{GREEN}[cleanup] [{host}] Force killed {process}{RESET}")
        
        if client:
            client.close()
    
    logging.info(f"{GREEN}[cleanup] Force kill completed for all monitoring processes.{RESET}")

class RemoteProgramRunner:
    def __init__(
        self,
        hostname: str,
        command: str,
        working_dir: str = "/opt/MasterThesis/trafGen",
        check_stuck: bool = True,
        stuck_check_interval: int = 5,
        stuck_check_idle_threshold: int = 30,
        timeout: int = 60,
        max_duration: int = 120,
        cleanup: bool = False,
        verbose: bool = False,
        program_name: str = None,
    ):
        self.hostname                = hostname
        self.command                 = command
        self.working_dir             = working_dir
        self.check_stuck             = check_stuck
        self.stuck_check_interval    = stuck_check_interval
        self.stuck_check_idle_threshold = stuck_check_idle_threshold
        self.timeout                 = timeout
        self.max_duration            = max_duration
        self.cleanup                 = cleanup
        self.verbose                 = verbose
        self.program_name            = program_name or self._extract_program_name()
        self.log_file                = f"/tmp/exp/{self.program_name}.log"
        self.pid_file                = f"/tmp/exp/{self.program_name}.pid"
        self.client                  = None
        self.pid                     = None
        self.result                  = {
            "hostname": hostname,
            "status":   "unknown",
            "output":   "",
            "error":    "",
            "pid":      None,
            "log_file": self.log_file,
        }

    def _extract_program_name(self):
        tokens = shlex.split(self.command)
        for token in tokens:
            if token not in {"sudo", "env", "bash", "sh"} and not token.startswith("-"):
                return os.path.basename(token)
        return "unknown_program"

    def log(self, msg):
        current_host = get_current_hostname()
        logging.info(f"{BLUE}[{current_host} local check] {self.hostname}: {msg}{RESET}")

    def connect(self):
        connector = SSHConnector()
        self.client = connector.connect(self.hostname)
        return self.client is not None

    def run_command(self, cmd, timeout=None, verbose=None):
        if self.client is None:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout or self.timeout)
            return (result.returncode == 0, result.stdout, result.stderr)
        else:
            try:
                stdin, stdout, stderr = self.client.exec_command(cmd, timeout=timeout or self.timeout)
                stdout.channel.settimeout(timeout or self.timeout)
                stderr.channel.settimeout(timeout or self.timeout)
                exit_code = stdout.channel.recv_exit_status()
                return (exit_code == 0, stdout.read().decode(), stderr.read().decode())
            except socket.timeout:
                return (False, "", "SSH command timed out")
            except Exception as e:
                return (False, "", str(e))

    def launch(self):
        full_cmd = f"cd {self.working_dir} && nohup {self.command} > {self.log_file} 2>&1 & echo $! > {self.pid_file} && echo $!"
        
        try:
            status, output, err = self.run_command(full_cmd, timeout=15)
            if not status:
                self.result.update({"status": "launch_failed", "error": err})
                return False
            
            lines = output.strip().split('\n')
            for line in lines:
                if line.strip().isdigit():
                    self.pid = line.strip()
                    self.result["pid"] = self.pid
                    return True
            
            time.sleep(2)
            status, pid_out, err = self.run_command(f"cat {self.pid_file}", timeout=5)
            if status and pid_out.strip().isdigit():
                self.pid = pid_out.strip()
                self.result["pid"] = self.pid
                return True
            
            self.result.update({"status": "pid_fetch_failed", "error": f"Could not get PID. Output: {output}"})
            return False
            
        except Exception as e:
            self.result.update({"status": "launch_failed", "error": str(e)})
            return False

    def is_process_running(self):
        if not self.pid:
            return False
        ps_status, ps_out, _ = self.run_command(f"ps -p {self.pid}", timeout=5)
        return ps_status and bool(self.pid in ps_out)

    def is_stuck(self):
        stat_cmd = f"stat -c %Y {self.log_file}"
        stat_status, mtime_str, _ = self.run_command(stat_cmd, timeout=5)
        if stat_status and mtime_str.strip().isdigit():
            last_modified = int(mtime_str.strip())
            idle_time = time.time() - last_modified
            return idle_time >= self.stuck_check_idle_threshold
        return False

    def kill(self):
        if self.pid:
            self.run_command(f"sudo kill {self.pid}", timeout=5)
            self.result["status"] = "killed_stuck"

    def collect_logs(self):
        success, final_out, _ = self.run_command(f"cat {self.log_file}", timeout=10)
        if success:
            self.result["output"] = final_out

    def cleanup_files(self):
        self.run_command(f"rm -f {self.pid_file}", timeout=5)

    def run(self):
        self.log(f"{BOLD}Starting: {self.command}{RESET}")

        if not self.connect():
            self.result["status"] = "connection_failed"
            return self.result

        if not self.launch():
            if self.client:
                self.client.close()
            return self.result

        start_time = time.time()
        while time.time() - start_time < self.max_duration:
            if not self.is_process_running():
                self.result["status"] = "completed"
                self.collect_logs()
                break

            if self.check_stuck and self.is_stuck():
                self.log(f"{RED}{self.program_name} appears stuck. Killing it.{RESET}")
                self.kill()
                self.collect_logs()
                break

            elapsed = int(time.time() - start_time)
            if elapsed % 30 == 0:
                self.log(f"{YELLOW}Running... {elapsed}s elapsed{RESET}")

            time.sleep(self.stuck_check_interval)
        else:
            self.log(f"{RED}Timeout reached. Killing process.{RESET}")
            self.kill()
            self.result["status"] = "timeout"

        if self.cleanup:
            self.cleanup_files()

        if self.client:
            self.client.close()
        self.log(f"{BOLD}Finished with status: {self.result['status']}{RESET}")
        return self.result

def get_client_threads(concurrency_n, concurrency_c, tcp_timeout_t):
    """Get client threads for the experiment"""
    client_threads = [
        threading.Thread(
            target=build_and_run_client,
            kwargs=dict(
                hostname="convsrc1",
                command=f"sudo ./tcp_client_er -s 172.16.1.1 -p 2000 -n {concurrency_n} -c {concurrency_c} -w 1 -a 172.16.1.10-22 -k -r 10000-65000 -t {tcp_timeout_t}"
            ),
            name="Client-tcp-convsrc1"
         )#,
        # threading.Thread(
        #     target=build_and_run_client,
        #     kwargs=dict(
        #         hostname="convsrc1",
        #         command=f"./udp_client_sub -s 172.16.1.1 -p 3000 -n {concurrency_n} -c {concurrency_c} -a 172.16.1.10-22 -r 10000-65000"
        #     ),
        #     name="Client-udp-convsrc1"
        # )
    ]
    return client_threads

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
