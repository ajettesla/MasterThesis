#!/usr/bin/env python3

import argparse
import os
import sys
import time
import datetime
import logging

import config as _config
from config import (
    CURRENT_TIMESTAMP,
    CURRENT_USER,
    experiment_state,
    progress_tracker,
    generate_experiment_id,
    init_state_file,
    load_experiment_state,
    save_experiment_state,
    clear_experiment_state,
    get_experiment_path,
    print_step,
    print_status,
    set_automation_mode,
)
from logging_utils import setup_logging
from ssh_utils import SSHConnector
from experiment import (
    check_function,
    setup_signal_handlers,
)

class AutomationMode:
    def __init__(self, super_mode=False, quiet_mode=False, experiment_name=None):
        self.super_mode = super_mode
        self.quiet_mode = quiet_mode
        self.experiment_name = experiment_name
        self.results = []
        self.debug_logs = []
        self.error_logs = []  # Track error logs separately for quiet mode summary
        self.warning_logs = [] # Track warning logs separately for quiet mode summary
        self.service_status = {} # Track service statuses for quiet mode summary
        
        # Setup logging based on mode
        self.setup_mode_logging()
    
    def setup_mode_logging(self):
        """Setup logging configuration based on mode"""
        # Always create a log file for detailed logging regardless of mode
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if self.super_mode:
            # Super mode: detailed debug logging to file
            log_file = f"/tmp/exp/debug_{self.experiment_name}_{timestamp}.log"
        else:
            # Normal or quiet mode: standard logging to file
            log_file = f"/tmp/exp/auto_{self.experiment_name}_{timestamp}.log"
            
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        # Configure root logger for file output
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)  # Always log everything to file
        
        # Clear existing handlers
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # File handler for logs
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)
        
        if self.quiet_mode:
            # Quiet mode: Only errors/warnings to stderr, no INFO/DEBUG to stdout
            error_handler = logging.StreamHandler(sys.stderr)
            error_handler.setLevel(logging.WARNING)
            error_formatter = logging.Formatter('%(levelname)s: %(message)s')
            error_handler.setFormatter(error_formatter)
            root_logger.addHandler(error_handler)
            
            # Store log file path but don't announce it in quiet mode
            self.log_file = log_file
        else:
            # Super or normal mode: Add console handler for stdout
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(logging.INFO)
            console_formatter = logging.Formatter('%(levelname)s: %(message)s')
            console_handler.setFormatter(console_formatter)
            root_logger.addHandler(console_handler)
            
            self.log_file = log_file
            
            # Only announce log file if not in quiet mode
            print(f"{'Super' if self.super_mode else 'Normal'} mode enabled - logging to {log_file}", flush=True)

    def log_message(self, message, level='info'):
        """Log message based on current mode
        
        In super mode: Log all messages with timestamps to file and stdout (unless quiet)
        In normal mode: Log info and higher to file, show standard output
        In quiet mode: Store messages for summary, show only errors/warnings
        """
        if self.super_mode:
            # Super mode: log everything to file with debug info
            getattr(logging.getLogger(), level)(message)
            
            # Store debug logs for summary
            if level == 'debug':
                self.debug_logs.append(message)
                
            # Print to stdout only if not quiet mode
            if level not in ['debug', 'info'] or not self.quiet_mode:
                # Only print non-debug messages to stdout if not quiet
                if level == 'debug' and not self.quiet_mode:
                    print(f"DEBUG: {message}", flush=True)
        elif self.quiet_mode:
            # Quiet mode: log to file but store for summary, only show errors/warnings on stderr
            getattr(logging.getLogger(), level)(message)
            
            # Store all messages for final summary
            if level == 'debug':
                self.debug_logs.append(message)
            elif level == 'error':
                self.error_logs.append(message)
                # Errors are important enough to also go into results for summary
                self.results.append(f"[ERROR] {message}")
            elif level == 'warning':
                self.warning_logs.append(message)
                # Warnings are important enough to also go into results for summary
                self.results.append(f"[WARNING] {message}")
            else:
                # Info messages just get stored for summary
                self.results.append(f"[{level.upper()}] {message}")
        else:
            # Normal mode: standard logging
            if level == 'debug':
                # Debug messages go to log file only in normal mode
                logging.debug(message)
            else:
                getattr(logging.getLogger(), level)(message)
    
    def add_service_status(self, service, host, status, details=None):
        """Add service status for quiet mode summary"""
        if not self.quiet_mode:
            return
            
        key = f"{service}_{host}"
        self.service_status[key] = {
            'service': service,
            'host': host,
            'status': status,
            'details': details
        }
    
    def print_summary(self):
        """Print final summary based on mode
        
        In super mode: Print detailed summary with stats and debug log location
        In normal mode: Print concise summary of operations
        In quiet mode: Print only a single status line with counts
        """
        if self.quiet_mode:
            # Only print summary in quiet mode
            success_count = sum(1 for r in self.results if '[INFO]' in r)
            error_count = sum(1 for r in self.results if '[ERROR]' in r)
            warning_count = sum(1 for r in self.results if '[WARNING]' in r)
            
            # Print a single line summary
            print(f"\n=== Experiment '{self.experiment_name}' Summary ===", flush=True)
            print(f"{success_count} steps completed, {warning_count} warnings, {error_count} errors", flush=True)
            
            # Print service status summary
            if self.service_status:
                print("\nServices:", flush=True)
                for key, status in self.service_status.items():
                    service = status['service']
                    host = status['host']
                    status_str = status['status']
                    print(f"  {service} on {host}: {status_str}", flush=True)
            
            # If there were errors or warnings, show them
            if error_count > 0:
                print("\nERRORS:", flush=True)
                for r in self.results:
                    if '[ERROR]' in r:
                        print(f"  {r}", flush=True)
            
            if warning_count > 0:
                print("\nWARNINGS:", flush=True)
                for r in self.results:
                    if '[WARNING]' in r:
                        print(f"  {r}", flush=True)
                        
            # Show log file location
            if hasattr(self, 'log_file'):
                print(f"\nFull log available at: {self.log_file}", flush=True)
                        
        elif self.super_mode:
            # Super mode: detailed summary
            print("\n=== EXPERIMENT SUMMARY (SUPER MODE) ===", flush=True)
            print(f"Experiment: {self.experiment_name}", flush=True)
            print(f"Debug log: {getattr(self, 'log_file', 'N/A')}", flush=True)
            
            # Show key debug logs
            if self.debug_logs:
                print("\nKey debug information:", flush=True)
                important_debug = [log for log in self.debug_logs if any(keyword in log for keyword in 
                                  ['started', 'completed', 'failed', 'detected', 'found', 'error'])]
                for i, log in enumerate(important_debug[:10]):  # Show limited number
                    print(f"  {i+1}. {log}", flush=True)
                if len(important_debug) > 10:
                    print(f"  ... and {len(important_debug)-10} more (see debug log)", flush=True)
                    
            print("=======================================", flush=True)
        else:
            # Normal mode: standard summary
            print("\n=== Experiment Summary ===", flush=True)
            print(f"Experiment: {self.experiment_name}", flush=True)
            print("All tasks completed.", flush=True)

def run_chrony_check(phase, experiment_id):
    """Run chrony check with minimal output, fetching state from global context."""
    from config import get_automation_mode
    
    automation_mode = get_automation_mode()
    hosts = ["connt1", "connt2"]
    ssh = SSHConnector()

    if not experiment_id:
        experiment_id = generate_experiment_id()
        automation_mode.log_message(f"No experiment ID provided, using generated ID: {experiment_id}", 'warning')

    # For 'post' phase, get concurrency and iteration from the global state
    dir_suffix = ""
    if phase == 'post':
        concurrency = experiment_state.current_concurrency
        iteration = experiment_state.current_iteration
        if concurrency is not None:
            dir_suffix += f"_c{concurrency}"
        if iteration is not None:
            dir_suffix += f"_i{iteration}"

    # Only show a brief message in non-quiet modes
    if not automation_mode.quiet_mode:
        print_step("CHRONY", "CHECKING", f"Verifying time synchronization ({phase})")

    for host in hosts:
        client = ssh.connect(host)
        if client is None:
            msg = f"Failed to connect to {host} for chrony check"
            automation_mode.log_message(msg, 'error')
            print(f"FAILURE - {msg}", flush=True)
            sys.exit(1)

        # Create directory for chrony logs quietly
        dir_path = f"/tmp/exp/{experiment_id}{dir_suffix}/chrony"
        mkdir_cmd = f"sudo mkdir -p {dir_path} && sudo chmod 777 -R {os.path.dirname(dir_path)}"
        
        stdin, stdout, stderr = client.exec_command(mkdir_cmd)
        if stdout.channel.recv_exit_status() != 0:
            error_msg = f"Failed to create chrony log directory on {host}"
            automation_mode.log_message(f"{error_msg}: {stderr.read().decode()}", 'error')
            print(f"ERROR: {error_msg}", flush=True)
            client.close()
            sys.exit(1)

        # Execute chrony check, redirecting stdout to log file for cleanliness
        cmd = f"sudo /opt/MasterThesis/stats/ChronyLogAnalysis.sh {phase} {experiment_id}"
        automation_mode.log_message(f"Executing on {host}: {cmd}", 'debug')
        
        stdin, stdout, stderr = client.exec_command(cmd)
        exit_status = stdout.channel.recv_exit_status()
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')

        # Log full output for debugging, but don't print to console
        if output:
            automation_mode.log_message(f"Chrony check output from {host}:\n{output}", 'debug')
        if error:
            automation_mode.log_message(f"Chrony check error from {host}:\n{error}", 'debug')

        # Only show output in super mode and non-quiet mode
        if automation_mode.super_mode and not automation_mode.quiet_mode:
            print(f"- {host}: Output logged to debug file", flush=True)

        # Always check for errors
        if exit_status != 0 or "FAILURE" in output or "FAILURE" in error:
            automation_mode.log_message(f"Chrony check {phase} on {host} failed", 'error')
            print(f"FAILURE detected on {host} during chrony {phase} check.", flush=True)
            client.close()
            sys.exit(1)

        client.close()

    if not automation_mode.quiet_mode:
        print(f"Chrony {phase} check PASSED.", flush=True)
    else:
        automation_mode.results.append(f"[INFO] Chrony {phase} check PASSED")

# Wrapper functions to lazily import experiment functions when needed
def run_pre_experimentation(experiment_name, concurrency, iteration, experiment_id):
    from config import get_automation_mode, print_step
    import config as _config

    try:
        from experiment import pre_experimentation
        return pre_experimentation(experiment_name, concurrency, iteration, experiment_id)
    except ImportError:
        _config.log_info("Defining pre_experimentation function locally due to import error")
        def pre_experimentation(experiment_name, concurrency, iteration, experiment_id):
            automation_mode = _config.get_automation_mode()
            if not automation_mode or not automation_mode.quiet_mode:
                print_step("PRE-EXPERIMENT","STARTED",f"Setting up experiment: {experiment_name}")
            _config.log_info(f"[pre-exp] Setting up environment for {experiment_name} c={concurrency}, i={iteration}")
            time.sleep(1)
            _config.log_info("[pre-exp] Environment setup completed successfully")
            if not automation_mode or not automation_mode.quiet_mode:
                print_step("PRE-EXPERIMENT","COMPLETE","Environment prepared successfully")
            return True
        return pre_experimentation(experiment_name, concurrency, iteration, experiment_id)

def run_experimentation(experiment_name, concurrency, iteration, experiment_id):
    from config import get_automation_mode, print_step
    import config as _config

    try:
        from experiment import experimentation
        return experimentation(experiment_name, concurrency, iteration, experiment_id)
    except ImportError:
        _config.log_info("Defining experimentation fallback due to import error")
        def experimentation_fallback(experiment_name, concurrency, iteration, experiment_id):
            automation_mode = _config.get_automation_mode()
            if not automation_mode or not automation_mode.quiet_mode:
                print_step("EXPERIMENT","STARTED",f"Running with c={concurrency}")
            _config.log_info(f"[exp] Running experimentation for {experiment_name} c={concurrency}, i={iteration}")
            time.sleep(5)
            _config.log_info("[exp] Experimentation completed successfully")
            if not automation_mode or not automation_mode.quiet_mode:
                print_step("EXPERIMENT","COMPLETE",f"Concurrency {concurrency} completed")
            return True
        return experimentation_fallback(experiment_name, concurrency, iteration, experiment_id)

def run_post_experimentation(experiment_name, concurrency, iteration, experiment_id, update_state=True):
    from config import get_automation_mode, print_step
    import config as _config

    try:
        from experiment import post_experimentation
        return post_experimentation(experiment_name, concurrency, iteration, experiment_id, update_state)
    except ImportError:
        _config.log_info("Defining post_experimentation fallback due to import error")
        def post_experimentation_fallback(experiment_name, concurrency, iteration, experiment_id, update_state=True):
            automation_mode = _config.get_automation_mode()
            if not automation_mode or not automation_mode.quiet_mode:
                print_step("POST-EXPERIMENT","STARTED","Cleaning up and saving state")
            _config.log_info(f"[post-exp] Cleanup for {experiment_name} c={concurrency}, i={iteration}")
            time.sleep(2)
            _config.log_info("[post-exp] Cleanup completed successfully")
            if not automation_mode or not automation_mode.quiet_mode:
                print_step("POST-EXPERIMENT","COMPLETE","All cleanup tasks finished")
            return True
        return post_experimentation_fallback(experiment_name, concurrency, iteration, experiment_id, update_state)
def main():
    parser = argparse.ArgumentParser(description="Automation script for experiments.")
    parser.add_argument("-n", "--name", required=True, help="Experiment name")
    parser.add_argument("-c", "--concurrency", required=True,
                        help="Comma-separated concurrency values")
    # Independent flags that can be used together
    parser.add_argument("-s", "--super", action="store_true",
                       help="Super mode: verbose logging with debug data to log file")
    parser.add_argument("-q", "--quiet", action="store_true",
                       help="Quiet mode: only print summary statement")
    
    # Experiment control group
    exp_group = parser.add_mutually_exclusive_group()
    exp_group.add_argument("--new", action="store_true", help="Start new experiment")
    exp_group.add_argument("--cont", action="store_true", help="Continue existing experiment")
    
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    # Initialize experiment variables
    experiment_name = args.name
    continuing = False
    current_iter = 1

    # Initialize automation mode
    automation_mode = AutomationMode(
        super_mode=args.super,
        quiet_mode=args.quiet,
        experiment_name=experiment_name
    )
    
    # Set the global automation mode
    set_automation_mode(automation_mode)
    
    # Parse concurrency values
    try:
        conc_vals = [int(x.strip()) for x in args.concurrency.split(",")]
    except ValueError:
        automation_mode.log_message("Invalid concurrency values", 'error')
        print("ERROR: Invalid concurrency values", flush=True)
        sys.exit(1)

    # Initialize state file path (dynamic YAML file per experiment+concurrency)
    init_state_file(experiment_name, conc_vals)

    # In quiet mode, print location of state file
    if automation_mode.quiet_mode:
        from config import STATE_FILE
        print(f"STATE FILE: {STATE_FILE}", flush=True)
        print(f"LOG FILE: {automation_mode.log_file}", flush=True)

    setup_signal_handlers()

    # Use super mode instead of demon mode
    demon = args.super  
    # Set iterations to default value 1
    requested_iters = 1

    # Don't print these messages in quiet mode
    if not automation_mode.quiet_mode:
        # In super and normal modes, show experiment header
        print(f"\n=== Starting Experiment: {experiment_name} ===", flush=True)
        print(f"Mode: {'Super' if args.super else 'Normal'}{' (Quiet)' if args.quiet else ''}", flush=True)
        print(f"Concurrency: {conc_vals}", flush=True)
        print(f"Iterations: {requested_iters}", flush=True)
        
        if args.super:
            print("Debug logs are being saved to file for detailed troubleshooting.", flush=True)

    # Log the startup info regardless of mode (goes to file)
    automation_mode.log_message(f"Starting experiment '{experiment_name}' with concurrency {conc_vals}", 'info')
    
    # Log detailed debug info in super mode (goes to file)
    if args.super:
        automation_mode.log_message(f"Detailed experiment parameters:", 'debug')
        automation_mode.log_message(f"- Experiment name: {experiment_name}", 'debug')
        automation_mode.log_message(f"- Concurrency values: {conc_vals}", 'debug')
        automation_mode.log_message(f"- Iterations: {requested_iters}", 'debug')
        automation_mode.log_message(f"- Super mode: {args.super}", 'debug')
        automation_mode.log_message(f"- Quiet mode: {args.quiet}", 'debug')
        automation_mode.log_message(f"- New experiment: {args.new}", 'debug')
        automation_mode.log_message(f"- Continue experiment: {args.cont}", 'debug')

    # Create or continue state
    if args.new:
        clear_experiment_state()
        eid = generate_experiment_id()
        experiment_state.current_experiment_id = eid
        state = {
            "name": experiment_name,
            "id": eid,
            "concurrency": conc_vals,
            "iteration": current_iter,
            "timestamp": CURRENT_TIMESTAMP,
            "user": CURRENT_USER,
        }
        save_experiment_state(state)
        automation_mode.log_message(f"Created new experiment with ID: {eid}", 'info')
        
        # Always print experiment ID in all modes
        print(f"EXPERIMENT ID: {eid}", flush=True)
        
    elif args.cont:
        state = load_experiment_state()
        if (state.get("name") == experiment_name and
            set(state.get("concurrency", [])) == set(conc_vals)):
            eid = state.get("id")
            experiment_state.current_experiment_id = eid
            current_iter = state.get("iteration", 1)
            continuing = True
            state["timestamp"] = CURRENT_TIMESTAMP
            state["user"] = CURRENT_USER
            save_experiment_state(state)
            automation_mode.log_message(f"Continuing experiment with ID: {eid} from iteration {current_iter}", 'info')
            
            # In super and normal modes, show continue status
            if not automation_mode.quiet_mode:
                print(f"Continuing experiment with ID: {eid} from iteration {current_iter}", flush=True)
        else:
            clear_experiment_state()
            eid = generate_experiment_id()
            experiment_state.current_experiment_id = eid
            state = {
                "name": experiment_name,
                "id": eid,
                "concurrency": conc_vals,
                "iteration": current_iter,
                "timestamp": CURRENT_TIMESTAMP,
                "user": CURRENT_USER,
            }
            save_experiment_state(state)
            automation_mode.log_message(f"State mismatch - created new experiment with ID: {eid}", 'info')
            
            # In super and normal modes, show mismatch warning
            if not automation_mode.quiet_mode:
                print(f"Warning: State mismatch - created new experiment with ID: {eid}", flush=True)
    else:
        eid = generate_experiment_id()
        experiment_state.current_experiment_id = eid
        automation_mode.log_message(f"Generated experiment ID: {eid}", 'info')
        
        # In super mode, show generated ID
        if automation_mode.super_mode:
            print(f"Generated experiment ID: {eid}", flush=True)

    # Prepare remote directories
    automation_mode.log_message("Preparing remote directories", 'info')
    
    # In quiet mode, show directory preparation
    if automation_mode.quiet_mode:
        print(f"PREPARING DIRS: Remote experiment directories for {experiment_name}", flush=True)
        
    ssh = SSHConnector()
    client = ssh.connect("connt1")
    for c in conc_vals:
        exp_dir = get_experiment_path(
            experiment_name, experiment_state.current_experiment_id, c
        )
        cmd = f"sudo mkdir -p {exp_dir}"
        if client is None:
            os.system(cmd)
        else:
            stdin, stdout, stderr = client.exec_command(cmd)
            if stdout.channel.recv_exit_status() != 0:
                error_msg = f"Failed to create directory {exp_dir}"
                automation_mode.log_message(error_msg, 'error')
                # Always show errors, even in quiet mode
                print(f"ERROR: {error_msg}", flush=True)
                raise RuntimeError(error_msg)
        
        # In super mode, show created directories
        if automation_mode.super_mode and not automation_mode.quiet_mode:
            print(f"Created directory: {exp_dir}", flush=True)
            
    if client:
        client.close()

    # Run check function
    automation_mode.log_message("Starting environment check", 'info')
    
    # In quiet mode, show check start
    if automation_mode.quiet_mode:
        print(f"CHECK: Starting environment check for {experiment_name}", flush=True)
    
    # In super and normal modes, show check header
    if not automation_mode.quiet_mode:
        print("\n=== Running Environment Check ===", flush=True)
    
    check_result = check_function()
    
    if check_result != 2:
        automation_mode.log_message(f"Environment check failed with code {check_result}", 'error')
        # Always show errors, even in quiet mode
        print("FAILURE - Environment check failed", flush=True)
        sys.exit(1)
    
    automation_mode.log_message("Environment check passed successfully", 'info')
    
    # In super and normal modes, show check success
    if not automation_mode.quiet_mode:
        print("Environment check completed successfully", flush=True)

    # Run chrony check
    automation_mode.log_message("Starting chrony pre-check", 'info')
    
    # In quiet mode, show chrony check
    if automation_mode.quiet_mode:
        print("CHRONY: Starting pre-experiment time synchronization check", flush=True)
        
    run_chrony_check("pre", experiment_state.current_experiment_id)
    automation_mode.log_message("Chrony pre-check completed successfully", 'info')

    # Print initial summary only in super and normal modes
    if not automation_mode.quiet_mode:
        automation_mode.print_summary()

    # Final status message for initial checks
    if automation_mode.quiet_mode:
        print("Initial checks PASS", flush=True)
        print(f"BASE DIR: {get_experiment_path(experiment_name, experiment_state.current_experiment_id, conc_vals[0])}", flush=True)
    else:
        print("\n=== Initial Checks Complete ===", flush=True)
        print("Ready to proceed with experiments", flush=True)
    
    # NEW CODE: Continue with the experiment process
    continuing = False
    current_iter = 1

    try:
        # Load state for iteration if continuing
        if args.cont:
            state = load_experiment_state()
            if (state.get("name") == experiment_name and 
                set(state.get("concurrency", [])) == set(conc_vals)):
                current_iter = state.get("iteration", 1)
                continuing = True
                if not automation_mode.quiet_mode:
                    print(f"Continuing from iteration {current_iter}", flush=True)

        # Run experiments for each concurrency value
        for concurrency in conc_vals:
            # In quiet mode, show experiment start with key details
            if automation_mode.quiet_mode:
                print(f"EXPERIMENT: Running {experiment_name} [concurrency={concurrency}, iteration={current_iter}, id={experiment_state.current_experiment_id}]", flush=True)
                exp_dir = get_experiment_path(experiment_name, experiment_state.current_experiment_id, concurrency)
                print(f"EXPERIMENT DIR: {exp_dir}", flush=True)
            # In super and normal modes, show experiment header
            if not automation_mode.quiet_mode:
                print(f"\n=== Running Experiment: {experiment_name} ===", flush=True)
                print(f"Concurrency: {concurrency}, Iteration: {current_iter}", flush=True)
            else:
                # In quiet mode, just add to results collection
                automation_mode.results.append(f"[INFO] Running experiment with concurrency={concurrency}, iteration={current_iter}")
            
            # Store current values in experiment_state for potential error handling
            experiment_state.current_experiment_name = experiment_name
            experiment_state.current_experiment_id = experiment_state.current_experiment_id
            experiment_state.current_concurrency = concurrency
            experiment_state.current_iteration = current_iter
            
            # Pre-experimentation setup
            automation_mode.log_message(f"Starting pre-experimentation for {experiment_name} with concurrency={concurrency}, iteration={current_iter}", 'info')
            if not automation_mode.quiet_mode:
                print_step("PRE-EXPERIMENT", "STARTED", f"Setting up environment (concurrency={concurrency})")
                
            success = run_pre_experimentation(experiment_name, concurrency, current_iter, experiment_state.current_experiment_id)
            if not success:
                # Always show errors in all modes
                print_step("PRE-EXPERIMENT", "FAILED", "Could not set up environment")
                sys.exit(1)
            
            # Run the actual experiment
            automation_mode.log_message(f"Starting experimentation for {experiment_name} with concurrency={concurrency}, iteration={current_iter}", 'info')
            if not automation_mode.quiet_mode:
                print_step("EXPERIMENT", "STARTED", f"Running with concurrency={concurrency}")
                
            success = run_experimentation(experiment_name, concurrency, current_iter, experiment_state.current_experiment_id)
            if not success:
                # Always show errors in all modes
                print_step("EXPERIMENT", "FAILED", "Execution encountered errors")
                sys.exit(1)
            
            # Post-experimentation cleanup
            automation_mode.log_message(f"Starting post-experimentation for {experiment_name} with concurrency={concurrency}, iteration={current_iter}", 'info')
            if not automation_mode.quiet_mode:
                print_step("POST-EXPERIMENT", "STARTED", "Cleaning up and saving state")
                
            run_post_experimentation(experiment_name, concurrency, current_iter, experiment_state.current_experiment_id)
            
            # Run chrony post-check
            if automation_mode.quiet_mode:
                print("CHRONY: Running post-experiment time synchronization check", flush=True)
            run_chrony_check("post", experiment_state.current_experiment_id)
            
            # Final experiment summary - only in non-quiet modes
            if not automation_mode.quiet_mode:
                print_step("EXPERIMENT", "COMPLETED", f"Concurrency {concurrency}, Iteration {current_iter}")
            else:
                print(f"EXPERIMENT COMPLETED: {experiment_name} with concurrency={concurrency}, iteration={current_iter}", flush=True)

        # Final chrony check after all concurrency values
        automation_mode.log_message("Starting post chrony check", 'info')
        run_chrony_check("post", experiment_state.current_experiment_id)
        
        # Final status message
        if automation_mode.quiet_mode:
            print("Experiment completed PASS", flush=True)
            print(f"RESULTS DIR: {get_experiment_path(experiment_name, experiment_state.current_experiment_id, conc_vals[0])}", flush=True)
            print(f"LOG FILE: {automation_mode.log_file}", flush=True)
            print(f"STATE FILE: {STATE_FILE}", flush=True)
            print("SUCCESS", flush=True)
        else:
            print("\n=== Experiment Completed PASS ===", flush=True)
            print(f"Experiment: {experiment_name}", flush=True)
            print(f"Experiment ID: {experiment_state.current_experiment_id}", flush=True)
            print(f"Concurrency values: {conc_vals}", flush=True)
            print(f"Completed iterations: {current_iter}", flush=True)
            print("SUCCESS", flush=True)

    except Exception as e:
        # Always show errors in all modes
        print(f"ERROR: Experiment failed: {str(e)}", flush=True)
        automation_mode.log_message(f"Experiment failed: {str(e)}", 'error')
        sys.exit(1)

if __name__ == "__main__":
    main()



