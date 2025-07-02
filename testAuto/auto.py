#!/usr/bin/env python3

import argparse
import os
import sys
import time
import datetime
import logging
import signal
import subprocess

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
)
from logging_utils import configure_logging, setup_logging
from ssh_utils import SSHConnector
from experiment import (
    check_function,
    pre_experimentation,
    experimentation,
    post_experimentation,
    setup_signal_handlers,
)

def get_run_directory_name(experiment_id, concurrency, iteration):
    """Generate the standard directory name format for this run"""
    return f"{experiment_id}_c{concurrency}_i{iteration}"

def run_chrony_check(phase, experiment_id, concurrency, iteration):
    """
    Run Chrony log analysis check on connt1 and connt2 via SSH.
    Uses the standardized directory format: {experiment_id}_c{concurrency}_i{iteration}
    """
    hosts = ["connt1", "connt2"]
    ssh = SSHConnector()
    
    # Get directory name in standard format, make sure experiment_id is valid
    if not experiment_id or experiment_id == "None":
        # This is a safeguard - log warning and try to get from state again
        logging.warning(f"Invalid experiment ID '{experiment_id}' passed to run_chrony_check! Trying to get from state.")
        state = load_experiment_state()
        experiment_id = state.get("id", "fallback_id")
        logging.info(f"Retrieved experiment ID from state: {experiment_id}")
    
    dir_name = get_run_directory_name(experiment_id, concurrency, iteration)
    
    current_time = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    print(f"\n=== Chrony Check ({phase}) - {current_time} - User: {CURRENT_USER} ===")
    print(f"Run ID: {dir_name}")
    
    for host in hosts:
        print(f"\n>> Running ChronyLogAnalysis.sh {phase} {dir_name} on {host} (as root):")
        client = ssh.connect(host)
        if client is None:
            msg = f"Failed to connect to {host} for Chrony check"
            logging.error(msg)
            print(f"FAILURE - {msg}")
            sys.exit(1)
        
        # First create the temp directory with proper permissions
        dir_path = f"/tmp/{dir_name}/chrony"
        mkdir_cmd = f"sudo mkdir -p {dir_path}"
        stdin, stdout, stderr = client.exec_command(mkdir_cmd)
        if stdout.channel.recv_exit_status() != 0:
            print(f"Failed to create temp directory on {host}: {stderr.read().decode('utf-8')}")
            client.close()
            sys.exit(1)
        
        # Fix permissions on the directory
        chmod_cmd = f"sudo chmod 777 -R /tmp/{dir_name}"
        stdin, stdout, stderr = client.exec_command(chmod_cmd)
        if stdout.channel.recv_exit_status() != 0:
            print(f"Failed to set permissions on temp directory on {host}: {stderr.read().decode('utf-8')}")
            client.close()
            sys.exit(1)
        
        # Run the script with the directory name as parameter
        cmd = f"sudo /opt/MasterThesis/stats/ChronyLogAnalysis.sh {phase} {dir_name}"
        print(f"Executing: {cmd}")
        
        stdin, stdout, stderr = client.exec_command(cmd)
        exit_status = stdout.channel.recv_exit_status()
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')
        
        # Print the output directly to stdout
        print(f"--- Output from {host} ---")
        print(output)
        if error:
            print(f"--- Error from {host} ---")
            print(error)
        print(f"--- End of output from {host} ---")
        
        if exit_status != 0 or "FAILURE" in output or "FAILURE" in error:
            logging.error(f"ChronyLogAnalysis.sh ({phase}) on {host} failed with status {exit_status}")
            print(f"FAILURE detected on {host}")
            client.close()
            sys.exit(1)
        
        logging.info(f"Chrony NTP status on {host}: OK ({phase})")
        client.close()
    
    print(f"\n✓ Chrony NTP status on all hosts: OK ({phase})")
    print(f"=== End of Chrony Check ({phase}) ===\n")
    
    return dir_name  # Return the directory name for potential reuse

def main():
    parser = argparse.ArgumentParser(description="Automation script for experiments.")
    parser.add_argument("-n", "--name",      required=True, help="Experiment name")
    parser.add_argument("-c", "--concurrency", required=True,
                        help="Comma-separated concurrency values")
    parser.add_argument("-d", "--demon",     action="store_true",
                        help="Redirect output to experiment logfile")
    parser.add_argument("-i", "--iterations", type=int, default=1,
                        help="Number of iterations")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--new",  action="store_true", help="Start new experiment")
    group.add_argument("--cont", action="store_true", help="Continue existing experiment")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    # Parse concurrency values
    try:
        conc_vals = [int(x.strip()) for x in args.concurrency.split(",")]
    except ValueError:
        logging.error("ERROR: Invalid concurrency values")
        sys.exit(1)

    # Initialize state file path (dynamic YAML file per experiment+concurrency)
    init_state_file(args.name, conc_vals)

    # Set up logging and signal handlers
    log_level = logging.DEBUG if args.verbose else logging.INFO
    # Call configure_logging with no arguments
    configure_logging()  # <-- Modified: removed argument
    setup_signal_handlers()

    experiment_name = args.name
    demon = args.demon
    requested_iters = args.iterations

    continuing = False
    current_iter = 1

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
        logging.info(f"[auto] New state: {state}")
        save_experiment_state(state)
        logging.info(f"New Experiment ID: {eid}")

    elif args.cont:
        state = load_experiment_state()
        logging.info(f"[auto] Loaded state: {state}")
        if (state.get("name") == experiment_name and
            set(state.get("concurrency", [])) == set(conc_vals)):
            eid = state.get("id")
            experiment_state.current_experiment_id = eid
            current_iter = state.get("iteration", 1)
            continuing = True
            state["timestamp"] = CURRENT_TIMESTAMP
            state["user"]      = CURRENT_USER
            logging.info(f"[auto] Updated state: {state}")
            save_experiment_state(state)
            logging.info(f"Continuing Experiment ID: {eid}, iteration {current_iter}")
        else:
            logging.warning("[auto] State missing or mismatch – starting fresh")
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
            logging.info(f"[auto] Fresh state: {state}")
            save_experiment_state(state)
            logging.info(f"New Experiment ID: {eid}")

    else:
        # No persistent state
        eid = generate_experiment_id()
        experiment_state.current_experiment_id = eid
        logging.info(f"Temporary Experiment ID: {eid}")

    # Start experiment logging (file or console)
    log_path = setup_logging(
        experiment_name,
        experiment_state.current_experiment_id,
        demon,
        CURRENT_TIMESTAMP,
        CURRENT_USER,
    )

    # Prepare remote directories
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
                raise RuntimeError(f"Failed to create directory {exp_dir}")
    if client:
        client.close()

    # Execute experiments
    iterations = 1 if (args.cont and continuing) else requested_iters
    total_runs = len(conc_vals) * iterations
    run_idx = 0

    for c in conc_vals:
        for _ in range(iterations):
            run_idx += 1
            state = load_experiment_state()
            iteration = state.get("iteration", current_iter)
            
            # IMPORTANT: Get the experiment ID directly from the state file for each run
            experiment_id = state.get("id")
            if not experiment_id:
                logging.error("Failed to get experiment ID from state file!")
                sys.exit(1)
            
            # Store the ID explicitly in a local variable to ensure consistency
            run_experiment_id = experiment_id
            
            logging.info(
                f"\nRUN {run_idx}/{total_runs}: {experiment_name}_"
                f"{run_experiment_id} - C={c} - iter={iteration}"
            )
            logging.info(f"Using experiment ID: {run_experiment_id}")

            experiment_state.current_experiment_name = experiment_name
            experiment_state.current_concurrency     = c
            experiment_state.current_iteration       = iteration
            experiment_state.current_experiment_id   = run_experiment_id  # Update the global state

            # 1) Pre-check
            if check_function() != 2:
                raise RuntimeError("check_function failed")
                
            # 1.5) Chrony NTP pre-check - using the explicit ID
            chrony_dir = run_chrony_check("pre", run_experiment_id, c, iteration)
            
            # 2) Pre-experiment setup
            if not pre_experimentation(
                experiment_name, c, iteration, run_experiment_id
            ):
                raise RuntimeError("pre_experimentation failed")
                
            # 3) Experimentation (with progress display)
            progress_tracker.start_time = time.time()
            if not experimentation(
                experiment_name, c, iteration, run_experiment_id
            ):
                raise RuntimeError("experimentation failed")
                
            # 4) Post-experiment cleanup & state update
            if not post_experimentation(
                experiment_name,
                c,
                iteration,
                run_experiment_id,
                update_state=True,
            ):
                raise RuntimeError("post_experimentation failed")
                
            # 4.5) Chrony NTP post-check - IMPORTANT: use the same ID as pre-check
            logging.info(f"Running post-check with same ID: {run_experiment_id}")
            run_chrony_check("post", run_experiment_id, c, iteration)

            logging.info(f"Run {run_idx}/{total_runs} completed")
            new_state = load_experiment_state()
            logging.info(f"[auto] State after save: {new_state}")
            current_iter = new_state.get("iteration", current_iter + 1)
            time.sleep(1)

    # Final summary
    final_state = load_experiment_state()
    next_iter = final_state.get("iteration", current_iter)
    logging.info(f"\nAll {total_runs} runs completed successfully!")
    logging.info(f"Experiment ID: {experiment_state.current_experiment_id}")
    logging.info(f"Next iteration: {next_iter}")
    if log_path:
        logging.info(f"Log file: {log_path}")

    # Footer in demon mode
    if demon and experiment_state.log_file:
        footer = (
            "\n=== Experiment Complete ===\n"
            f"End Time: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Experiment: {experiment_name}_{experiment_state.current_experiment_id}\n"
            f"Next Iteration: {next_iter}\n"
            "Status: SUCCESS\n"
            "===========================\n"
        )
        experiment_state.log_file.write(footer)
        
        # Check if these attributes exist before using them
        if hasattr(experiment_state, 'original_stdout') and experiment_state.original_stdout:
            sys.stdout = experiment_state.original_stdout
        if hasattr(experiment_state, 'original_stderr') and experiment_state.original_stderr:
            sys.stderr = experiment_state.original_stderr
        
        # Only write to original_stdout if it exists
        if hasattr(experiment_state, 'original_stdout') and experiment_state.original_stdout:
            experiment_state.original_stdout.write(footer)

    # Only write to original_stdout if it exists
    if hasattr(experiment_state, 'original_stdout') and experiment_state.original_stdout:
        experiment_state.original_stdout.write("SUCCESS\n")
        experiment_state.original_stdout.flush()
    else:
        # Alternative: just print to the current stdout
        print("SUCCESS")

if __name__ == "__main__":
    main()
