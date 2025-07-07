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
)
from logging_utils import setup_logging
from ssh_utils import SSHConnector
from experiment import (
    check_function,
    pre_experimentation,
    experimentation,
    post_experimentation,
    setup_signal_handlers,
)

def run_chrony_check(phase, experiment_id, concurrency=None, iteration=None):
    hosts = ["connt1", "connt2"]
    ssh = SSHConnector()

    if not experiment_id:
        experiment_id = "exp_" + datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')
        logging.warning(f"No experiment ID provided, using generated ID: {experiment_id}")

    dir_suffix = ""
    if concurrency is not None:
        dir_suffix += f"_c{concurrency}"
    if iteration is not None:
        dir_suffix += f"_i{iteration}"

    current_time = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

    print(f"=== Chrony Check ({phase}) - {current_time} - User: {CURRENT_USER} === Experiment ID: {experiment_id}{dir_suffix}")


    for host in hosts:
        print(f">> Running ChronyLogAnalysis.sh {phase} {experiment_id}{dir_suffix} on {host} (as root):")
        client = ssh.connect(host)
        if client is None:
            msg = f"Failed to connect to {host} for Chrony check"
            logging.error(msg)
            print(f"FAILURE - {msg}")
            sys.exit(1)

        dir_path = f"/tmp/exp/{experiment_id}{dir_suffix}/chrony"
        for cmd in [
            f"sudo mkdir -p {dir_path}",
            f"sudo chmod 777 -R /tmp/exp/{experiment_id}{dir_suffix}"
        ]:
            stdin, stdout, stderr = client.exec_command(cmd)
            if stdout.channel.recv_exit_status() != 0:
                print(f"Failed to execute '{cmd}' on {host}: {stderr.read().decode('utf-8')}")
                client.close()
                sys.exit(1)

        cmd = f"sudo /opt/MasterThesis/stats/ChronyLogAnalysis.sh {phase} {experiment_id}{dir_suffix}"
        print(f"Executing: {cmd}")
        stdin, stdout, stderr = client.exec_command(cmd)
        exit_status = stdout.channel.recv_exit_status()
        output, error = stdout.read().decode('utf-8'), stderr.read().decode('utf-8')


        print(f"--- Output from {host} ---\n{output}", end='')
        if error:
            print(f"--- Error from {host} ---\n{error}", end='')
 


        if exit_status != 0 or "FAILURE" in output or "FAILURE" in error:
            logging.error(f"ChronyLogAnalysis.sh ({phase}) on {host} failed with status {exit_status}")
            print(f"FAILURE detected on {host}")
            client.close()
            sys.exit(1)

        logging.info(f"Chrony NTP status on {host}: OK ({phase})")
        client.close()

    print(f"✓ Chrony NTP status on all hosts: OK ({phase})")


def main():
    parser = argparse.ArgumentParser(description="Automation script for experiments.")
    parser.add_argument("-n", "--name",      required=True, help="Experiment name")
    parser.add_argument("-c", "--concurrency", required=True,
                        help="Comma-separated concurrency values")
    parser.add_argument("-d", "--demon",     action="store_true",
                        help="Enable daemon mode (logging only, print still goes to terminal)")
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
        print("ERROR: Invalid concurrency values")
        sys.exit(1)

    # Initialize state file path (dynamic YAML file per experiment+concurrency)
    init_state_file(args.name, conc_vals)

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
        save_experiment_state(state)
    elif args.cont:
        state = load_experiment_state()
        if (state.get("name") == experiment_name and
            set(state.get("concurrency", [])) == set(conc_vals)):
            eid = state.get("id")
            experiment_state.current_experiment_id = eid
            current_iter = state.get("iteration", 1)
            continuing = True
            state["timestamp"] = CURRENT_TIMESTAMP
            state["user"]      = CURRENT_USER
            save_experiment_state(state)
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
    else:
        eid = generate_experiment_id()
        experiment_state.current_experiment_id = eid

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
        experiment_state.current_concurrency = c
        for _ in range(iterations):
            run_idx += 1
            state = load_experiment_state()
            iteration = state.get("iteration", current_iter)
            experiment_id_for_chrony = state.get("id", experiment_state.current_experiment_id)
            experiment_state.current_iteration = iteration

            # Setup per-run logging
            setup_logging(
                experiment_name,
                experiment_state.current_experiment_id,
                demon,
                CURRENT_TIMESTAMP,
                CURRENT_USER
            )

            # 1) Pre-check
            if check_function() != 2:
                raise RuntimeError("check_function failed")
            # 1.5) Chrony NTP pre-check
            run_chrony_check("pre", experiment_id_for_chrony, c, iteration)
            # 2) Pre-experiment setup
            if not pre_experimentation(
                experiment_name, c, iteration, experiment_state.current_experiment_id
            ):
                raise RuntimeError("pre_experimentation failed")
            # 3) Experimentation (with progress display)
            progress_tracker.start_time = time.time()
            if not experimentation(
                experiment_name, c, iteration, experiment_state.current_experiment_id
            ):
                raise RuntimeError("experimentation failed")
            # 4) Post-experiment cleanup & state update
            if not post_experimentation(
                experiment_name,
                c,
                iteration,
                experiment_state.current_experiment_id,
                update_state=True,
            ):
                raise RuntimeError("post_experimentation failed")
            # 4.5) Chrony NTP post-check
            run_chrony_check("post", experiment_id_for_chrony, c, iteration)

            logging.info(f"Run {run_idx}/{total_runs} completed")
            new_state = load_experiment_state()
            current_iter = new_state.get("iteration", current_iter + 1)
            time.sleep(1)

    # Final summary
    final_state = load_experiment_state()
    next_iter = final_state.get("iteration", current_iter)
    logging.info(f"\nAll {total_runs} runs completed successfully!")
    logging.info(f"Experiment ID: {experiment_state.current_experiment_id}")
    logging.info(f"Next iteration: {next_iter}")

    footer = (
        "\n=== Experiment Complete ===\n"
        f"Experiment: {experiment_name}_{experiment_state.current_experiment_id}\n"
        f"Next Iteration: {next_iter}\n"
    )
    print(footer)
    print("SUCCESS")

if __name__ == "__main__":
    main()
