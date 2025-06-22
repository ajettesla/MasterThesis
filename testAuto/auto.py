#!/usr/bin/env python3

import argparse
import os
import sys
import time
import datetime
import getpass
import logging
import signal

from config import (
    CURRENT_TIMESTAMP, CURRENT_USER, experiment_state, progress_tracker,
    generate_experiment_id, load_experiment_state, save_experiment_state,
    clear_experiment_state, get_experiment_path
)

from logging_utils import (
    configure_logging, setup_logging, cleanup_logging, check_and_clear_memory_usage
)

from ssh_utils import (
    SSHConnector, run_command_locally, run_command_remotely, run_command_with_timeout
)

from experiment import (
    check_function, pre_experimentation, experimentation, post_experimentation,
    setup_signal_handlers, verify_critical_processes_running
)

def print_progress_every_5s(stop_event):
    last_connt1 = 0
    last_connt2 = 0
    ssh_connector = SSHConnector()
    clients = {}
    while not stop_event.is_set():
        elapsed = time.time() - progress_tracker.start_time
        elapsed_minutes = elapsed / 60.0
        print(f"\n[Progress] {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Elapsed: {elapsed_minutes:.1f} min")
        for filepath, stats in progress_tracker.file_stats.items():
            filename = os.path.basename(filepath)
            size_mb = stats.get('size', 0) / (1024 * 1024)
            lines = stats.get('lines', 0)
            delta_kb = stats.get('delta_size', 0) / 1024
            print(f"File: {filename} | Size: {size_mb:.2f}MB | Lines: {lines} | Delta: {delta_kb:.2f}KB")
        # Conntrack entries
        for host in ["connt1", "connt2"]:
            if host not in clients:
                clients[host] = ssh_connector.connect(host)
            client = clients[host]
            cmd = "sudo conntrack -C"
            if client is None:
                status, output, _ = run_command_locally(cmd, f"[{host}]")
            else:
                status, output = run_command_with_timeout(client, cmd, 5, hostname=host)
            count = int(output.strip()) if status and output.strip().isdigit() else 0
            if host == "connt1":
                delta = count - last_connt1
                last_connt1 = count
            else:
                delta = count - last_connt2
                last_connt2 = count
            print(f"{host}: {count} (Delta: {delta:+d})")
        sys.stdout.flush()
        stop_event.wait(5)

def main():
    parser = argparse.ArgumentParser(description="Automation script for experiments.")
    parser.add_argument("-n", "--name", required=True, help="Experiment name")
    parser.add_argument("-c", "--concurrency", required=True, help="Concurrency values (comma-separated)")
    parser.add_argument("-d", "--demon", action="store_true", help="demon mode - redirect output to log file")
    parser.add_argument("-i", "--iterations", type=int, default=1, help="Number of iterations (default: 1, ignored in --cont mode)")
    continuation_group = parser.add_mutually_exclusive_group()
    continuation_group.add_argument("--new", action="store_true", help="Start a new experiment, clear existing state")
    continuation_group.add_argument("--cont", action="store_true", help="Continue an existing experiment if state matches")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    configure_logging(log_level=log_level)
    setup_signal_handlers()

    experiment_name = args.name
    requested_iterations = args.iterations
    demon = args.demon
    try:
        concurrency_values = [int(x.strip()) for x in args.concurrency.split(',')]
    except ValueError:
        logging.error("ERROR: Invalid concurrency values")
        sys.exit(1)

    continuing_experiment = False
    current_iteration_count = 1

    if args.new:
        clear_experiment_state()
        experiment_state.current_experiment_id = generate_experiment_id()
        state = {
            'name': experiment_name,
            'id': experiment_state.current_experiment_id,
            'concurrency': concurrency_values,
            'iteration': current_iteration_count,
            'timestamp': CURRENT_TIMESTAMP,
            'user': CURRENT_USER
        }
        save_experiment_state(state)
        logging.info(f"Created new experiment ID: {experiment_state.current_experiment_id}")
    elif args.cont:
        state = load_experiment_state()
        if state and state.get('name') == experiment_name:
            stored_concurrency = state.get('concurrency', [])
            if set(stored_concurrency) == set(concurrency_values):
                experiment_state.current_experiment_id = state.get('id')
                current_iteration_count = state.get('iteration', 1)
                continuing_experiment = True
                state['timestamp'] = CURRENT_TIMESTAMP
                state['user'] = CURRENT_USER
                save_experiment_state(state)
                logging.info(f"Continuing experiment with ID: {experiment_state.current_experiment_id}, iteration: {current_iteration_count}")
            else:
                logging.warning(f"Found experiment with name '{experiment_name}' but concurrency values don't match.")
                logging.warning(f"State has: {stored_concurrency}, but you provided: {concurrency_values}")
                clear_experiment_state()
                experiment_state.current_experiment_id = generate_experiment_id()
                state = {
                    'name': experiment_name,
                    'id': experiment_state.current_experiment_id,
                    'concurrency': concurrency_values,
                    'iteration': current_iteration_count,
                    'timestamp': CURRENT_TIMESTAMP,
                    'user': CURRENT_USER
                }
                save_experiment_state(state)
                logging.info(f"Creating new experiment ID: {experiment_state.current_experiment_id}")
        else:
            experiment_state.current_experiment_id = generate_experiment_id()
            state = {
                'name': experiment_name,
                'id': experiment_state.current_experiment_id,
                'concurrency': concurrency_values,
                'iteration': current_iteration_count,
                'timestamp': CURRENT_TIMESTAMP,
                'user': CURRENT_USER
            }
            save_experiment_state(state)
            logging.info(f"No matching experiment found. Created new experiment ID: {experiment_state.current_experiment_id}")
    else:
        experiment_state.current_experiment_id = generate_experiment_id()
        logging.info(f"Using temporary experiment ID: {experiment_state.current_experiment_id}")

    log_path = setup_logging(experiment_name, experiment_state.current_experiment_id, demon, CURRENT_TIMESTAMP, CURRENT_USER)

    try:
        logging.info(f"[MAIN] Experiment: {experiment_name}")
        logging.info(f"[MAIN] Experiment ID: {experiment_state.current_experiment_id}")
        if args.cont and continuing_experiment:
            logging.info(f"[MAIN] Continuing from iteration: {current_iteration_count}")
            iterations_to_run = 1
        else:
            logging.info(f"[MAIN] Starting new experiment with {requested_iterations} iterations")
            iterations_to_run = requested_iterations
        logging.info(f"[MAIN] Concurrency values: {concurrency_values}")
        logging.info(f"[MAIN] demon mode: {'ON' if demon else 'OFF'}")
        logging.info(f"[MAIN] Current time: {CURRENT_TIMESTAMP} (UTC)")
        logging.info(f"[MAIN] User: {CURRENT_USER}")
        if log_path:
            logging.info(f"[MAIN] Log file: {log_path}")
        logging.info(f"[MAIN] Started at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        logging.info("=" * 80)

        ssh_connector = SSHConnector()
        client = ssh_connector.connect("connt1")
        for c in concurrency_values:
            exp_dir = get_experiment_path(experiment_name, experiment_state.current_experiment_id, c)
            directory_cmd = f"sudo mkdir -p {exp_dir}"
            if client is None:
                os.system(directory_cmd)
            else:
                stdin, stdout, stderr = client.exec_command(directory_cmd)
                exit_code = stdout.channel.recv_exit_status()
                if exit_code != 0:
                    raise Exception(f"Failed to create directory for {exp_dir}")

        total_experiments = iterations_to_run
        current_experiment = 0

        for c in concurrency_values:
            for _ in range(iterations_to_run):
                current_experiment += 1
                state = load_experiment_state()
                if state and state.get('name') == experiment_name and state.get('id') == experiment_state.current_experiment_id:
                    iteration_number = state.get('iteration', current_iteration_count)
                else:
                    iteration_number = current_iteration_count

                logging.info(f"\nEXPERIMENT {current_experiment}/{total_experiments}: {experiment_name}_{experiment_state.current_experiment_id} - Concurrency {c} - Iteration {iteration_number}")

                experiment_state.current_experiment_name = experiment_name
                experiment_state.current_concurrency = c
                experiment_state.current_iteration = iteration_number

                check_result = check_function()
                if check_result != 2:
                    raise Exception("check_function failed")

                if not pre_experimentation(experiment_name, c, iteration_number, experiment_state.current_experiment_id):
                    raise Exception("pre_experimentation failed")

                # --- Start progress display thread without box formatting ---
                stop_event = threading.Event()
                progress_thread = threading.Thread(target=print_progress_every_5s, args=(stop_event,))
                progress_tracker.start_time = time.time()
                progress_thread.start()

                if not experimentation(experiment_name, c, iteration_number, experiment_state.current_experiment_id):
                    stop_event.set()
                    progress_thread.join()
                    raise Exception("experimentation failed")

                stop_event.set()
                progress_thread.join()

                if not post_experimentation(experiment_name, c, iteration_number, experiment_state.current_experiment_id, update_state=True):
                    raise Exception("post_experimentation failed")

                logging.info(f"Experiment {current_experiment}/{total_experiments} completed successfully")

                state = load_experiment_state()
                if state:
                    current_iteration_count = state.get('iteration', current_iteration_count + 1)
                time.sleep(1)

        if client:
            client.close()

        state = load_experiment_state()
        next_iteration = state.get('iteration', current_iteration_count) if state else current_iteration_count

        logging.info(f"\nAll {total_experiments} experiments completed successfully!")
        logging.info(f"Experiment ID: {experiment_state.current_experiment_id}")
        logging.info(f"Next iteration: {next_iteration}")
        if log_path:
            logging.info(f"Log file: {log_path}")

        if experiment_state.log_file and demon:
            footer = (
                f"\n=== Experiment Complete ===\n"
                f"End Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"Experiment: {experiment_name}_{experiment_state.current_experiment_id}\n"
                f"Next Iteration: {next_iteration}\n"
                f"Status: SUCCESS\n"
                f"===========================\n"
            )
            experiment_state.log_file.write(footer)
            experiment_state.log_file.close()
            sys.stdout = experiment_state.original_stdout
            sys.stderr = experiment_state.original_stderr
            experiment_state.original_stdout.write(footer)
        experiment_state.original_stdout.write("SUCCESS\n")
        experiment_state.original_stdout.flush()

    except Exception as e:
        logging.error(f"ERROR: {str(e)}")
        if experiment_state.log_file and demon:
            footer = (
                f"\n=== Experiment Failed ===\n"
                f"End Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"Experiment: {experiment_name}_{experiment_state.current_experiment_id}\n"
                f"Error: {str(e)}\n"
                f"Status: FAILURE\n"
                f"========================\n"
            )
            experiment_state.log_file.write(footer)
            experiment_state.log_file.close()
            sys.stdout = experiment_state.original_stdout
            sys.stderr = experiment_state.original_stderr
            experiment_state.original_stdout.write(footer)
        experiment_state.original_stdout.write("FAILURE\n")
        experiment_state.original_stdout.flush()
        sys.exit(1)

if __name__ == "__main__":
    main()
