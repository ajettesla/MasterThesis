#!/bin/bash

set -euo pipefail

### --- Configuration ---
VENV_DIR="${VENV_DIR:-./venv}"
VENV_PY="$VENV_DIR/bin/python"
REQUIREMENTS_FILE="${REQUIREMENTS_FILE:-requirements.txt}"
BASE_DIR="${BASE_DIR:-/opt/MasterThesis/CMNpsutil}"
TEMP_DIR="${TEMP_DIR:-/tmp}"
START_LOG="$TEMP_DIR/start.log"

INTERVAL=""
LABEL=""
IFACE=""
PROGRAM=""
KILL_ONLY=false
DAEMON_MODE=false
SELF_PID=$$

### --- Logging Function ---
log() {
    local message="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$message" >&2
    if $DAEMON_MODE && [[ -w "$START_LOG" ]]; then
        echo "$message" >> "$START_LOG"
    fi
}

### --- Status Logging for Growth Only (always writes growth, never tail) ---
log_status() {
    local cm_status="$1"
    local nm_status="$2"
    # Only growth info, never include tail output
    echo "cm=$cm_status, n=$nm_status" >> "$START_LOG"
}

### --- Check File/Directory Permissions ---
check_writable() {
    local path="$1"
    local dir
    dir=$(dirname "$path")
    mkdir -p "$dir" || {
        log "ERROR: Failed to create directory $dir"
        exit 1
    }
    touch "$path" 2>/dev/null || {
        log "ERROR: Cannot create or write to $path"
        exit 1
    }
    [[ -w "$path" ]] || {
        log "ERROR: No write permission for $path"
        exit 1
    }
}

### --- Setup Virtual Environment ---
setup_venv() {
    log "Checking virtual environment..."
    if [[ -x "$VENV_PY" ]]; then
        if "$VENV_PY" cm_monitor.py --help >/dev/null 2>&1 && "$VENV_PY" n_monitor.py --help >/dev/null 2>&1; then
            log "Virtual environment is valid"
            return 0
        else
            log "Virtual environment invalid, recreating..."
            rm -rf "$VENV_DIR"
        fi
    else
        log "Virtual environment not found, creating..."
    fi

    python3 -m venv "$VENV_DIR" || {
        log "ERROR: Failed to create virtual environment"
        exit 1
    }
    "$VENV_DIR/bin/pip" install --upgrade pip || {
        log "ERROR: Failed to upgrade pip"
        exit 1
    }

    if [[ -f "$REQUIREMENTS_FILE" ]]; then
        log "Installing requirements from $REQUIREMENTS_FILE..."
        "$VENV_DIR/bin/pip" install -r "$REQUIREMENTS_FILE" --quiet || {
            log "ERROR: Failed to install requirements"
            exit 1
        }
    else
        log "Installing psutil (no requirements.txt found)..."
        "$VENV_DIR/bin/pip" install psutil --quiet || {
            log "ERROR: Failed to install psutil"
            exit 1
        }
    fi
}

### --- Usage Help ---
usage() {
    echo "Usage: $0 [options]" >&2
    echo "Options:" >&2
    echo "  -i <interval>           Interval in seconds (required)" >&2
    echo "  -l <label|path>         Label or full path to log prefix (required)" >&2
    echo "  -p <program_name>       Name of process to monitor (required)" >&2
    echo "  --iface <interface>     Network interface (required)" >&2
    echo "  -k                      Kill running monitoring programs" >&2
    echo "  -d                      Run in daemon mode" >&2
    exit 1
}

### --- Start a Monitor Process ---
start_monitor() {
    local script="$1"
    local pid_file="$2"
    local args=("${@:3}")

    if [[ -f "$pid_file" ]]; then
        local pid
        pid=$(cat "$pid_file")
        if ps -p "$pid" > /dev/null; then
            log "$script already running with PID $pid"
            return 0
        fi
    fi

    log "Starting $script..."
    "$VENV_PY" "$script" "${args[@]}" -d &
    sleep 1
    local pid
    pid=$(pgrep -f "$script ${args[*]}" | grep -v "^$SELF_PID$" || true)
    if [[ -n "$pid" ]]; then
        echo "$pid" > "$pid_file"
        log "$script started with PID $pid"
        return 0
    else
        log "ERROR: $script failed to start"
        return 1
    fi
}

### --- Stop All Programs ---
stop_programs() {
    log "Stopping monitoring programs..."

    local processes=("cm_monitor.py" "n_monitor.py" "[s]tart.sh")
    for proc in "${processes[@]}"; do
        local pids
        pids=$(pgrep -f "$proc" | grep -v "^$SELF_PID$" || true)
        if [[ -n "$pids" ]]; then
            echo "$pids" | xargs -r kill
            log "Killed $proc processes: $pids"
        else
            log "No $proc processes found"
        fi
    done

    rm -f "$TEMP_DIR"/*_cm.pid "$TEMP_DIR"/*_nm.pid
    log "Cleanup complete."
    exit 0
}

### --- Signal Handling ---
cleanup_on_exit() {
    log "Caught termination signal. Cleaning up..."
    stop_programs
}
trap cleanup_on_exit SIGINT SIGTERM SIGQUIT

### --- Parse CLI Arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage ;;
        -i)
            [[ -n "$2" ]] || { log "ERROR: -i requires an argument"; usage; }
            INTERVAL="$2"
            shift 2
            ;;
        -l)
            [[ -n "$2" ]] || { log "ERROR: -l requires an argument"; usage; }
            LABEL="$2"
            shift 2
            ;;
        -p)
            [[ -n "$2" ]] || { log "ERROR: -p requires an argument"; usage; }
            PROGRAM="$2"
            shift 2
            ;;
        --iface)
            [[ -n "$2" ]] || { log "ERROR: --iface requires an argument"; usage; }
            IFACE="$2"
            shift 2
            ;;
        -k) KILL_ONLY=true; shift ;;
        -d) DAEMON_MODE=true; shift ;;
        --daemon-running) shift ;; # Internal flag for daemon mode
        *) log "ERROR: Unknown option: $1"; usage ;;
    esac
done

if $KILL_ONLY; then
    stop_programs
fi

if [[ -z "$INTERVAL" || -z "$LABEL" || -z "$IFACE" || -z "$PROGRAM" ]]; then
    log "ERROR: Missing required options: -i, -l, -p, --iface"
    usage
fi

### --- Daemon Mode ---
if $DAEMON_MODE; then
    check_writable "$START_LOG"
    log "Launching daemon..."
    ARGS=("-i" "$INTERVAL" "-l" "$LABEL" "-p" "$PROGRAM" "--iface" "$IFACE" "--daemon-running")
    nohup "$0" "${ARGS[@]}" >> "$START_LOG" 2>&1 &
    DAEMON_PID=$!
    log "Started in daemon mode with PID $DAEMON_PID"
    sleep 1
    if ! ps -p "$DAEMON_PID" > /dev/null; then
        log "ERROR: Daemon process $DAEMON_PID failed to start"
        cat "$START_LOG" >&2
        exit 1
    fi
    exit 0
fi

### --- Setup Log & PID Paths ---
if [[ "$LABEL" == /* ]]; then
    CM_LOG="${LABEL}_${PROGRAM}_cm_monitor.csv"
    NM_LOG="${LABEL}_${PROGRAM}_n_monitor.csv"
else
    CM_LOG="$TEMP_DIR/${PROGRAM}_${LABEL}_cm_monitor.csv"
    NM_LOG="$TEMP_DIR/${PROGRAM}_${LABEL}_n_monitor.csv"
fi

check_writable "$CM_LOG"
check_writable "$NM_LOG"

CM_PID_FILE="$TEMP_DIR/${PROGRAM}_cm.pid"
NM_PID_FILE="$TEMP_DIR/${PROGRAM}_nm.pid"

log "Changing to directory $BASE_DIR..."
cd "$BASE_DIR" || {
    log "ERROR: Failed to change to directory $BASE_DIR"
    exit 1
}

setup_venv

### --- Start Monitors ---
if ! start_monitor "cm_monitor.py" "$CM_PID_FILE" -i "$INTERVAL" -p "$PROGRAM" -l "$CM_LOG"; then
    log "ERROR: Failed to start cm_monitor.py"
    stop_programs
    exit 1
fi

if ! start_monitor "n_monitor.py" "$NM_PID_FILE" -i "$INTERVAL" --iface "$IFACE" -l "$NM_LOG"; then
    log "ERROR: Failed to start n_monitor.py"
    stop_programs
    exit 1
fi

### --- Monitor Loop ---
CM_PREV_LC=$(wc -l "$CM_LOG" 2>/dev/null | awk '{print $1}' || echo 0)
NM_PREV_LC=$(wc -l "$NM_LOG" 2>/dev/null | awk '{print $1}' || echo 0)

while true; do
    sleep 30
    log "====== STATUS @ $(date) ======"

    CM_CURRENT_LC=$(wc -l "$CM_LOG" 2>/dev/null | awk '{print $1}' || echo 0)
    NM_CURRENT_LC=$(wc -l "$NM_LOG" 2>/dev/null | awk '{print $1}' || echo 0)

    CM_STATUS="false"
    NM_STATUS="false"

    if [[ -f "$CM_PID_FILE" ]] && ps -p "$(cat "$CM_PID_FILE")" > /dev/null; then
        if [[ "$CM_CURRENT_LC" -gt "$CM_PREV_LC" ]]; then
            CM_STATUS="true"
            log "CM Monitor active: Log line count increased ($CM_CURRENT_LC)"
        else
            log "CM Monitor inactive or stalled ($CM_CURRENT_LC lines)"
        fi
    else
        log "CM Monitor not running"
    fi

    if [[ -f "$NM_PID_FILE" ]] && ps -p "$(cat "$NM_PID_FILE")" > /dev/null; then
        if [[ "$NM_CURRENT_LC" -gt "$NM_PREV_LC" ]]; then
            NM_STATUS="true"
            log "Network Monitor active: Log line count increased ($NM_CURRENT_LC)"
        else
            log "Network Monitor inactive or stalled ($NM_CURRENT_LC lines)"
        fi
    else
        log "Network Monitor not running"
    fi

    # Log growth status to start.log (ALWAYS, never log tail output)
    log_status "$CM_STATUS" "$NM_STATUS"

    # The following log lines **never** go to start.log, only to stderr/console
    #log "---- Last 5 lines of CM Monitor ----"
    #[[ -f "$CM_LOG" ]] && tail -n 5 "$CM_LOG" >&2 || log "No CM log data"
    #log ""

    #log "---- Last 5 lines of Network Monitor ----"
    #[[ -f "$NM_LOG" ]] && tail -n 5 "$NM_LOG" >&2 || log "No NM log data"
    log "====================================="

    CM_PREV_LC=$CM_CURRENT_LC
    NM_PREV_LC=$NM_CURRENT_LC
done
