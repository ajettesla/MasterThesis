#!/bin/bash

set -e  # Exit on any error

### --- Virtual Environment Setup ---
VENV_DIR="./venv"
VENV_PY="$VENV_DIR/bin/python"
REQUIREMENTS_FILE="requirements.txt"

echo "Checking virtual environment..."

if [ ! -x "$VENV_PY" ]; then
    echo "Virtual environment not found. Creating..."
    python3 -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install --upgrade pip
fi

if [ -f "$REQUIREMENTS_FILE" ]; then
    echo "Installing requirements from $REQUIREMENTS_FILE..."
    "$VENV_DIR/bin/pip" install -r "$REQUIREMENTS_FILE"
else
    echo "Installing psutil (no requirements.txt found)..."
    "$VENV_DIR/bin/pip" install psutil
fi

### --- Configuration ---
PID_FILE="pids.txt"
BASE_DIR="/opt/Master/Thesis/CMNpsutil"

CM_LOG=""
NM_LOG=""

CM_PREV_LINES=0
NM_PREV_LINES=0

INTERVAL=""
LABEL=""
IFACE=""
PROGRAM=""
KILL_ONLY=false

### --- Usage ---
usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -i <interval>           Interval in seconds (required)"
    echo "  -l <label|path>         Label or full path to log prefix (required)"
    echo "  -p <program_name>       Name of process to monitor (required)"
    echo "  --iface <interface>     Network interface (required)"
    echo "  -k                      Kill running monitoring programs"
    exit 1
}

### --- Stop Running Programs ---
stop_programs() {
    if [[ -f $PID_FILE ]]; then
        echo "Stopping running programs..."
        while read pid; do
            kill -9 "$pid" 2>/dev/null || true
        done < "$PID_FILE"
        rm -f "$PID_FILE"
        echo "Programs stopped."
    else
        echo "No PID file found. Nothing to stop."
    fi
    exit 0
}

### --- Parse CLI Arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        -i)
            INTERVAL="$2"
            shift 2
            ;;
        -l)
            LABEL="$2"
            shift 2
            ;;
        -p)
            PROGRAM="$2"
            shift 2
            ;;
        --iface)
            IFACE="$2"
            shift 2
            ;;
        -k)
            KILL_ONLY=true
            shift
            ;;
        *)
            usage
            ;;
    esac
done

$KILL_ONLY && stop_programs

# Check for required input
if [[ -z "$INTERVAL" || -z "$LABEL" || -z "$IFACE" || -z "$PROGRAM" ]]; then
    echo "Missing required argument(s)."
    usage
fi

### --- Setup Log Paths ---
if [[ "$LABEL" == /* ]]; then
    LOG_DIR=$(dirname "$LABEL")
    LOG_PREFIX=$(basename "$LABEL")
    mkdir -p "$LOG_DIR"
    CM_LOG="$LABEL""_cm_monitor.csv"
    NM_LOG="$LABEL""_n_monitor.csv"
else
    CM_LOG="${LABEL}_cm_monitor.log"
    NM_LOG="${LABEL}_n_monitor.log"
fi

cd "$BASE_DIR" || exit 1

### --- Start Monitor Scripts ---
echo "Starting monitor scripts with virtual environment..."

"$VENV_PY" cm_monitor.py -i "$INTERVAL" -p "$PROGRAM" -l "$LABEL" > "$CM_LOG" 2>&1 &
echo $! >> "$PID_FILE"

"$VENV_PY" n_monitor.py -i "$INTERVAL" --iface "$IFACE" -l "$LABEL" > "$NM_LOG" 2>&1 &
echo $! >> "$PID_FILE"

sleep 5

CM_PREV_LINES=$(wc -l < "$CM_LOG")
NM_PREV_LINES=$(wc -l < "$NM_LOG")

### --- Periodic Monitoring Loop ---
while true; do
    sleep 60
    echo "====== STATUS @ $(date) ======"

    CM_CURRENT_LINES=$(wc -l < "$CM_LOG")
    NM_CURRENT_LINES=$(wc -l < "$NM_LOG")

    if (( CM_CURRENT_LINES > CM_PREV_LINES )); then
        echo "✅ CM Monitor active: +$((CM_CURRENT_LINES - CM_PREV_LINES)) new lines"
    else
        echo "⚠️  CM Monitor inactive or stalled"
    fi

    if (( NM_CURRENT_LINES > NM_PREV_LINES )); then
        echo "✅ Network Monitor active: +$((NM_CURRENT_LINES - NM_PREV_LINES)) new lines"
    else
        echo "⚠️  Network Monitor inactive or stalled"
    fi

    echo "---- Last 5 lines of CM Monitor ----"
    tail -n 5 "$CM_LOG"
    echo ""
    echo "---- Last 5 lines of Network Monitor ----"
    tail -n 5 "$NM_LOG"
    echo "====================================="

    CM_PREV_LINES=$CM_CURRENT_LINES
    NM_PREV_LINES=$NM_CURRENT_LINES
done
