#!/bin/bash

set -euo pipefail

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
BASE_DIR="/opt/MasterThesis/CMNpsutil/"
CM_PID_FILE=""
NM_PID_FILE=""
CM_LOG=""
NM_LOG=""

INTERVAL=""
LABEL=""
IFACE=""
PROGRAM=""
KILL_ONLY=false

### --- Usage Help ---
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

### --- Stop All Programs ---
stop_programs() {
    echo "🔴 Stopping monitoring programs..."

    # Kill cm_monitor.py
    CM_MATCHES=$(pgrep -f "cm_monitor.py" || true)
    if [[ -n "$CM_MATCHES" ]]; then
        echo "$CM_MATCHES" | xargs -r kill
        echo "✅ Killed cm_monitor.py processes"
    else
        echo "⚠️  No cm_monitor.py processes found"
    fi

    # Kill n_monitor.py
    NM_MATCHES=$(pgrep -f "n_monitor.py" || true)
    if [[ -n "$NM_MATCHES" ]]; then
        echo "$NM_MATCHES" | xargs -r kill
        echo "✅ Killed n_monitor.py processes"
    else
        echo "⚠️  No n_monitor.py processes found"
    fi

    # Kill all start.sh processes except self
    SELF_PID=$$
    START_MATCHES=$(pgrep -f "[s]tart.sh" | grep -v "$SELF_PID" || true)
    if [[ -n "$START_MATCHES" ]]; then
        echo "$START_MATCHES" | xargs -r kill
        echo "✅ Killed other start.sh processes"
    else
        echo "⚠️  No other start.sh scripts found"
    fi

    # Remove stale PID files
    rm -f /tmp/*_cm.pid /tmp/*_nm.pid

    echo "🧹 Cleanup complete."
    exit 0
}

### --- Parse CLI Arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        -i) INTERVAL="$2"; shift 2 ;;
        -l) LABEL="$2"; shift 2 ;;
        -p) PROGRAM="$2"; shift 2 ;;
        --iface) IFACE="$2"; shift 2 ;;
        -k) KILL_ONLY=true; shift ;;
        *) usage ;;
    esac
done

$KILL_ONLY && stop_programs

[[ -z "$INTERVAL" || -z "$LABEL" || -z "$IFACE" || -z "$PROGRAM" ]] && usage

### --- Setup Log & PID Paths ---
if [[ "$LABEL" == /* ]]; then
    LOG_DIR=$(dirname "$LABEL")
    LOG_PREFIX=$(basename "$LABEL")
    mkdir -p "$LOG_DIR"
    CM_LOG="$LABEL""_cm_monitor.csv"
    NM_LOG="$LABEL""_n_monitor.csv"
else
    CM_LOG="/tmp/${PROGRAM}_cm_monitor.log"
    NM_LOG="/tmp/${PROGRAM}_n_monitor.log"
fi

CM_PID_FILE="/tmp/${PROGRAM}_cm.pid"
NM_PID_FILE="/tmp/${PROGRAM}_nm.pid"

cd "$BASE_DIR" || exit 1

### --- Signal Handling ---
cleanup_on_exit() {
    echo ""
    echo "⚠️  Caught termination signal. Cleaning up..."
    stop_programs
}
trap cleanup_on_exit SIGINT SIGTERM SIGQUIT

### --- Start Monitor Scripts ---
echo "🚀 Starting monitor scripts..."

"$VENV_PY" cm_monitor.py -i "$INTERVAL" -p "$PROGRAM" -l "$CM_LOG" > "$CM_LOG" 2>&1 &
echo $! > "$CM_PID_FILE"

"$VENV_PY" n_monitor.py -i "$INTERVAL" --iface "$IFACE" -l "$NM_LOG" > "$NM_LOG" 2>&1 &
echo $! > "$NM_PID_FILE"

sleep 5

CM_PREV_LINES=$(wc -l < "$CM_LOG" || echo 0)
NM_PREV_LINES=$(wc -l < "$NM_LOG" || echo 0)

### --- Monitor Loop ---
while true; do
    sleep 60
    echo "====== STATUS @ $(date) ======"

    CM_CURRENT_LINES=$(wc -l < "$CM_LOG" || echo 0)
    NM_CURRENT_LINES=$(wc -l < "$NM_LOG" || echo 0)

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
    tail -n 5 "$CM_LOG" || echo "No CM log data"
    echo ""
    echo "---- Last 5 lines of Network Monitor ----"
    tail -n 5 "$NM_LOG" || echo "No NM log data"
    echo "====================================="

    CM_PREV_LINES=$CM_CURRENT_LINES
    NM_PREV_LINES=$NM_CURRENT_LINES
done
