#!/bin/bash

PID_FILE="pids.txt"
BASE_DIR="/opt/Master/Thesis/CMNpsutil"
VENV_PATH="$BASE_DIR/venv/bin/activate"

CM_LOG=""
NM_LOG=""

CM_PREV_LINES=0
NM_PREV_LINES=0

INTERVAL=""
LABEL=""
IFACE=""
PROGRAM=""
KILL_ONLY=false

# Help function
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

# Kill running processes
stop_programs() {
    if [[ -f $PID_FILE ]]; then
        echo "Stopping running programs..."
        while read pid; do
            kill -9 "$pid" 2>/dev/null
        done < "$PID_FILE"
        rm -f "$PID_FILE"
        echo "Programs stopped."
    else
        echo "No PID file found. Nothing to stop."
    fi
    exit 0
}

# Parse CLI arguments
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

# If kill flag is set, stop and exit
$KILL_ONLY && stop_programs

# Validate required arguments
if [[ -z "$INTERVAL" || -z "$LABEL" || -z "$IFACE" || -z "$PROGRAM" ]]; then
    echo "Missing required argument(s)."
    usage
fi

# Format log file paths
if [[ "$LABEL" == /* ]]; then
    # It's a full path
    LOG_DIR=$(dirname "$LABEL")
    LOG_PREFIX=$(basename "$LABEL")
    mkdir -p "$LOG_DIR"
    CM_LOG="$LABEL""_cm_monitor.csv"
    NM_LOG="$LABEL""_n_monitor.csv"
else
    # Just a label
    CM_LOG="${LABEL}_cm_monitor.log"
    NM_LOG="${LABEL}_n_monitor.log"
fi

# Activate virtual environment
echo "Activating virtual environment..."
source "$VENV_PATH"

cd "$BASE_DIR" || exit 1

# Start monitoring programs
echo "Starting cm_monitor.py and n_monitor.py..."

nohup ./cm_monitor.py -i "$INTERVAL" -p "$PROGRAM" -l "$LABEL" > "$CM_LOG" 2>&1 &
echo $! >> "$PID_FILE"

nohup ./n_monitor.py -i "$INTERVAL" --iface "$IFACE" -l "$LABEL" > "$NM_LOG" 2>&1 &
echo $! >> "$PID_FILE"

# Wait for logs to initialize
sleep 5

# Get initial line counts
CM_PREV_LINES=$(wc -l < "$CM_LOG")
NM_PREV_LINES=$(wc -l < "$NM_LOG")

# Monitoring loop
while true; do
    sleep 30
    echo "====== STATUS @ $(date) ======"

    CM_CURRENT_LINES=$(wc -l < "$CM_LOG")
    NM_CURRENT_LINES=$(wc -l < "$NM_LOG")

    if (( CM_CURRENT_LINES > CM_PREV_LINES )); then
        echo "✅ CM Monitor is running: +$((CM_CURRENT_LINES - CM_PREV_LINES)) new lines"
    else
        echo "⚠️  CM Monitor might be stalled (no new logs)"
    fi

    if (( NM_CURRENT_LINES > NM_PREV_LINES )); then
        echo "✅ Network Monitor is running: +$((NM_CURRENT_LINES - NM_PREV_LINES)) new lines"
    else
        echo "⚠️  Network Monitor might be stalled (no new logs)"
    fi

    CM_PREV_LINES=$CM_CURRENT_LINES
    NM_PREV_LINES=$NM_CURRENT_LINES
done

