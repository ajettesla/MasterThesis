#!/usr/bin/env bash
set -e  # Exit on any error

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root. Use: sudo \$0"
    exit 1
fi

# Set base directory
BASE_DIR="/opt/MasterThesis"

# connectiontrackingAnalysis
cd "$BASE_DIR/connectiontrackingAnalysis"
chmod +x conntrackAnalysis.py

# CMNpsutil
cd "$BASE_DIR/CMNpsutil"
chmod +x cm_monitor.py n_monitor.py start.sh

# testAuto
cd "$BASE_DIR/testAuto"
chmod +x auto.py

# trafGen
cd "$BASE_DIR/trafGen"
make clean
make

# stats
cd "$BASE_DIR/stats"
chmod +x ChronyLogAnalysis.sh
