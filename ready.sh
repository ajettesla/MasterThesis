#!/usr/bin/env bash
set -e  # Exit if any command fails

# Ensure script is run with root privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root. Use: sudo $0" 
   exit 1
fi

# Change permissions and build components
cd ConnectiontrackingAnalysis
chmod +x conntrackAnalysis.py

cd ../CMNpsutil
chmod +x cm_monitor.py n_monitor.py start.sh

cd ../testAuto
chmod +x auto.py

cd ../trafGen
make clean
make
