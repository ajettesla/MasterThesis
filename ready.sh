#!/usr/bin/env bash
sudo su 
cd ConnectiontrackingAnalysis 
chmod +x conntrackAnalysis.py
cd ../CMNpsutil
chmod +x cm_monitor.py n_monitor.py start.sh
cd ../testAuto
chmod +x auto.py
cd ../trafGen
make clean 
make 
exit 

