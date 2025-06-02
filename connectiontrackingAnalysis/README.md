

---

This module is responsible for monitoring log files and extracting important information. It includes two scripts: `conntrackAnalysis.py` and `extractPtp.py`.

The `connectionTrackingProgram` logs connection tracking data to the syslog server. These analysis scripts should be run on the syslog server to extract metrics such as synchronization delay and other relevant parameters.

The `extractPtp.py` script was originally designed to analyze how well `connt1` and `connt2` are synchronized and to measure synchronization accuracy. However, it was initially built for use with **ptp4l**, and since the setup now uses **PTPd2**, the script may need to be updated accordingly.

---

