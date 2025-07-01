
---

This master’s thesis evaluates the performance of **conntrackd** by measuring synchronization delay, CPU usage, memory usage, and network usage. The study tests **conntrackd** under various scenarios, including different network loads and conditions, to observe its behavior and performance.

---

### Experimental Setup

The testbed consists of the following devices:

* **convsrc1** (Client 1 and Syslog Server)
* **convsrc2** (Client 2 and Syslog Server)
* **connt1** (Gateway 1 - Active)
* **connt2** (Gateway 2 - Backup)
* **convsrc5** (TCP and UDP Server)
* **convsrc8** (TCP and UDP Server)

All these devices are connected to an internal network. Network configurations are managed via **Netplan**, with configuration files located in the `networkConfiguration` folder.

The TCP/UDP server programs and traffic generation tools are included in the `trafGen` directory. The **conntrackd** configurations are stored in the `configuration` folder.

---


To verify current in-flight connections

watch -n 1 'ss -ant | awk "NR>1 {count[\$1]++} END {for (s in count) print s, count[s]}"'



