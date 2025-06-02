This is the Ansible roles directory where all device configurations are managed. It uses keys and IP addresses from the hosts file, though these can be modified in the SSH config if needed.

The setup will configure five devices as part of the experiment: convsrc2, convsrc1, connt1, connt2, convsrc5, and convsr8. Specifically:

    convsrc2 will be configured with syslog.

    connt1 and connt2 will be set up with Keepalived and LVS to distribute traffic to convsrc5 and convsr8, where both TCP and UDP servers are running.

    On the LVS nodes, TCP traffic is handled on port 2000 and UDP on port 3000.

    On convsrc5 and convsr8, the TCP server runs on port 8000, and the UDP server runs on port 9000.

Additionally, connt1 and connt2 will be configured with PTPd2 to synchronize with a PTP master. The conntrack_logger program, located in the connectionTrackingProgram directory, will also be deployed on connt1, connt2, convsrc5, and convsr8 to monitor network connections.
