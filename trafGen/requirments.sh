#!/usr/bin/env bash
# conntrack_stress.sh - script to allocate and test 2M conntrack entries
# Requires: root privileges, conntrack-tools, tcp_client binary in current directory

set -euo pipefail

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
  echo "Error: This script must be run as root." >&2
  exit 1
fi

# Configuration parameters
TARGET_ENTRIES=2000000         # Desired number of conntrack entries
HASHSIZE=$((TARGET_ENTRIES / 4))  # Recommended: ~1/4 of max entries
DURATION=300                   # TIME_WAIT / FIN_WAIT timeout (seconds)
CONCURRENCY=$TARGET_ENTRIES    # Number of concurrent connections to hold
TOTAL_CONNECTIONS=$((TARGET_ENTRIES * 2))  # Total connections to attempt
SERVER_IP="127.0.0.1"        # Target server IP
SERVER_PORT=5000               # Target server port (tcp_client -p)

# 1. Tune kernel parameters via sysctl
echo "[*] Applying sysctl settings..."
SYSCTL_SETTINGS=(
  "net.netfilter.nf_conntrack_max=${TARGET_ENTRIES}"
  "net.netfilter.nf_conntrack_buckets=${HASHSIZE}"
  "net.ipv4.tcp_tw_reuse=0"
  "net.ipv4.tcp_fin_timeout=${DURATION}"
  "net.core.netdev_max_backlog=250000"
  "net.core.rmem_max=16777216"
  "net.core.wmem_max=16777216"
)
for setting in "${SYSCTL_SETTINGS[@]}"; do
  sysctl -w $setting
done

# 2. Adjust module hashsize (if writable)
HASHPATH="/sys/module/nf_conntrack/parameters/hashsize"
if [[ -w "$HASHPATH" ]]; then
  echo "[*] Setting conntrack hashsize to $HASHSIZE"
  echo $HASHSIZE > "$HASHPATH"
else
  echo "[!] Cannot write hashsize at $HASHPATH."
  echo "    Please ensure nf_conntrack module is loaded with hashsize=$HASHSIZE"
fi

# 3. Increase global file descriptor cap
echo "[*] Increasing fs.nr_open to $((TARGET_ENTRIES * 2))"
sysctl -w fs.nr_open=$((TARGET_ENTRIES * 2))

# 4. Raise ulimit for this shell
echo "[*] Raising ulimit for open files to $((TARGET_ENTRIES * 2))"
ulimit -n $((TARGET_ENTRIES * 2)) || echo "[!] Failed to raise ulimit. Check PAM limits or systemd settings."

echo
# 5. Flush existing conntrack entries
echo "[*] Flushing existing conntrack entries..."
conntrack -F

echo
# 6. Start traffic generation
echo "[*] Starting tcp_client: total=$TOTAL_CONNECTIONS, concurrency=$CONCURRENCY"
./tcp_client -s $SERVER_IP -p $SERVER_PORT -n $TOTAL_CONNECTIONS -c $CONCURRENCY &
CLIENT_PID=$!

echo
# 7. Monitor conntrack usage
echo "[*] Monitoring conntrack_count (press Ctrl-C to stop)"
watch -n1 "echo \\nConnected=$(cat /proc/sys/net/netfilter/nf_conntrack_count) \\nMax=$(cat /proc/sys/net/netfilter/nf_conntrack_max)"

# Cleanup on exit
echo "\n[*] Stopping tcp_client (PID $CLIENT_PID)"
kill $CLIENT_PID

echo "[*] Done."

