#!/usr/bin/env python3
"""
Simple Network Monitor (per-second sampling) with default 30s window aggregation.

- Samples every INTERVAL seconds (default 1.0s).
- Aggregates per-second samples into non-overlapping windows of --window seconds
  (default 30). For each window we compute the average of the per-second samples
  in that window; final statistics are computed over those window-averages.
- Also prints per-second (raw) statistics alongside window-averaged statistics.
- Use --iface to collect per-interface counters using `ip -s link`.
- Use --duration to run for a fixed time (seconds) or run until Ctrl-C/SIGTERM.
"""

import argparse
import psutil
import signal
import sys
import time
import subprocess
from types import SimpleNamespace
from math import sqrt
from typing import Optional, List, Tuple

INTERVAL = 1.0  # sampling interval in seconds


def to_mbps(byte_delta: int, seconds: float) -> float:
    if seconds <= 0:
        return 0.0
    return (max(0, byte_delta) * 8.0) / seconds / 1_000_000.0


def to_pps(pkt_delta: int, seconds: float) -> float:
    if seconds <= 0:
        return 0.0
    return max(0, pkt_delta) / seconds


def mean(values: List[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def sample_std(values: List[float]) -> float:
    n = len(values)
    if n <= 1:
        return 0.0
    m = mean(values)
    return sqrt(sum((x - m) ** 2 for x in values) / (n - 1))


def percentile(sorted_values: List[float], p: float) -> float:
    n = len(sorted_values)
    if n == 0:
        return 0.0
    if n == 1:
        return sorted_values[0]
    if p <= 0:
        return sorted_values[0]
    if p >= 100:
        return sorted_values[-1]
    pos = (p / 100.0) * (n - 1)
    lower = int(pos)
    upper = min(lower + 1, n - 1)
    frac = pos - lower
    return sorted_values[lower] * (1 - frac) + sorted_values[upper] * frac


def nonparam_ci(values: List[float], lower_p=2.5, upper_p=97.5) -> Tuple[float, float]:
    srt = sorted(values)
    return percentile(srt, lower_p), percentile(srt, upper_p)


def stats(values: List[float]):
    if not values:
        return dict(n=0, mean=0.0, std=0.0, min=0.0, max=0.0, ci=(0.0, 0.0))
    return dict(
        n=len(values),
        mean=mean(values),
        std=sample_std(values),
        min=min(values),
        max=max(values),
        ci=nonparam_ci(values),
    )


def fmt(title: str, unit: str, s: dict) -> str:
    return (
        f"{title} [{unit}] - n={s['n']}, "
        f"mean={s['mean']:.2f}, std={s['std']:.2f}, "
        f"min={s['min']:.2f}, max={s['max']:.2f}, "
        f"95% CI [{s['ci'][0]:.2f}, {s['ci'][1]:.2f}]"
    )


def collect_interface_counters_ip(iface: str) -> Optional[SimpleNamespace]:
    if not iface:
        return None
    try:
        out = subprocess.check_output(
            ["ip", "-s", "link", "show", "dev", iface],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        lines = out.splitlines()
        rx_idx = next((i for i, l in enumerate(lines) if l.strip().startswith("RX:")), None)
        tx_idx = next((i for i, l in enumerate(lines) if l.strip().startswith("TX:")), None)
        if rx_idx is None or tx_idx is None:
            return None

        def find_numeric_line(start_idx: int) -> Optional[List[int]]:
            i = start_idx + 1
            while i < len(lines):
                ln = lines[i].strip()
                if ln == "":
                    i += 1
                    continue
                if any(ch.isdigit() for ch in ln):
                    tokens = [tok for tok in ln.split() if any(c.isdigit() for c in tok)]
                    try:
                        return list(map(int, tokens))
                    except ValueError:
                        pass
                i += 1
            return None

        rx_vals = find_numeric_line(rx_idx)
        tx_vals = find_numeric_line(tx_idx)
        if not rx_vals or not tx_vals:
            return None

        return SimpleNamespace(
            bytes_recv=rx_vals[0],
            packets_recv=rx_vals[1] if len(rx_vals) > 1 else 0,
            bytes_sent=tx_vals[0],
            packets_sent=tx_vals[1] if len(tx_vals) > 1 else 0,
        )
    except Exception:
        return None


def monitor(iface: Optional[str] = None, duration: Optional[float] = None, window: int = 30):
    # Per-second accumulators (raw samples)
    sys_mbps_rx, sys_mbps_tx, sys_mbps_total = [], [], []
    sys_pps_rx, sys_pps_tx, sys_pps_total = [], [], []

    if_mbps_rx = [] if iface else None
    if_mbps_tx = [] if iface else None
    if_mbps_total = [] if iface else None
    if_pps_rx = [] if iface else None
    if_pps_tx = [] if iface else None
    if_pps_total = [] if iface else None

    # Window buffers and aggregated lists (window-averages)
    buf_sys_mbps_rx, buf_sys_mbps_tx, buf_sys_mbps_total = [], [], []
    buf_sys_pps_rx, buf_sys_pps_tx, buf_sys_pps_total = [], [], []
    agg_sys_mbps_rx, agg_sys_mbps_tx, agg_sys_mbps_total = [], [], []
    agg_sys_pps_rx, agg_sys_pps_tx, agg_sys_pps_total = [], [], []

    buf_if_mbps_rx = [] if iface else None
    buf_if_mbps_tx = [] if iface else None
    buf_if_mbps_total = [] if iface else None
    buf_if_pps_rx = [] if iface else None
    buf_if_pps_tx = [] if iface else None
    buf_if_pps_total = [] if iface else None
    agg_if_mbps_rx = [] if iface else None
    agg_if_mbps_tx = [] if iface else None
    agg_if_mbps_total = [] if iface else None
    agg_if_pps_rx = [] if iface else None
    agg_if_pps_tx = [] if iface else None
    agg_if_pps_total = [] if iface else None

    prev_sys = psutil.net_io_counters()
    prev_if = collect_interface_counters_ip(iface) if iface else None
    start_t = time.monotonic()
    last_t = start_t

    stop_requested = False

    def on_term(signum, frame):
        nonlocal stop_requested
        stop_requested = True

    signal.signal(signal.SIGTERM, on_term)
    try:
        signal.signal(signal.SIGINT, on_term)
    except Exception:
        pass

    print(f"Collecting per-second samples every {INTERVAL:.2f}s... Press Ctrl-C to show summary.", file=sys.stderr)
    if window > 1:
        print(f"Aggregating per-{window}s windows for statistics (default = 30s).", file=sys.stderr)

    try:
        while not stop_requested:
            if duration is not None:
                now_total = time.monotonic()
                if now_total - start_t >= duration:
                    break

            next_sample_time = last_t + INTERVAL
            to_sleep = next_sample_time - time.monotonic()
            if to_sleep > 0:
                time.sleep(to_sleep)

            now = time.monotonic()
            elapsed = now - last_t
            if elapsed <= 0:
                elapsed = INTERVAL
            last_t = now

            # System counters (psutil)
            cur_sys = psutil.net_io_counters()
            d_sent_b = cur_sys.bytes_sent - prev_sys.bytes_sent
            d_recv_b = cur_sys.bytes_recv - prev_sys.bytes_recv
            d_sent_p = cur_sys.packets_sent - prev_sys.packets_sent
            d_recv_p = cur_sys.packets_recv - prev_sys.packets_recv

            s_rx_mbps = to_mbps(d_recv_b, elapsed)
            s_tx_mbps = to_mbps(d_sent_b, elapsed)
            s_tot_mbps = s_rx_mbps + s_tx_mbps

            s_rx_pps = to_pps(d_recv_p, elapsed)
            s_tx_pps = to_pps(d_sent_p, elapsed)
            s_tot_pps = s_rx_pps + s_tx_pps

            sys_mbps_rx.append(s_rx_mbps)
            sys_mbps_tx.append(s_tx_mbps)
            sys_mbps_total.append(s_tot_mbps)
            sys_pps_rx.append(s_rx_pps)
            sys_pps_tx.append(s_tx_pps)
            sys_pps_total.append(s_tot_pps)

            # add to window buffers
            buf_sys_mbps_rx.append(s_rx_mbps)
            buf_sys_mbps_tx.append(s_tx_mbps)
            buf_sys_mbps_total.append(s_tot_mbps)
            buf_sys_pps_rx.append(s_rx_pps)
            buf_sys_pps_tx.append(s_tx_pps)
            buf_sys_pps_total.append(s_tot_pps)

            prev_sys = cur_sys

            # Interface counters via ip -s link (if requested)
            if iface:
                cur_if = collect_interface_counters_ip(iface)
                if cur_if and prev_if:
                    di_sent_b = cur_if.bytes_sent - prev_if.bytes_sent
                    di_recv_b = cur_if.bytes_recv - prev_if.bytes_recv
                    di_sent_p = cur_if.packets_sent - prev_if.packets_sent
                    di_recv_p = cur_if.packets_recv - prev_if.packets_recv

                    i_rx_mbps = to_mbps(di_recv_b, elapsed)
                    i_tx_mbps = to_mbps(di_sent_b, elapsed)
                    i_tot_mbps = i_rx_mbps + i_tx_mbps

                    i_rx_pps = to_pps(di_recv_p, elapsed)
                    i_tx_pps = to_pps(di_sent_p, elapsed)
                    i_tot_pps = i_rx_pps + i_tx_pps

                    if_mbps_rx.append(i_rx_mbps)
                    if_mbps_tx.append(i_tx_mbps)
                    if_mbps_total.append(i_tot_mbps)
                    if_pps_rx.append(i_rx_mbps if False else i_rx_pps)  # keep structure; real values appended properly below
                    # Properly append PPS values:
                    if_pps_rx.append(i_rx_pps)
                    if_pps_tx.append(i_tx_pps)
                    if_pps_total.append(i_tot_pps)

                    # add to interface window buffers
                    buf_if_mbps_rx.append(i_rx_mbps)
                    buf_if_mbps_tx.append(i_tx_mbps)
                    buf_if_mbps_total.append(i_tot_mbps)
                    buf_if_pps_rx.append(i_rx_pps)
                    buf_if_pps_tx.append(i_tx_pps)
                    buf_if_pps_total.append(i_tot_pps)

                prev_if = cur_if

            # If a full window is collected, compute averages and store in aggregated lists
            if window > 1:
                if len(buf_sys_mbps_total) >= window:
                    # system window averages
                    agg_sys_mbps_rx.append(mean(buf_sys_mbps_rx))
                    agg_sys_mbps_tx.append(mean(buf_sys_mbps_tx))
                    agg_sys_mbps_total.append(mean(buf_sys_mbps_total))
                    agg_sys_pps_rx.append(mean(buf_sys_pps_rx))
                    agg_sys_pps_tx.append(mean(buf_sys_pps_tx))
                    agg_sys_pps_total.append(mean(buf_sys_pps_total))
                    # clear buffers for next window (tumbling windows)
                    buf_sys_mbps_rx.clear()
                    buf_sys_mbps_tx.clear()
                    buf_sys_mbps_total.clear()
                    buf_sys_pps_rx.clear()
                    buf_sys_pps_tx.clear()
                    buf_sys_pps_total.clear()

                if iface and buf_if_mbps_total is not None and len(buf_if_mbps_total) >= window:
                    agg_if_mbps_rx.append(mean(buf_if_mbps_rx))
                    agg_if_mbps_tx.append(mean(buf_if_mbps_tx))
                    agg_if_mbps_total.append(mean(buf_if_mbps_total))
                    agg_if_pps_rx.append(mean(buf_if_pps_rx))
                    agg_if_pps_tx.append(mean(buf_if_pps_tx))
                    agg_if_pps_total.append(mean(buf_if_pps_total))
                    buf_if_mbps_rx.clear()
                    buf_if_mbps_tx.clear()
                    buf_if_mbps_total.clear()
                    buf_if_pps_rx.clear()
                    buf_if_pps_tx.clear()
                    buf_if_pps_total.clear()

    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"\nError during monitoring loop: {e}", file=sys.stderr)

    # If a partial window remains, include it as a final (shorter) window average
    if window > 1:
        if buf_sys_mbps_total:
            agg_sys_mbps_rx.append(mean(buf_sys_mbps_rx))
            agg_sys_mbps_tx.append(mean(buf_sys_mbps_tx))
            agg_sys_mbps_total.append(mean(buf_sys_mbps_total))
            agg_sys_pps_rx.append(mean(buf_sys_pps_rx))
            agg_sys_pps_tx.append(mean(buf_sys_pps_tx))
            agg_sys_pps_total.append(mean(buf_sys_pps_total))
            buf_sys_mbps_rx.clear()
            buf_sys_mbps_tx.clear()
            buf_sys_mbps_total.clear()
            buf_sys_pps_rx.clear()
            buf_sys_pps_tx.clear()
            buf_sys_pps_total.clear()

        if iface and buf_if_mbps_total is not None and buf_if_mbps_total:
            agg_if_mbps_rx.append(mean(buf_if_mbps_rx))
            agg_if_mbps_tx.append(mean(buf_if_mbps_tx))
            agg_if_mbps_total.append(mean(buf_if_mbps_total))
            agg_if_pps_rx.append(mean(buf_if_pps_rx))
            agg_if_pps_tx.append(mean(buf_if_pps_tx))
            agg_if_pps_total.append(mean(buf_if_pps_total))
            buf_if_mbps_rx.clear()
            buf_if_mbps_tx.clear()
            buf_if_mbps_total.clear()
            buf_if_pps_rx.clear()
            buf_if_pps_tx.clear()
            buf_if_pps_total.clear()

    # Summary output
    print("\n=== Network Monitor Summary ===")
    print(f"Sampling interval: {INTERVAL:.2f}s, aggregation window: {window}s")
    print("Bandwidth in Mbps; Packets in PPS\n")

    # Per-second summary (raw)
    print("Per-second statistics (raw samples):")
    print(fmt("System Mbps (total)", "Mbps", stats(sys_mbps_total)))
    print(fmt("System Mbps (rx)", "Mbps", stats(sys_mbps_rx)))
    print(fmt("System Mbps (tx)", "Mbps", stats(sys_mbps_tx)))
    print(fmt("System PPS (total)", "pps", stats(sys_pps_total)))
    print(fmt("System PPS (rx)", "pps", stats(sys_pps_rx)))
    print(fmt("System PPS (tx)", "pps", stats(sys_pps_tx)))

    if iface:
        print(f"\nInterface: {iface} (per-second)")
        print(fmt("Iface Mbps (total)", "Mbps", stats(if_mbps_total or [])))
        print(fmt("Iface Mbps (rx)", "Mbps", stats(if_mbps_rx or [])))
        print(fmt("Iface Mbps (tx)", "Mbps", stats(if_mbps_tx or [])))
        print(fmt("Iface PPS (total)", "pps", stats(if_pps_total or [])))
        print(fmt("Iface PPS (rx)", "pps", stats(if_pps_rx or [])))
        print(fmt("Iface PPS (tx)", "pps", stats(if_pps_tx or [])))

    # Aggregated-over-window summary (if window > 1)
    if window > 1:
        print(f"\nWindow-averaged statistics (each value is average over {window}s):")
        print(fmt("System Mbps (total) - window-avg", "Mbps", stats(agg_sys_mbps_total)))
        print(fmt("System Mbps (rx) - window-avg", "Mbps", stats(agg_sys_mbps_rx)))
        print(fmt("System Mbps (tx) - window-avg", "Mbps", stats(agg_sys_mbps_tx)))
        print(fmt("System PPS (total) - window-avg", "pps", stats(agg_sys_pps_total)))
        print(fmt("System PPS (rx) - window-avg", "pps", stats(agg_sys_pps_rx)))
        print(fmt("System PPS (tx) - window-avg", "pps", stats(agg_sys_pps_tx)))

        if iface:
            print(f"\nInterface: {iface} (window-avg)")
            print(fmt("Iface Mbps (total) - window-avg", "Mbps", stats(agg_if_mbps_total or [])))
            print(fmt("Iface Mbps (rx) - window-avg", "Mbps", stats(agg_if_mbps_rx or [])))
            print(fmt("Iface Mbps (tx) - window-avg", "Mbps", stats(agg_if_mbps_tx or [])))
            print(fmt("Iface PPS (total) - window-avg", "pps", stats(agg_if_pps_total or [])))
            print(fmt("Iface PPS (rx) - window-avg", "pps", stats(agg_if_pps_rx or [])))
            print(fmt("Iface PPS (tx) - window-avg", "pps", stats(agg_if_pps_tx or [])))


def main():
    parser = argparse.ArgumentParser(description="Per-second network monitor with default 30s window aggregation.")
    parser.add_argument("--iface", help="Interface to track using `ip -s link` (e.g., eth0)")
    parser.add_argument("--duration", type=float, default=None, help="Optional duration in seconds to run (default: run until Ctrl-C)")
    parser.add_argument("--window", type=int, default=30, help="Aggregation window in seconds (default 30). Use 1 for per-second stats.")
    args = parser.parse_args()

    if args.window <= 0:
        print("Error: --window must be a positive integer.", file=sys.stderr)
        sys.exit(2)

    monitor(args.iface, args.duration, args.window)


if __name__ == "__main__":
    main()
