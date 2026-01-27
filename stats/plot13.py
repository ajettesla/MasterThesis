#!/usr/bin/env python3
"""
plot_full.py  (Python 3.8 compatible)

Full integrated plotting + stats tool (restores plot11-style CDFs and adds plot29 features).

WHAT THIS SCRIPT PRODUCES (when flags are enabled):
1) Scatter plots (per run/prefix) for:
   - Delay (convsrc2/*_ca.csv)  [QQ trimming APPLIED if -qq/--qq-low/--qq-high and not --no-qq]
   - CPU   (connt1/*_cm_monitor.csv) + linear regression line
   - Net   (connt1/*_n_monitor.csv)  + linear regression line
   Notes:
   - CPU/Net are NOT quantile-trimmed. Only filter: mask = vals > 0.0001
   - Axes start at 0 for ALL scatter plots (x and y), using relative time for CPU/Net (t - t0).
   - Windowing is applied for CPU/Net scatter (conntrack window, fallback net-shift, fallback full range).

2) CDF plots (plot11 format):
   - Per-mode across concurrencies (e.g., ftfw_tcp: c1000,c2000,c4000,c8000)
   - Per-concurrency across modes (e.g., c1000: ftfw_tcp, ftfw_udp, notrack_udp, notrack_tcp)
   - Ping CDF overlay on every CDF plot (if ping file exists)
   Style:
   - Solid lines for data
   - Median (P50) drop-lines only
   - x-axis ticks labeled in "ms" when range is small (<=20ms range), otherwise matplotlib decides.
   - Axes start at 0.
   - X max follows QQ-trimmed high bound (when QQ enabled), to avoid “zoomed out”.

3) Violin plots (optional) per group (same grouping as CDF plots).

4) 2D Error plots:
   - Per-mode (constant mode, varying rate): errorbars for c1000..c8000, with REGRESSION line (ONLY here).
   - 2x2 grid of modes (same constant-mode/vary-rate points; regression shown in the individual plots, optional in grid).
   - Per-concurrency across modes (constant rate, varying mode): errorbars for modes; NO regression.
   - c2000 comparison across modes (same as per-concurrency for c2000), NO regression.
   Notes:
   - Uses pooled mean/std across per-prefix windows (sample-size-aware pooling like plot11).

5) Summary files:
   - violin/summary.txt  (per experiment: cpu/net min/max/mean/median/std, delay min/max/mean/median/std/cv,
                          delay p25/p50/p75/p95/p99)
   - violin/cdf.txt      (P25, P50, P75 only)

PERFORMANCE:
- Uses ThreadPoolExecutor across experiments (--threads)
- Verbose logging with --verbose
- Emits warnings when files/columns are missing (no silent pass).

DATA LAYOUT ASSUMED (same as plot11/plot29):
  base/
    convsrc2/<folder>/*_ca.csv                 (delay; column: time_diff_ns)
    connt1/<folder>/*_cm_monitor.csv           (cpu; columns: time, proc_cpu_cycles_ghz OR proc_cpu_percent,
                                               optional conntrack_count)
    connt1/<folder>/*_n_monitor.csv            (net; columns: time, iface_tx_bytes_per_sec)

PING FILE:
  /opt/results/ping/ping_const_{int(min_delay)}ms_0ms_172-16-3-4_data.csv
  Expected column: RTT_ms (your data)
"""

import argparse
import csv
import gc
import math
import os
import sys
import threading
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import yaml
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator

warnings.filterwarnings("ignore", message=".*empty slice.*")

# Matplotlib colormap compatibility
try:
    import matplotlib.colormaps as mcol  # mpl 3.7+
except Exception:
    import matplotlib.cm as mcol


# -----------------------
# Constants
# -----------------------
DEFAULT_CDF_BINS = 2048
DEFAULT_QQ_SAMPLE_CAP = 10000
DEFAULT_VIOLIN_SAMPLE_CAP = 200_000
DEFAULT_MIN_DELAY_MS = 1.0

MODES = ["ftfw_tcp", "ftfw_udp", "notrack_udp", "notrack_tcp"]
CONCS = ["c1000", "c2000", "c4000", "c8000"]

SCATTER_COLOR = "#4c78a8"
MODE_COLORS = {
    "ftfw_tcp": "#1f77b4",
    "ftfw_udp": "#ff7f0e",
    "notrack_udp": "#2ca02c",
    "notrack_tcp": "#d62728",
}
CONC_COLORS = {
    "c1000": "#1f77b4",
    "c2000": "#ff7f0e",
    "c4000": "#2ca02c",
    "c8000": "#d62728",
}

PRINT_LOCK = threading.Lock()


# -----------------------
# Logging helpers
# -----------------------
def _log(prefix: str, msg: str) -> None:
    with PRINT_LOCK:
        print(f"{prefix} {msg}", flush=True)


def info(msg: str, verbose: bool = True) -> None:
    if verbose:
        _log("[INFO]", msg)


def warn(msg: str) -> None:
    _log("[WARN]", msg)


def err(msg: str) -> None:
    _log("[ERROR]", msg)


# -----------------------
# Utility helpers
# -----------------------
def safe_get_cmap(name: str):
    try:
        return mcol.get_cmap(name)
    except Exception:
        try:
            import matplotlib.cm as cm
            return cm.get_cmap(name)
        except Exception:
            return plt.cm.get_cmap(name)


def parse_config(config_path: str) -> List[dict]:
    with open(config_path, "r") as f:
        cfg = yaml.safe_load(f) or {}
    exps = cfg.get("experiments", [])
    if not isinstance(exps, list):
        raise ValueError("Config missing 'experiments' list")
    return exps


def parse_exclude(exclude_str) -> set:
    if not exclude_str or not str(exclude_str).strip():
        return set()
    out = set()
    for part in str(exclude_str).split(","):
        p = part.strip()
        if not p:
            continue
        if "-" in p:
            try:
                a, b = map(int, p.split("-"))
                out.update(range(a, b + 1))
            except Exception:
                continue
        else:
            try:
                out.add(int(p))
            except Exception:
                continue
    return out


def get_mode_client(folder: str) -> Tuple[Optional[str], Optional[str]]:
    parts = folder.split("_")
    mode = "_".join(parts[:2]) if len(parts) >= 2 else None
    client = next((p for p in parts if p.startswith("c") and p[1:].isdigit()), None)
    return mode, client


def parse_label(folder: str) -> str:
    # "ftfw_tcp_c2000_..." -> "ftfw tcp c2000"
    parts = folder.split("_")
    if len(parts) >= 3:
        return " ".join(parts[:3])
    return " ".join(parts)


def _format_x_as_sample_index(ax, n_points: int) -> None:
    ax.set_xlim(0, max(n_points, 1) * 1.02)
    ax.xaxis.set_major_locator(MaxNLocator(nbins=6, integer=True))
    ax.ticklabel_format(axis="x", style="sci", scilimits=(0, 0), useMathText=True)
    ax.set_xlabel("Sample index")


def _set_integer_ms_xticks(ax, xmin: float, xmax: float) -> None:
    xmin = 0.0
    xmin_int = int(math.floor(xmin))
    xmax_int = int(math.ceil(xmax))
    if xmax_int <= xmin_int:
        ticks = [xmin_int]
    else:
        if xmax_int - xmin_int > 20:
            return
        ticks = np.arange(xmin_int, xmax_int + 1)
    ax.set_xticks(ticks)
    ax.set_xticklabels([f"{int(t)}ms" for t in ticks], rotation=0)


# -----------------------
# Ping loader
# -----------------------
def load_ping_reference(min_delay_ms: float, verbose: bool) -> Optional[np.ndarray]:
    # Your file is: ping/ping_const_1ms_0ms_..._data.csv and column RTT_ms
    # Use int(min_delay_ms) for filename as in earlier scripts.
    fpath = Path(f"/opt/results/ping/ping_const_{int(min_delay_ms)}ms_0ms_172-16-3-4_data.csv")
    if not fpath.exists():
        warn(f"Ping file not found: {fpath}")
        return None

    try:
        df = pd.read_csv(fpath)
    except Exception as e:
        warn(f"Could not read ping file {fpath.name}: {e}")
        return None

    # Prefer RTT_ms, otherwise first numeric column
    col = None
    if "RTT_ms" in df.columns:
        col = "RTT_ms"
    else:
        # fallback: try any column containing rtt/delay/time
        for c in df.columns:
            lc = c.lower()
            if "rtt" in lc or "delay" in lc or "time" in lc:
                col = c
                break
        if col is None and len(df.columns) > 0:
            # last resort: first column
            col = df.columns[0]

    if col is None:
        warn(f"Ping file has no usable column: {fpath.name}")
        return None

    try:
        vals = pd.to_numeric(df[col], errors="coerce").dropna().astype(float).values
    except Exception as e:
        warn(f"Ping column '{col}' not numeric: {e}")
        return None

    # If units look like ns, convert
    if vals.size and np.nanmedian(vals) > 10000:
        vals = vals / 1_000_000.0

    vals = vals[(vals > 0.0) & np.isfinite(vals)]
    if vals.size == 0:
        warn("Ping data empty after filtering.")
        return None

    info(f"Ping loaded: N={vals.size}, min={vals.min():.3f}, max={vals.max():.3f}, median={np.median(vals):.3f}", verbose)
    return vals


def apply_delay_qq(vals: np.ndarray, qq: Optional[float], qq_low: Optional[float], qq_high: Optional[float], no_qq: bool) -> Tuple[np.ndarray, Optional[Dict[str, float]]]:
    if vals.size == 0 or no_qq:
        return vals, None

    low_bound = None
    high_bound = None

    if qq_low is not None:
        try:
            ql = float(qq_low)
            if 0.0 <= ql <= 1.0:
                low_bound = float(np.quantile(vals, ql))
        except Exception:
            low_bound = None

    if qq_high is not None:
        try:
            qh = float(qq_high)
            if 0.0 <= qh <= 1.0:
                high_bound = float(np.quantile(vals, qh))
        except Exception:
            high_bound = None
    elif qq is not None:
        try:
            qh = float(qq)
            if 0.0 <= qh <= 1.0:
                high_bound = float(np.quantile(vals, qh))
        except Exception:
            high_bound = None

    out = vals
    if low_bound is not None:
        out = out[out >= low_bound]
    if high_bound is not None:
        out = out[out <= high_bound]

    qb = None
    if low_bound is not None or high_bound is not None:
        qb = {"low": low_bound, "high": high_bound}
    return out, qb


# -----------------------
# CDF histogram building (plot11-style, memory conscious)
# -----------------------
def _compute_quantile_bounds(sampled: np.ndarray, qq: Optional[float], qq_low: Optional[float], qq_high: Optional[float]) -> Tuple[Optional[float], Optional[float]]:
    if sampled.size == 0:
        return None, None

    low_bound = None
    high_bound = None

    if qq_low is not None:
        try:
            ql = float(qq_low)
            if 0.0 <= ql <= 1.0:
                low_bound = float(np.quantile(sampled, ql))
        except Exception:
            low_bound = None

    if qq_high is not None:
        try:
            qh = float(qq_high)
            if 0.0 <= qh <= 1.0:
                high_bound = float(np.quantile(sampled, qh))
        except Exception:
            high_bound = None
    elif qq is not None:
        try:
            qh = float(qq)
            if 0.0 <= qh <= 1.0:
                high_bound = float(np.quantile(sampled, qh))
        except Exception:
            high_bound = None

    return low_bound, high_bound


def _scott_bins_estimate(sampled: np.ndarray, xmin: float, xmax: float, min_bins: int, max_bins: int) -> int:
    if sampled.size < 2:
        return min_bins
    sigma = float(np.nanstd(sampled))
    n = int(sampled.size)
    if sigma <= 0 or not np.isfinite(sigma):
        return min_bins
    bw = 3.5 * sigma * (n ** (-1.0 / 3.0))
    if bw <= 0 or not np.isfinite(bw):
        return min_bins
    nb = int(math.ceil((xmax - xmin) / bw))
    nb = max(min_bins, nb)
    nb = min(max_bins, nb)
    return nb


def get_delay_histogram_plot11_style(
    delay_folder: Path,
    exclude: set,
    min_delay_ms: float,
    qq: Optional[float],
    qq_low: Optional[float],
    qq_high: Optional[float],
    no_qq: bool,
    qq_sample_cap: int,
    bins_method: str,
    fixed_bins: int,
    scott_min_bins: int,
    scott_max_bins: int,
    verbose: bool,
) -> Dict:
    """
    Two-pass:
      Pass1: sample up to qq_sample_cap per file (>=min_delay) to compute QQ bounds and estimate x_max.
      Pass2: build histogram with shared bin_edges for this experiment (min_delay..x_max).
    """
    files = sorted(delay_folder.glob("*_ca.csv"))
    if len(files) == 0:
        warn(f"No delay files found in {delay_folder}")
        return {"counts": np.zeros(1, dtype=np.int64), "bin_edges": np.array([min_delay_ms, min_delay_ms + 1e-6]), "qq_bound": None,
                "percent_ge_min": 0.0, "total_points": 0, "total_ge_min": 0, "bins_used": 1}

    rng = np.random.default_rng(42)

    total_points = 0
    total_ge_min = 0
    sampled_chunks = []

    # Pass 1: sampling
    for f in files:
        try:
            idx = int(f.name.split("_")[0])
        except Exception:
            idx = None
        if idx is not None and idx in exclude:
            continue

        try:
            df = pd.read_csv(f, usecols=["time_diff_ns"])
        except Exception as e:
            warn(f"Delay read failed: {f.name}: {e}")
            continue

        arr = df["time_diff_ns"].values.astype(np.float64) / 1_000_000.0
        arr = arr[np.isfinite(arr)]
        arr = arr[arr >= 0.0]
        total_points += int(arr.size)

        ge = arr[arr >= float(min_delay_ms)]
        if ge.size:
            total_ge_min += int(ge.size)
            if ge.size > qq_sample_cap:
                try:
                    samp = rng.choice(ge, size=qq_sample_cap, replace=False)
                except Exception:
                    samp = ge[:qq_sample_cap]
                sampled_chunks.append(samp)
            else:
                sampled_chunks.append(ge)

        del df
        gc.collect()

    sampled = np.concatenate(sampled_chunks) if sampled_chunks else np.array([], dtype=np.float64)

    low_bound = None
    high_bound = None
    if (not no_qq) and sampled.size > 0:
        low_bound, high_bound = _compute_quantile_bounds(sampled, qq=qq, qq_low=qq_low, qq_high=qq_high)

    # Choose x_max (CRITICAL for not being zoomed out):
    # - If QQ high bound exists -> use it
    # - else use max(sampled) (or min_delay if empty)
    if high_bound is not None and np.isfinite(high_bound):
        x_max = float(high_bound)
    elif sampled.size > 0:
        x_max = float(np.nanmax(sampled))
    else:
        x_max = float(min_delay_ms)

    x_max = max(x_max, float(min_delay_ms))

    # Decide bins for this experiment
    if bins_method == "scott" and sampled.size > 1:
        bins_used = _scott_bins_estimate(
            sampled=sampled,
            xmin=float(min_delay_ms),
            xmax=float(x_max),
            min_bins=scott_min_bins,
            max_bins=scott_max_bins,
        )
    else:
        bins_used = int(fixed_bins)

    bins_used = max(8, int(bins_used))

    bin_edges = np.linspace(min_delay_ms, x_max * 1.0001, bins_used + 1)
    counts = np.zeros(bins_used, dtype=np.int64)

    # Pass 2: histogram
    total_points2 = 0
    total_ge_min2 = 0

    for f in files:
        try:
            idx = int(f.name.split("_")[0])
        except Exception:
            idx = None
        if idx is not None and idx in exclude:
            continue

        try:
            df = pd.read_csv(f, usecols=["time_diff_ns"])
        except Exception as e:
            warn(f"Delay read failed (pass2): {f.name}: {e}")
            continue

        arr = df["time_diff_ns"].values.astype(np.float64) / 1_000_000.0
        arr = arr[np.isfinite(arr)]
        arr = arr[arr >= float(min_delay_ms)]

        total_points2 += int(arr.size)

        if (not no_qq) and low_bound is not None:
            arr = arr[arr >= low_bound]
        if (not no_qq) and high_bound is not None:
            arr = arr[arr <= high_bound]

        total_ge_min2 += int(arr.size)

        if arr.size:
            h, _ = np.histogram(arr, bins=bin_edges)
            counts += h.astype(np.int64)

        del df
        gc.collect()

    # percent is relative to (>=min_delay) samples in pass2 (that’s what we actually plot)
    pct_ge_min = (100.0 * total_ge_min2 / total_points2) if total_points2 > 0 else 0.0

    qq_bound = None
    if (not no_qq) and (low_bound is not None or high_bound is not None):
        qq_bound = {"low": low_bound, "high": high_bound}

    if verbose:
        info(
            f"Delay histogram built: files={len(files)}, bins={bins_used}, x_max={x_max:.3f}ms, "
            f"qq_bound={qq_bound}, kept={total_ge_min2}",
            verbose=True
        )

    return {
        "counts": counts,
        "bin_edges": bin_edges,
        "qq_bound": qq_bound,
        "percent_ge_min": float(pct_ge_min),
        "total_points": int(total_points),
        "total_ge_min": int(total_ge_min2),
        "bins_used": int(bins_used),
    }


# -----------------------
# Windowing for CPU/Net
# -----------------------
def find_conntrack_window(cm_df: pd.DataFrame, min_abs: float = 1000.0) -> Tuple[Optional[float], Optional[float]]:
    if cm_df is None or cm_df.empty:
        return None, None
    if "time" not in cm_df.columns:
        return None, None

    times = pd.to_numeric(cm_df["time"], errors="coerce").dropna().astype(float).values
    if times.size < 2:
        return None, None

    if "conntrack_count" in cm_df.columns:
        vals = pd.to_numeric(cm_df["conntrack_count"], errors="coerce").astype(float).values
        vals = vals[np.isfinite(vals)]
        if vals.size >= 3:
            diffs = np.abs(np.diff(vals))
            if diffs.size > 0:
                thr = max(0.2 * float(np.nanmax(diffs)), float(min_abs))
                jumps = np.where(diffs >= thr)[0]
                if jumps.size >= 2:
                    s = float(times[int(jumps[0] + 1)])
                    e = float(times[int(jumps[-1])])
                    if e > s:
                        return s, e

    # fallback: full range
    return float(times[0]), float(times[-1])


def detect_window_from_net_shift(net_df: pd.DataFrame, shift_frac: float = 0.5, shift_min_kib: float = 10.0, margin_s: float = 1.0) -> Tuple[Optional[float], Optional[float]]:
    if net_df is None or net_df.empty:
        return None, None
    if "time" not in net_df.columns or "iface_tx_bytes_per_sec" not in net_df.columns:
        return None, None

    times = pd.to_numeric(net_df["time"], errors="coerce").dropna().astype(float).values
    vals = pd.to_numeric(net_df["iface_tx_bytes_per_sec"], errors="coerce").astype(float).values / 1024.0
    if times.size < 2 or vals.size < 2:
        return None, None

    diffs = np.abs(np.diff(vals))
    max_diff = float(np.nanmax(diffs)) if diffs.size else 0.0
    thresh = max(shift_frac * max_diff, float(shift_min_kib))
    big = np.where(diffs >= thresh)[0]

    if big.size >= 2:
        first = int(big[0] + 1)
        last = int(big[-1] + 1)
        s = max(float(times[0]), float(times[first]) - margin_s)
        e = min(float(times[-1]), float(times[last]) + margin_s)
        if e > s:
            return s, e

    # fallback: active region
    max_val = float(np.nanmax(vals)) if vals.size else 0.0
    if max_val > 0:
        active = np.where(vals >= max(0.05 * max_val, 1.0))[0]
        if active.size:
            s = max(float(times[0]), float(times[int(active[0])]) - margin_s)
            e = min(float(times[-1]), float(times[int(active[-1])]) + margin_s)
            if e > s:
                return s, e

    return float(times[0]), float(times[-1])


def get_window_for_prefix(base: Path, folder: str, prefix: str, verbose: bool) -> Tuple[float, float, str]:
    """
    Determine [start,end] window for this run/prefix using:
      1) conntrack jumps in cm_monitor
      2) fallback net-shift in n_monitor
      3) fallback full range
    """
    cm_path = base / "connt1" / folder / f"{prefix}_cm_monitor.csv"
    net_path = base / "connt1" / folder / f"{prefix}_n_monitor.csv"

    cm_df = None
    net_df = None
    method = "unknown"

    if cm_path.exists():
        try:
            cm_df = pd.read_csv(cm_path)
        except Exception as e:
            warn(f"CM read failed: {cm_path.name}: {e}")
            cm_df = None

    if net_path.exists():
        try:
            net_df = pd.read_csv(net_path, usecols=["time", "iface_tx_bytes_per_sec"])
        except Exception as e:
            warn(f"NET read failed: {net_path.name}: {e}")
            net_df = None

    s, e = None, None
    if cm_df is not None:
        s, e = find_conntrack_window(cm_df, min_abs=1000.0)
        if s is not None and e is not None:
            method = "conntrack"
    if (s is None or e is None) and net_df is not None:
        s, e = detect_window_from_net_shift(net_df, shift_frac=0.5, shift_min_kib=10.0, margin_s=1.0)
        if s is not None and e is not None:
            method = "net-shift"

    if (s is None or e is None) and cm_df is not None and "time" in cm_df.columns:
        try:
            times = pd.to_numeric(cm_df["time"], errors="coerce").dropna().astype(float).values
            if times.size:
                s, e = float(times[0]), float(times[-1])
                method = "full-range"
        except Exception:
            pass

    if s is None or e is None:
        warn(f"Window not found for {folder}/{prefix}, using 0..0")
        return 0.0, 0.0, "none"

    if e <= s:
        warn(f"Bad window for {folder}/{prefix} (start>=end), using full range if possible")
        return float(s), float(e), method

    if verbose:
        info(f"Window {folder}/{prefix}: {s:.3f}..{e:.3f} ({method})", verbose=True)

    return float(s), float(e), method


# -----------------------
# Scatter plotters
# -----------------------
def plot_delay_scatter(delay_ms: np.ndarray, out_path: Path, title: str = "Delay scatter") -> None:
    n = int(delay_ms.size)
    if n == 0:
        return
    plt.figure(figsize=(10, 4))
    plt.scatter(np.arange(n), delay_ms, s=3.0, alpha=0.6, color=SCATTER_COLOR)
    ax = plt.gca()
    ax.set_title(title)
    _format_x_as_sample_index(ax, n)
    ax.set_ylabel("Delay (ms)")
    ax.set_xlim(left=0)
    ymax = float(np.nanmax(delay_ms)) if n else 0.0
    ax.set_ylim(0, max(1e-6, ymax * 1.1))
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(str(out_path), bbox_inches="tight", pad_inches=0.1)
    plt.close()
    gc.collect()




def _safe_linreg(x: np.ndarray, y: np.ndarray) -> Optional[Tuple[float, float]]:
    if x.size < 2 or y.size < 2:
        return None
    if not np.isfinite(x).all() or not np.isfinite(y).all():
        m = np.isfinite(x) & np.isfinite(y)
        x = x[m]
        y = y[m]
    if x.size < 2:
        return None
    try:
        slope, inter = np.polyfit(x, y, 1)
        return float(slope), float(inter)
    except Exception:
        return None


def plot_time_scatter_with_regression(
    t_rel: np.ndarray,
    vals: np.ndarray,
    out_path: Path,
    title: str,
    ylabel: str,
) -> None:
    if vals.size < 2:
        return
    plt.figure(figsize=(10, 4))
    plt.scatter(t_rel, vals, s=3.0, alpha=0.6, color=SCATTER_COLOR)

    # regression
    lr = _safe_linreg(t_rel, vals)
    if lr is not None:
        slope, inter = lr
        xs = np.linspace(float(np.min(t_rel)), float(np.max(t_rel)), 100)
        ys = slope * xs + inter
        plt.plot(xs, ys, "r--", lw=1.5, label=f"m={slope:.4f}")
        plt.legend(frameon=False)

    ax = plt.gca()
    ax.set_title(title)
    ax.set_xlabel("Time (s) (relative)")
    ax.set_ylabel(ylabel)

    # axes start at 0 (both)
    ax.set_xlim(left=0)
    ax.set_ylim(bottom=0)

    # headroom
    ymax = float(np.nanmax(vals)) if vals.size else 0.0
    ax.set_ylim(0, max(1e-6, ymax * 1.1))

    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(str(out_path), bbox_inches="tight", pad_inches=0.1)
    plt.close()
    gc.collect()


# -----------------------
# Stats helpers
# -----------------------
def _cv(mean: float, std: float) -> float:
    if mean == 0.0 or not np.isfinite(mean) or not np.isfinite(std):
        return 0.0
    return float(std / mean * 100.0)


def _nanmin(a: np.ndarray) -> float:
    return float(np.nanmin(a)) if a.size else float("nan")


def _nanmax(a: np.ndarray) -> float:
    return float(np.nanmax(a)) if a.size else float("nan")


def _nanmean(a: np.ndarray) -> float:
    return float(np.nanmean(a)) if a.size else float("nan")


def _nanstd(a: np.ndarray) -> float:
    return float(np.nanstd(a, ddof=1)) if a.size > 1 else (0.0 if a.size == 1 else float("nan"))


def _nanmedian(a: np.ndarray) -> float:
    return float(np.nanmedian(a)) if a.size else float("nan")


def _percentile(a: np.ndarray, p: float) -> float:
    if a.size == 0:
        return float("nan")
    return float(np.nanpercentile(a, p))


def _pooled_stats_from_parts(parts: List[Dict], mean_key: str, std_key: str, count_key: str) -> Tuple[float, float, int]:
    """
    Pool mean/std across runs using sample-size-aware pooling (like plot11).
    parts[i] has mean, std, and count.
    """
    total_n = 0
    means = []
    vars_ = []
    ns = []

    for p in parts:
        try:
            n = int(p.get(count_key) or 0)
        except Exception:
            n = 0
        if n <= 0:
            continue
        try:
            m = float(p.get(mean_key))
        except Exception:
            m = float("nan")
        try:
            s = float(p.get(std_key))
        except Exception:
            s = float("nan")
        v = (s * s) if np.isfinite(s) else float("nan")

        means.append(m)
        vars_.append(v)
        ns.append(n)
        total_n += n

    if total_n == 0:
        return float("nan"), float("nan"), 0

    pooled_mean = float(np.sum([m * n for m, n in zip(means, ns)]) / total_n)

    S = 0.0
    for m, v, n in zip(means, vars_, ns):
        if np.isfinite(v):
            S += (n - 1) * v
        S += n * ((m - pooled_mean) ** 2)

    if total_n > 1:
        pooled_var = S / (total_n - 1)
        pooled_std = math.sqrt(max(pooled_var, 0.0))
    else:
        pooled_std = 0.0

    return float(pooled_mean), float(pooled_std), int(total_n)


# -----------------------
# Data structures
# -----------------------
@dataclass
class DelayHist:
    counts: np.ndarray
    bin_edges: np.ndarray
    qq_bound: Optional[Dict[str, float]]
    percent_ge_min: float
    total_points: int
    total_ge_min: int
    bins_used: int


@dataclass
class ExperimentResult:
    folder: str
    mode: str
    client: str
    label: str

    # Delay histogram + stats (QQ-trimmed for plotting/stats)
    delay_hist: DelayHist
    delay_min: float
    delay_max: float
    delay_mean: float
    delay_median: float
    delay_std: float
    delay_cv: float
    delay_p25: float
    delay_p50: float
    delay_p75: float
    delay_p95: float
    delay_p99: float

    # CPU/Net pooled stats (windowed, NOT quantile trimmed)
    cpu_mean: float
    cpu_std: float
    cpu_min: float
    cpu_max: float
    cpu_median: float

    net_mean: float
    net_std: float
    net_min: float
    net_max: float
    net_median: float

    # per-prefix pooled parts for 2D (so we can do method stats if desired)
    prefix_parts: List[Dict]
    
def load_delay_run(conv_path: Path, run_id: str, min_delay_ms: float) -> Optional[np.ndarray]:
    """
    Load delay array for one run from convsrc2/<folder>/<run_id>_ca.csv
    Returns delay in ms, filtered to >0 and >= min_delay_ms.
    """
    p = conv_path / f"{run_id}_ca.csv"
    if not p.exists():
        # fallback pattern (if ever becomes 10_something_ca.csv)
        matches = sorted(conv_path.glob(f"{run_id}_*_ca.csv"))
        p = matches[0] if matches else None

    if p is None or not p.exists():
        return None

    try:
        df = pd.read_csv(p, usecols=["time_diff_ns"])
    except Exception:
        return None

    arr = df["time_diff_ns"].values.astype(np.float64) / 1_000_000.0
    del df

    arr = arr[np.isfinite(arr)]
    arr = arr[(arr > 0.0) & (arr >= float(min_delay_ms))]
    return arr



# -----------------------
# Per-experiment worker: build hist + stats + scatter + prefix parts
# -----------------------
def process_experiment(
    exp: dict,
    base: Path,
    outdir: Path,
    min_delay_ms: float,
    qq: Optional[float],
    qq_low: Optional[float],
    qq_high: Optional[float],
    no_qq: bool,
    qq_sample_cap: int,
    bins_method: str,
    fixed_bins: int,
    scott_min_bins: int,
    scott_max_bins: int,
    do_scatter: bool,
    verbose: bool,
) -> Optional[ExperimentResult]:
    folder = exp.get("folder")
    if not folder:
        warn("Experiment missing 'folder' field; skipping.")
        return None

    exclude = parse_exclude(exp.get("exclude", ""))
    mode, client = get_mode_client(folder)
    mode = mode or "unknown"
    client = client or "unknown"
    label = exp.get("label", parse_label(folder))

    delay_folder = base / "convsrc2" / folder
    c1_folder = base / "connt1" / folder

    if not delay_folder.exists():
        warn(f"Delay folder missing: {delay_folder} (skipping {folder})")
        return None
    if not c1_folder.exists():
        warn(f"Connt1 folder missing: {c1_folder} (skipping {folder})")
        return None

    # ---------------------------
    # 1) Delay histogram (plot11 style) + QQ bounds
    # ---------------------------
    info(f"[{folder}] Building delay histogram...", verbose)
    h = get_delay_histogram_plot11_style(
        delay_folder=delay_folder,
        exclude=exclude,
        min_delay_ms=min_delay_ms,
        qq=qq,
        qq_low=qq_low,
        qq_high=qq_high,
        no_qq=no_qq,
        qq_sample_cap=qq_sample_cap,
        bins_method=bins_method,
        fixed_bins=fixed_bins,
        scott_min_bins=scott_min_bins,
        scott_max_bins=scott_max_bins,
        verbose=verbose,
    )

    delay_hist = DelayHist(
        counts=h["counts"],
        bin_edges=h["bin_edges"],
        qq_bound=h["qq_bound"],
        percent_ge_min=h["percent_ge_min"],
        total_points=h["total_points"],
        total_ge_min=h["total_ge_min"],
        bins_used=h["bins_used"],
    )

    # Extract QQ bounds for per-run delay scatter trimming
    d_lb = None
    d_hb = None
    if delay_hist.qq_bound and not no_qq:
        d_lb = delay_hist.qq_bound.get("low", None)
        d_hb = delay_hist.qq_bound.get("high", None)

    # ---------------------------
    # 2) Delay stats from histogram (plot11 style)
    # ---------------------------
    counts = delay_hist.counts.astype(np.float64)
    be = delay_hist.bin_edges
    total = float(np.sum(counts))
    centers = 0.5 * (be[:-1] + be[1:])

    if total > 0:
        nz = np.nonzero(counts)[0]
        dmin = float(be[int(nz[0])]) if nz.size else float("nan")
        dmax = float(be[int(nz[-1]) + 1]) if nz.size else float("nan")
        dmean = float(np.sum(counts * centers) / total)
        csum = np.cumsum(counts)

        def q_at(frac: float) -> float:
            idx = int(np.searchsorted(csum, frac * total))
            if idx >= centers.size:
                return float(centers[-1])
            return float(centers[idx])

        d_p25 = q_at(0.25)
        d_p50 = q_at(0.50)
        d_p75 = q_at(0.75)
        d_p95 = q_at(0.95)
        d_p99 = q_at(0.99)
        dmed = d_p50

        dvar = float(np.sum(counts * (centers - dmean) ** 2) / total)
        dstd = math.sqrt(max(dvar, 0.0))
        dcv = _cv(dmean, dstd)
    else:
        dmin = dmax = dmean = dmed = dstd = dcv = float("nan")
        d_p25 = d_p50 = d_p75 = d_p95 = d_p99 = float("nan")

    # ---------------------------
    # 3) Per-run CPU/Net window stats + scatter plots
    # ---------------------------
    cm_files = sorted(c1_folder.glob("*_cm_monitor.csv"))
    if len(cm_files) == 0:
        warn(f"[{folder}] No cm_monitor files in {c1_folder}")
        return None

    prefix_parts: List[Dict] = []
    cpu_all_in_window = []
    net_all_in_window = []

    scatter_root = outdir / "scatter" / folder
    delay_sc_dir = scatter_root / "delay"
    cpu_sc_dir = scatter_root / "cpu"
    net_sc_dir = scatter_root / "network"

    conv_path = base / "convsrc2" / folder

    for cm_path in cm_files:
        prefix = cm_path.name.replace("_cm_monitor.csv", "")

        # run_id is the numeric prefix of the cm filename (10_conntrackd -> "10")
        run_id = prefix.split("_", 1)[0]
        try:
            run_idx = int(run_id)
        except Exception:
            run_idx = None

        if run_idx is not None and run_idx in exclude:
            if verbose:
                info(f"[{folder}] Skipping excluded run {run_idx} ({prefix})", True)
            continue

        # Window for cpu/net
        s, e, wmethod = get_window_for_prefix(base, folder, prefix, verbose=verbose)

        # ---- CPU ----
        try:
            cm_df = pd.read_csv(cm_path)
        except Exception as ex:
            warn(f"[{folder}] Cannot read {cm_path.name}: {ex}")
            continue

        cpu_col = None
        if "proc_cpu_cycles_ghz" in cm_df.columns:
            cpu_col = "proc_cpu_cycles_ghz"
        elif "proc_cpu_percent" in cm_df.columns:
            cpu_col = "proc_cpu_percent"

        cpu_part = {"cpu_in": 0, "cpu_mean": float("nan"), "cpu_std": float("nan")}

        if cpu_col is None or "time" not in cm_df.columns:
            warn(f"[{folder}] Missing CPU columns in {cm_path.name} (need time + cpu col)")
        else:
            t = pd.to_numeric(cm_df["time"], errors="coerce").astype(float).values
            v = pd.to_numeric(cm_df[cpu_col], errors="coerce").astype(float).values
            mwin = (t >= s) & (t <= e)
            t_in = t[mwin]
            v_in = v[mwin]

            # KEEP ONLY THIS FILTER (no quantile trimming)
            mask = v_in > 0.0001
            t_in = t_in[mask]
            v_in = v_in[mask]

            if v_in.size:
                cpu_all_in_window.append(v_in)
                cpu_part = {
                    "cpu_in": int(v_in.size),
                    "cpu_mean": float(np.mean(v_in)),
                    "cpu_std": float(np.std(v_in, ddof=1)) if v_in.size > 1 else 0.0,
                }

                if do_scatter and t_in.size > 1:
                    t_rel = t_in - float(t_in[0])
                    
                    pretty_mode = mode.replace("_", " ")
                    plot_time_scatter_with_regression(
                        t_rel=t_rel,
                        vals=v_in,
                        out_path=cpu_sc_dir / f"{prefix}_cpu.png",
                        title=f"CPU: {pretty_mode} {client} run {run_id}",
                        ylabel="CPU Utilisation (Gcycles/sec)" if cpu_col == "proc_cpu_cycles_ghz" else "CPU (%)",
                    )
                    
                    


        # ---- NET ----
        net_path = c1_folder / f"{prefix}_n_monitor.csv"
        net_part = {"net_in": 0, "net_mean": float("nan"), "net_std": float("nan")}

        if not net_path.exists():
            warn(f"[{folder}] Missing net file: {net_path.name}")
        else:
            try:
                net_df = pd.read_csv(net_path, usecols=["time", "iface_tx_bytes_per_sec"])
            except Exception as ex:
                warn(f"[{folder}] Cannot read {net_path.name}: {ex}")
                net_df = None

            if net_df is not None and not net_df.empty:
                t = pd.to_numeric(net_df["time"], errors="coerce").astype(float).values
                v = pd.to_numeric(net_df["iface_tx_bytes_per_sec"], errors="coerce").astype(float).values / 1024.0

                mwin = (t >= s) & (t <= e)
                t_in = t[mwin]
                v_in = v[mwin]

                # KEEP ONLY THIS FILTER (no quantile trimming)
                mask = v_in > 0.0001
                t_in = t_in[mask]
                v_in = v_in[mask]

                if v_in.size:
                    net_all_in_window.append(v_in)
                    net_part = {
                        "net_in": int(v_in.size),
                        "net_mean": float(np.mean(v_in)),
                        "net_std": float(np.std(v_in, ddof=1)) if v_in.size > 1 else 0.0,
                    }

                    if do_scatter and t_in.size > 1:
                        t_rel = t_in - float(t_in[0])
                 
                        pretty_mode = mode.replace("_", " ")
                        plot_time_scatter_with_regression(
                            t_rel=t_rel,
                            vals=v_in,
                            out_path=net_sc_dir / f"{prefix}_net.png",
                            title=f"Network: {pretty_mode} {client} run {run_id}",
                            ylabel="Link Capacity (kiB/sec)",
                        )



        prefix_parts.append({
            "prefix": prefix,
            "method": wmethod,
            "cpu_in": cpu_part["cpu_in"],
            "cpu_mean": cpu_part["cpu_mean"],
            "cpu_std": cpu_part["cpu_std"],
            "net_in": net_part["net_in"],
            "net_mean": net_part["net_mean"],
            "net_std": net_part["net_std"],
        })

        # ---- DELAY SCATTER (IMPORTANT FIX) ----
        if do_scatter:
            arr = load_delay_run(conv_path, run_id, min_delay_ms)
            if arr is None:
                warn(f"[{folder}] Missing delay file for run {run_id} (expected {run_id}_ca.csv)")
            else:
                # APPLY SAME QQ trimming bounds as the histogram
                if not no_qq and (d_lb is not None or d_hb is not None):
                    if d_lb is not None:
                        arr = arr[arr >= float(d_lb)]
                    if d_hb is not None:
                        arr = arr[arr <= float(d_hb)]

                if arr.size:
                    plot_delay_scatter(arr, delay_sc_dir / f"{run_id}_delay.png")
                else:
                    if verbose:
                        info(f"[{folder}] Delay scatter empty after filters for run {run_id}", True)

        del cm_df
        gc.collect()

    # ---------------------------
    # 4) pooled cpu/net + min/max/median (from window samples)
    # ---------------------------
    cpu_mean, cpu_std, _ = _pooled_stats_from_parts(prefix_parts, "cpu_mean", "cpu_std", "cpu_in")
    net_mean, net_std, _ = _pooled_stats_from_parts(prefix_parts, "net_mean", "net_std", "net_in")

    if cpu_all_in_window:
        cpu_concat = np.concatenate(cpu_all_in_window)
        cpu_min = _nanmin(cpu_concat)
        cpu_max = _nanmax(cpu_concat)
        cpu_med = _nanmedian(cpu_concat)
    else:
        cpu_min = cpu_max = cpu_med = float("nan")

    if net_all_in_window:
        net_concat = np.concatenate(net_all_in_window)
        net_min = _nanmin(net_concat)
        net_max = _nanmax(net_concat)
        net_med = _nanmedian(net_concat)
    else:
        net_min = net_max = net_med = float("nan")

    return ExperimentResult(
        folder=folder,
        mode=mode,
        client=client,
        label=label,

        delay_hist=delay_hist,
        delay_min=dmin,
        delay_max=dmax,
        delay_mean=dmean,
        delay_median=dmed,
        delay_std=float(dstd),
        delay_cv=float(dcv),
        delay_p25=float(d_p25),
        delay_p50=float(d_p50),
        delay_p75=float(d_p75),
        delay_p95=float(d_p95),
        delay_p99=float(d_p99),

        cpu_mean=float(cpu_mean),
        cpu_std=float(cpu_std),
        cpu_min=float(cpu_min),
        cpu_max=float(cpu_max),
        cpu_median=float(cpu_med),

        net_mean=float(net_mean),
        net_std=float(net_std),
        net_min=float(net_min),
        net_max=float(net_max),
        net_median=float(net_med),

        prefix_parts=prefix_parts,
    )


# -----------------------
# CDF plotting (plot11 style + ping)
# -----------------------
def plot_cdf_from_histograms_plot11(
    hist_items: List[Dict],
    title: str,
    out_path: Path,
    ping_vals: Optional[np.ndarray],
    min_delay_ms: float,
    qq: Optional[float],
    qq_low: Optional[float],
    qq_high: Optional[float],
    no_qq: bool,
) -> None:
    if not hist_items and ping_vals is None:
        warn(f"[CDF] No datasets for '{title}'")
        return

    fig, ax = plt.subplots(figsize=(14, 8))

    x_min = 0.0

    # determine x_max from hist edges (already qq-trimmed high bound!)
    x_max = 0.0
    for h in hist_items:
        try:
            x_max = max(x_max, float(h["bin_edges"][-1]))
        except Exception:
            pass

    # Ping: filter and apply same QQ trimming for fair overlay
    # FIX: keep raw samples (do NOT sort into ECDF)
    ping_plot = None
    if ping_vals is not None and ping_vals.size:
        pv = ping_vals.copy()
        pv = pv[(pv > 0.0) & (pv >= float(min_delay_ms))]
        pv, _ = apply_delay_qq(pv, qq=qq, qq_low=qq_low, qq_high=qq_high, no_qq=no_qq)
        pv = pv[np.isfinite(pv)]
        if pv.size:
            ping_plot = pv  # <-- FIX: raw samples, not sorted ECDF
            x_max = max(x_max, float(np.max(ping_plot)))

    if x_max <= 0:
        x_max = float(min_delay_ms)

    # padding and visibility (plot11 fix)
    ax.set_xlim(x_min, x_max * 1.05)
    ax.set_ylim(-0.05, 1.05)

    # ping CDF
    # FIX: histogram-based ping CDF using SAME bin_edges as datasets (smooth like others)
    if ping_plot is not None and ping_plot.size and hist_items:
        bin_edges = hist_items[0]["bin_edges"]
        counts_ping, _ = np.histogram(ping_plot, bins=bin_edges)
        total_ping = float(np.sum(counts_ping))
        if total_ping > 0:
            x_ping = bin_edges[1:]
            y_ping = np.cumsum(counts_ping) / total_ping
            ax.plot(x_ping, y_ping, lw=2.0, color="blue", linestyle="-", label="Ping")

    # datasets
    for h in hist_items:
        counts = h["counts"].astype(np.float64)
        total = float(np.sum(counts))
        if total <= 0:
            continue
        edges = h["bin_edges"]
        x = edges[1:]
        y = np.cumsum(counts) / total

        ax.plot(x, y, lw=2.0, color=h.get("color", "#333333"), label=h.get("label", "data"), linestyle="-")

        # median drop lines only
        q = 0.5
        idx = int(np.searchsorted(y, q))
        qx = float(x[idx]) if idx < x.size else float(x[-1])
        ax.vlines(qx, ymin=0, ymax=q, colors="gray", linestyles="--", linewidth=1.5, alpha=0.7)
        ax.hlines(q, xmin=0, xmax=qx, colors="gray", linestyles="--", linewidth=1.5, alpha=0.7)

    ax.set_xlabel("Delay (ms)")
    ax.set_ylabel("CDF")
    ax.set_title(title)
    ax.grid(alpha=0.25)
    ax.legend(frameon=False, loc="lower right")

    _set_integer_ms_xticks(ax, 0.0, x_max)

    plt.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(str(out_path), bbox_inches="tight", pad_inches=0.1)
    plt.close(fig)
    gc.collect()


# -----------------------
# Violin plots (optional)
# -----------------------
def plot_violin_box(
    data_list: List[np.ndarray],
    labels: List[str],
    title: str,
    out_path: Path,
) -> None:
    # Filter empty
    valid_data = []
    valid_labels = []
    for d, l in zip(data_list, labels):
        if d is not None and d.size > 0:
            valid_data.append(d)
            valid_labels.append(l)
    if not valid_data:
        return

    plt.figure(figsize=(12, 6))
    parts = plt.violinplot(valid_data, showmeans=False, showmedians=False, showextrema=False)

    for i, pc in enumerate(parts["bodies"]):
        lab = valid_labels[i]
        color = None
        for c in CONC_COLORS:
            if c in lab:
                color = CONC_COLORS[c]
                break
        if color is None:
            for m in MODE_COLORS:
                if m in lab.replace(" ", "_"):
                    color = MODE_COLORS[m]
                    break
        if color is None:
            color = SCATTER_COLOR
        pc.set_facecolor(color)
        pc.set_edgecolor("black")
        pc.set_alpha(0.6)

    plt.boxplot(
        valid_data,
        notch=True,
        sym="",
        widths=0.15,
        patch_artist=True,
        boxprops=dict(facecolor="white", color="black", alpha=0.7),
        capprops=dict(color="black"),
        whiskerprops=dict(color="black"),
        medianprops=dict(color="red", linewidth=1.5),
    )

    ax = plt.gca()
    ax.set_title(title)
    ax.set_ylabel("Delay (ms)")
    ax.set_ylim(bottom=0)
    ax.set_xticks(np.arange(1, len(valid_labels) + 1))
    ax.set_xticklabels(valid_labels, rotation=15)
    ax.grid(True, axis="y", linestyle="--", alpha=0.5)

    plt.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(str(out_path), bbox_inches="tight", pad_inches=0.1)
    plt.close()
    gc.collect()


# -----------------------
# 2D plots
# -----------------------
def _plot_2d_constant_mode_vary_rate(
    results: List[ExperimentResult],
    outdir: Path,
    mode: str,
    do_regression: bool,
) -> None:
    """
    Requirement: linear regression ONLY here (constant mode, varying cps).
    """
    sub = [r for r in results if r.mode == mode and r.client in CONCS]
    if not sub:
        return

    # order by client numeric
    def load_num(c: str) -> int:
        try:
            return int(c.replace("c", ""))
        except Exception:
            return 0

    sub.sort(key=lambda r: load_num(r.client))

    x = np.array([r.cpu_mean for r in sub], dtype=float)
    y = np.array([r.net_mean for r in sub], dtype=float)
    xerr = np.array([r.cpu_std for r in sub], dtype=float)
    yerr = np.array([r.net_std for r in sub], dtype=float)

    figdir = outdir / "violin"
    figdir.mkdir(parents=True, exist_ok=True)

    plt.figure(figsize=(8, 6))
    ax = plt.gca()
    color = MODE_COLORS.get(mode, "black")

    ax.errorbar(
        x, y,
        xerr=xerr, yerr=yerr,
        fmt="x",
        color=color,
        ecolor=color,
        elinewidth=1.5,
        capsize=4,
        markersize=10,
    )

    for r in sub:
        ax.text(r.cpu_mean, r.net_mean, f"  {r.client}", fontsize=9)

    if do_regression and x.size >= 2 and np.isfinite(x).all() and np.isfinite(y).all():
        lr = _safe_linreg(x, y)
        if lr is not None:
            slope, inter = lr
            xs = np.linspace(float(np.min(x)), float(np.max(x)), 100)
            ys = slope * xs + inter
            ax.plot(xs, ys, linestyle="--", color=color, alpha=0.6, label=f"Reg (m={slope:.4f})")
            ax.legend(frameon=False)

    ax.set_title(f"2D Plot: {mode.replace('_',' ').upper()} (varying cps)")
    ax.set_xlabel("CPU (Gcycles/sec)")
    ax.set_ylabel("Capacity (kiB/sec)")
    ax.set_xlim(left=0)
    ax.set_ylim(bottom=0)
    ax.grid(True, linestyle="--", alpha=0.3)

    plt.tight_layout()
    plt.savefig(str(figdir / f"2d_error_mode_{mode}.png"), bbox_inches="tight", pad_inches=0.1)
    plt.close()


def _plot_2d_grid_modes(results: List[ExperimentResult], outdir: Path) -> None:
    figdir = outdir / "violin"
    figdir.mkdir(parents=True, exist_ok=True)

    fig, axs = plt.subplots(2, 2, figsize=(14, 10))
    order = [("ftfw_tcp", axs[0, 0]), ("ftfw_udp", axs[0, 1]),
             ("notrack_udp", axs[1, 0]), ("notrack_tcp", axs[1, 1])]

    for mode, ax in order:
        sub = [r for r in results if r.mode == mode and r.client in CONCS]
        ax.set_title(mode.upper().replace("_", " "))
        if sub:
            sub.sort(key=lambda r: int(r.client.replace("c", "")) if r.client.startswith("c") else 0)
            color = MODE_COLORS.get(mode, "black")
            for r in sub:
                ax.errorbar(
                    r.cpu_mean, r.net_mean,
                    xerr=r.cpu_std, yerr=r.net_std,
                    fmt="x",
                    color=color,
                    ecolor=color,
                    elinewidth=1.5,
                    capsize=4,
                    markersize=8,
                )
                #ax.text(r.cpu_mean, r.net_mean, f"  {r.client}", fontsize=8, va="bottom")

        ax.set_xlabel("CPU (Gcycles/sec)")
        ax.set_ylabel("Capacity (kiB/sec)")
        ax.set_xlim(left=0)
        ax.set_ylim(bottom=0)
        ax.grid(True, linestyle="--", alpha=0.3)

    plt.tight_layout()
    plt.savefig(str(figdir / "2d_error_subplots_modes.png"), bbox_inches="tight", pad_inches=0.1)
    plt.close(fig)


def _plot_2d_constant_rate_vary_mode(results: List[ExperimentResult], outdir: Path, client: str) -> None:
    """
    Constant rate (client), varying mode: NO regression.
    """
    sub = [r for r in results if r.client == client and r.mode in MODES]
    if not sub:
        return

    figdir = outdir / "violin"
    figdir.mkdir(parents=True, exist_ok=True)

    plt.figure(figsize=(8, 6))
    ax = plt.gca()

    # plot each mode point
    for r in sub:
        color = MODE_COLORS.get(r.mode, "black")
        ax.errorbar(
            r.cpu_mean, r.net_mean,
            xerr=r.cpu_std, yerr=r.net_std,
            fmt="x",
            color=color,
            ecolor=color,
            elinewidth=2,
            capsize=5,
            markersize=10,
            label=r.mode,
        )
        #ax.text(r.cpu_mean, r.net_mean, f"  {r.mode}", fontsize=9)

    ax.set_title(f"2D Plot: {client} across modes")
    ax.set_xlabel("CPU (Gcycles/sec)")
    ax.set_ylabel("Capacity (kiB/sec)")
    ax.set_xlim(left=0)
    ax.set_ylim(bottom=0)
    ax.grid(True, linestyle="--", alpha=0.5)

    # dedupe legend labels
    handles, labels = ax.get_legend_handles_labels()
    seen = set()
    h2, l2 = [], []
    for hh, ll in zip(handles, labels):
        if ll not in seen:
            seen.add(ll)
            h2.append(hh)
            l2.append(ll)
    ax.legend(h2, l2, frameon=False)

    plt.tight_layout()
    plt.savefig(str(figdir / f"2d_error_{client}_modes.png"), bbox_inches="tight", pad_inches=0.1)
    plt.close()


# -----------------------
# Summary writers
# -----------------------
def write_summary(results: List[ExperimentResult], outdir: Path) -> None:
    lines = []
    header = (
        "Folder | Mode | Client | "
        "CPU(min/max/mean/median/std) | NET(min/max/mean/median/std) | "
        "Delay(min/max/mean/median/std/cv%) | p25 | p50 | p75 | p95 | p99"
    )
    lines.append(header)
    lines.append("-" * 180)

    for r in results:
        lines.append(
            f"{r.folder} | {r.mode} | {r.client} | "
            f"{r.cpu_min:.3f}/{r.cpu_max:.3f}/{r.cpu_mean:.3f}/{r.cpu_median:.3f}/{r.cpu_std:.3f} | "
            f"{r.net_min:.3f}/{r.net_max:.3f}/{r.net_mean:.3f}/{r.net_median:.3f}/{r.net_std:.3f} | "
            f"{r.delay_min:.3f}/{r.delay_max:.3f}/{r.delay_mean:.3f}/{r.delay_median:.3f}/{r.delay_std:.3f}/{r.delay_cv:.2f} | "
            f"{r.delay_p25:.3f} | {r.delay_p50:.3f} | {r.delay_p75:.3f} | {r.delay_p95:.3f} | {r.delay_p99:.3f}"
        )

    outp = outdir / "violin" / "summary.txt"
    outp.parent.mkdir(parents=True, exist_ok=True)
    with open(outp, "w") as f:
        f.write("\n".join(lines))


def write_cdf_summary(results: List[ExperimentResult], outdir: Path) -> None:
    lines = []
    lines.append("Folder | Mode | Client | P25_Delay(ms) | P50_Median_Delay(ms) | P75_Delay(ms)")
    lines.append("-" * 90)
    for r in results:
        lines.append(f"{r.folder} | {r.mode} | {r.client} | {r.delay_p25:.3f} | {r.delay_p50:.3f} | {r.delay_p75:.3f}")

    outp = outdir / "violin" / "cdf.txt"
    outp.parent.mkdir(parents=True, exist_ok=True)
    with open(outp, "w") as f:
        f.write("\n".join(lines))


# -----------------------
# CDF group builders (IMPORTANT: include all files already in each experiment histogram)
# -----------------------
def build_cdf_groups(results: List[ExperimentResult]) -> Tuple[Dict[str, List[ExperimentResult]], Dict[str, List[ExperimentResult]]]:
    """
    Returns:
      mode_groups[mode] -> list of experiments for that mode (across cps)
      conc_groups[client] -> list of experiments for that client (across modes)
    """
    mode_groups: Dict[str, List[ExperimentResult]] = {m: [] for m in MODES}
    conc_groups: Dict[str, List[ExperimentResult]] = {c: [] for c in CONCS}

    for r in results:
        if r.mode in mode_groups and r.client in CONCS:
            mode_groups[r.mode].append(r)
        if r.client in conc_groups and r.mode in MODES:
            conc_groups[r.client].append(r)

    # sort for consistent legend order
    for m in mode_groups:
        mode_groups[m].sort(key=lambda x: int(x.client.replace("c", "")) if x.client.startswith("c") else 0)
    for c in conc_groups:
        conc_groups[c].sort(key=lambda x: MODES.index(x.mode) if x.mode in MODES else 999)

    return mode_groups, conc_groups


# -----------------------
# Main
# -----------------------
def main():
    parser = argparse.ArgumentParser(description="Full plotting tool (scatter + CDF + ping + 2D + summaries) [Py3.8]")
    parser.add_argument("-c", "--config", required=True, help="YAML config file")
    parser.add_argument("-o", "--output", required=True, help="Output directory")
    parser.add_argument("--base", default="/mnt/LONTAS/ExpControl/pobo22/exp/raw", help="Base experiment dir")
    parser.add_argument("--min-delay", type=float, default=DEFAULT_MIN_DELAY_MS, help="Min delay (ms)")

    # QQ trimming (for delay only; applies to CDF/violin/stats AND delay scatter)
    parser.add_argument("-qq", "--qq", type=float, default=None, help="Upper quantile (deprecated single bound)")
    parser.add_argument("--qq-low", type=float, default=None, help="Lower quantile (0..1)")
    parser.add_argument("--qq-high", type=float, default=None, help="Upper quantile (0..1)")
    parser.add_argument("--no-qq", action="store_true", help="Disable qq trimming")

    # CDF bins
    parser.add_argument("--cdf-bin-method", choices=["fixed", "scott"], default="fixed",
                        help="Histogram bins method per experiment")
    parser.add_argument("--cdf-bins", type=int, default=DEFAULT_CDF_BINS, help="Bins if --cdf-bin-method fixed")
    parser.add_argument("--scott-min-bins", type=int, default=128, help="Min bins for Scott")
    parser.add_argument("--scott-max-bins", type=int, default=4096, help="Max bins for Scott")
    parser.add_argument("--qq-sample-cap", type=int, default=DEFAULT_QQ_SAMPLE_CAP, help="Sampling cap for QQ/scott estimates")
    parser.add_argument("--violin-sample-cap", type=int, default=DEFAULT_VIOLIN_SAMPLE_CAP, help="Violin sample cap")

    # Flags
    parser.add_argument("--scatter", action="store_true", help="Generate scatter plots")
    parser.add_argument("--cdf", action="store_true", help="Generate CDF plots")
    parser.add_argument("--violin", action="store_true", help="Generate violin plots")
    parser.add_argument("--plot2d", action="store_true", help="Generate 2D error plots")

    # Performance + verbosity
    parser.add_argument("--threads", type=int, default=4, help="Thread count (experiments in parallel)")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")

    args = parser.parse_args()

    # Default: run everything
    if not (args.scatter or args.cdf or args.violin or args.plot2d):
        args.scatter = True
        args.cdf = True
        args.violin = True
        args.plot2d = True

    base = Path(args.base)
    outdir = Path(args.output) / Path(args.config).stem
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "violin").mkdir(exist_ok=True)
    (outdir / "scatter").mkdir(exist_ok=True)

    exps = parse_config(args.config)
    if not exps:
        err("No experiments in config.")
        sys.exit(1)

    # Ping
    ping_vals = load_ping_reference(args.min_delay, verbose=True)

    # Threaded per-experiment processing
    info(f"Processing {len(exps)} experiments with threads={args.threads}", True)

    from concurrent.futures import ThreadPoolExecutor, as_completed

    results: List[ExperimentResult] = []
    failures = 0

    # If user only asked for --cdf, we still must build per-experiment delay hist.
    # But we avoid scatter work by passing do_scatter flag.
    do_scatter = bool(args.scatter)

    with ThreadPoolExecutor(max_workers=max(1, int(args.threads))) as pool:
        futs = []
        for exp in exps:
            futs.append(pool.submit(
                process_experiment,
                exp=exp,
                base=base,
                outdir=outdir,
                min_delay_ms=float(args.min_delay),
                qq=args.qq,
                qq_low=args.qq_low,
                qq_high=args.qq_high,
                no_qq=bool(args.no_qq),
                qq_sample_cap=int(args.qq_sample_cap),
                bins_method=str(args.cdf_bin_method),
                fixed_bins=int(args.cdf_bins),
                scott_min_bins=int(args.scott_min_bins),
                scott_max_bins=int(args.scott_max_bins),
                do_scatter=do_scatter,
                verbose=bool(args.verbose),
            ))

        for fut in as_completed(futs):
            try:
                r = fut.result()
                if r is not None:
                    results.append(r)
            except KeyboardInterrupt:
                raise
            except Exception as e:
                failures += 1
                warn(f"Experiment task failed: {e}")

    if not results:
        err("No experiment results produced.")
        sys.exit(1)

    # Sort stable output
    results.sort(key=lambda r: (r.mode, r.client, r.folder))

    # Summaries
    write_summary(results, outdir)
    write_cdf_summary(results, outdir)
    info(f"Wrote summaries to {outdir/'violin'}", True)

    # CDF plots
    if args.cdf:
        mode_groups, conc_groups = build_cdf_groups(results)

        # Per-mode across conc
        for mode in MODES:
            g = mode_groups.get(mode, [])
            if not g:
                warn(f"No experiments for mode {mode} (CDF)")
                continue
            hist_items = []
            for r in g:
                hist_items.append({
                    "counts": r.delay_hist.counts,
                    "bin_edges": r.delay_hist.bin_edges,
                    "label": r.client,
                    "color": CONC_COLORS.get(r.client, "#333333"),
                })
            outp = outdir / "violin" / f"cdf_mode_{mode}.png"
            plot_cdf_from_histograms_plot11(
                hist_items=hist_items,
                title=f"Delay CDF: {mode} across cps",
                out_path=outp,
                ping_vals=ping_vals,
                min_delay_ms=float(args.min_delay),
                qq=args.qq, qq_low=args.qq_low, qq_high=args.qq_high, no_qq=bool(args.no_qq),
            )

        # Per-concurrency across modes (MORE IMPORTANT per your note)
        for client in CONCS:
            g = conc_groups.get(client, [])
            if not g:
                warn(f"No experiments for client {client} (CDF)")
                continue
            hist_items = []
            for r in g:
                hist_items.append({
                    "counts": r.delay_hist.counts,
                    "bin_edges": r.delay_hist.bin_edges,
                    "label": r.mode.replace("_", " "),
                    "color": MODE_COLORS.get(r.mode, "#333333"),
                })
            outp = outdir / "violin" / f"cdf_conc_{client}.png"
            plot_cdf_from_histograms_plot11(
                hist_items=hist_items,
                title=f"Delay CDF: {client} across modes",
                out_path=outp,
                ping_vals=ping_vals,
                min_delay_ms=float(args.min_delay),
                qq=args.qq, qq_low=args.qq_low, qq_high=args.qq_high, no_qq=bool(args.no_qq),
            )

        info("CDF plots done.", True)

    # Violin plots (optional): build same two group styles
    if args.violin:
        rng = np.random.default_rng(42)

        mode_groups, conc_groups = build_cdf_groups(results)

        # Violin per-mode across conc
        for mode in MODES:
            g = mode_groups.get(mode, [])
            if not g:
                continue
            data_list = []
            labels = []
            for r in g:
                # sample from histogram by reading centers weighted would be complex;
                # instead we re-sample by approx using bin centers and counts (fast).
                counts = r.delay_hist.counts.astype(int)
                centers = 0.5 * (r.delay_hist.bin_edges[:-1] + r.delay_hist.bin_edges[1:])
                if counts.sum() <= 0:
                    continue
                # build sample indices
                n_take = min(int(args.violin_sample_cap), int(counts.sum()))
                # multinomial sample on bins
                probs = counts / float(counts.sum())
                idxs = rng.choice(np.arange(centers.size), size=n_take, replace=True, p=probs)
                samp = centers[idxs]
                data_list.append(samp)
                labels.append(r.client)
            outp = outdir / "violin" / f"violin_mode_{mode}.png"
            plot_violin_box(data_list, labels, f"Violin: {mode} across cps", outp)

        # Violin per-conc across modes
        for client in CONCS:
            g = conc_groups.get(client, [])
            if not g:
                continue
            data_list = []
            labels = []
            for r in g:
                counts = r.delay_hist.counts.astype(int)
                centers = 0.5 * (r.delay_hist.bin_edges[:-1] + r.delay_hist.bin_edges[1:])
                if counts.sum() <= 0:
                    continue
                n_take = min(int(args.violin_sample_cap), int(counts.sum()))
                probs = counts / float(counts.sum())
                idxs = rng.choice(np.arange(centers.size), size=n_take, replace=True, p=probs)
                samp = centers[idxs]
                data_list.append(samp)
                labels.append(r.mode.replace("_", " "))
            outp = outdir / "violin" / f"violin_conc_{client}.png"
            plot_violin_box(data_list, labels, f"Violin: {client} across modes", outp)

        info("Violin plots done.", True)

    # 2D plots
    if args.plot2d:
        # Per-mode, varying rate (with regression)
        for mode in MODES:
            _plot_2d_constant_mode_vary_rate(results, outdir, mode, do_regression=True)

        # 2x2 grid for modes
        _plot_2d_grid_modes(results, outdir)

        # Per-concurrency, varying mode (no regression)
        for client in CONCS:
            _plot_2d_constant_rate_vary_mode(results, outdir, client)

        info("2D plots done.", True)

    info(f"All done. Output dir: {outdir}", True)


if __name__ == "__main__":
    main()

