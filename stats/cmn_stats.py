#!/usr/bin/env python3
import pandas as pd
import numpy as np
from pathlib import Path
import argparse
import re

def parse_exclude_list(exclude_str):
    result = set()
    if exclude_str.strip() == "":
        return result
    for part in exclude_str.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            result.update(range(start, end + 1))
        else:
            result.add(int(part))
    return result

def load_and_concat_csvs(folder_path, pattern, excluded_files):
    all_dfs = []
    for f in sorted(folder_path.glob(pattern)):
        try:
            num = int(f.name.split('_')[0])
            if num in excluded_files:
                continue
            df = pd.read_csv(f)
            df['file_num'] = num
            all_dfs.append(df)
        except (ValueError, IndexError):
            print(f"Warning: Could not parse file number from {f.name}. Skipping.")
            continue
        except Exception as e:
            print(f"Error reading file {f.name}: {e}")
            continue
    if all_dfs:
        return pd.concat(all_dfs, ignore_index=True)
    else:
        return pd.DataFrame()

def compute_conntrack_rate(df):
    df = df.sort_values('time').reset_index(drop=True)
    df['conntrack_count'] = pd.to_numeric(df['conntrack_count'], errors='coerce')
    df['time'] = pd.to_numeric(df['time'], errors='coerce')
    
    conntrack_diff = df['conntrack_count'].diff()
    time_diff = df['time'].diff()

    df['conntrack_rate'] = np.where(time_diff.isnull() | (time_diff <= 0), 0, conntrack_diff / time_diff)
    df['conntrack_rate'].fillna(0, inplace=True)
    return df

def find_experiment_bounds(df, expected_rate):
    """
    Finds experiment bounds by identifying the continuous block of high conntrack rates.
    - An "onload" data point is one where the rate is > 80% of the expected rate.
    - Start: The timestamp of the first "onload" data point.
    - End: The timestamp of the last "onload" data point.
    """
    if df.empty or 'conntrack_rate' not in df.columns:
        return None, None

    # Define the threshold as 80% of the rate from the folder name (e.g., 800 for c1000)
    rate_threshold = expected_rate * 0.8
    
    # Find all indices where the rate is above the threshold
    high_rate_indices = df.index[df['conntrack_rate'] > rate_threshold].tolist()

    if not high_rate_indices:
        # If no high-rate period is found, we cannot determine the bounds.
        return None, None
        
    # The start is the first time we cross the threshold.
    start_idx = high_rate_indices[0]
    # The end is the last time we are above the threshold.
    end_idx = high_rate_indices[-1]

    start_time = df.loc[start_idx, 'time']
    end_time = df.loc[end_idx, 'time']

    if start_time >= end_time:
        return None, None

    return start_time, end_time

def compute_stats(df, cols, extra_cols=None):
    stats = {}
    for col in cols:
        if col not in df.columns:
            stats[col] = "Column not found"
            continue
        
        data = pd.to_numeric(df[col], errors='coerce').dropna()
        if data.empty:
            stats[col] = "No valid data"
        else:
            mean = data.mean()
            median = data.median()
            std = data.std()
            if extra_cols and col in extra_cols:
                min_val = data.min()
                max_val = data.max()
                stats[col] = (mean, median, std, min_val, max_val)
            else:
                stats[col] = (mean, median, std)
    return stats

def format_stats(stats, desc_map):
    lines = []
    for col, val in stats.items():
        desc = desc_map.get(col, col)
        if isinstance(val, str):
            lines.append(f"  {desc}: {val}")
        else:
            if len(val) == 5:
                mean, median, std, min_val, max_val = val
                lines.append(f"  {desc}: Mean = {mean:.2f}, Median = {median:.2f}, Std = {std:.2f}, Min = {min_val:.2f}, Max = {max_val:.2f}")
            else:
                mean, median, std = val
                lines.append(f"  {desc}: Mean = {mean:.2f}, Median = {median:.2f}, Std = {std:.2f}")
    return lines

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rawdir', required=True, help="Base raw directory")
    parser.add_argument('--foldername', required=True, help="Folder name inside connt1 and connt2")
    parser.add_argument('--exclude', default="", help="Exclude files by number, e.g. 2-3,5")
    parser.add_argument('--outdir', required=True, help="Output directory")
    args = parser.parse_args()

    rawdir = Path(args.rawdir)
    foldername = args.foldername
    exclude_set = parse_exclude_list(args.exclude)
    outdir = Path(args.outdir)
    outdir_path = outdir / foldername
    outdir_path.mkdir(parents=True, exist_ok=True)
    summary_file = outdir_path / "combined_base_onload_summary.txt"

    # Extract expected rate from folder name (e.g., c1000 -> 1000)
    expected_rate = 1000 # Default value
    match = re.search(r'c(\d+)', foldername)
    if match:
        expected_rate = int(match.group(1))
        print(f"Detected expected rate: {expected_rate} from folder name.")
    else:
        print(f"Warning: Could not detect rate from folder name. Using default: {expected_rate}.")

    all_summary = []

    cm_cols = ['proc_cpu_percent', 'proc_cpu_cycles_ghz', 'proc_mem_mb', 'conntrack_rate', 'clock_delta_ms']
    cm_desc = {
        'proc_cpu_percent': 'Process CPU (%)', 'proc_cpu_cycles_ghz': 'CPU Cycles (GHz)',
        'proc_mem_mb': 'Process Memory (MB)', 'conntrack_rate': 'Conntrack Rate (Δcount/sec)',
        'clock_delta_ms': 'Clock Delta (ms)'
    }
    cm_extra_cols = ['clock_delta_ms']
    n_cols = ['iface_rx_bytes_per_sec', 'iface_tx_bytes_per_sec']
    n_desc = {'iface_rx_bytes_per_sec': 'RX KB/s', 'iface_tx_bytes_per_sec': 'TX KB/s'}

    for conn_folder in ['connt1', 'connt2']:
        folder_path = rawdir / conn_folder / foldername
        if not folder_path.exists():
            all_summary.append(f"Warning: Folder {folder_path} does not exist. Skipping.\n")
            continue

        all_summary.append(f"--- Summary for {conn_folder}/{foldername} ---")

        cm_df = load_and_concat_csvs(folder_path, "*_cm_monitor.csv", exclude_set)
        if cm_df.empty:
            all_summary.append("No cm_monitor data found.\n")
            continue

        cm_df = compute_conntrack_rate(cm_df)
        
        onload_start, onload_end = find_experiment_bounds(cm_df, expected_rate)

        if onload_start is not None and onload_end is not None:
            base_cm = cm_df[(cm_df['time'] < onload_start) | (cm_df['time'] > onload_end)]
            onload_cm = cm_df[(cm_df['time'] >= onload_start) & (cm_df['time'] <= onload_end)]
        else:
            all_summary.append("Could not determine experiment bounds. Treating all data as base.\n")
            base_cm = cm_df
            onload_cm = pd.DataFrame()

        all_summary.append("cm_monitor Base (Idle) Segment:")
        # For base stats, only consider periods with non-negative rates.
        base_cm_for_stats = base_cm[base_cm['conntrack_rate'] >= 0]
        base_stats = compute_stats(base_cm_for_stats, cm_cols, extra_cols=cm_extra_cols)
        all_summary.extend(format_stats(base_stats, cm_desc))

        all_summary.append("\ncm_monitor Onload (Experiment) Segment:")
        onload_stats = compute_stats(onload_cm, cm_cols, extra_cols=cm_extra_cols)
        all_summary.extend(format_stats(onload_stats, cm_desc))
        all_summary.append("")

        n_df = load_and_concat_csvs(folder_path, "*_n_monitor.csv", exclude_set)
        if n_df.empty:
            all_summary.append("No n_monitor data found.\n")
            continue

        n_df['iface_rx_bytes_per_sec'] = pd.to_numeric(n_df['iface_rx_bytes_per_sec'], errors='coerce') / 1024.0
        n_df['iface_tx_bytes_per_sec'] = pd.to_numeric(n_df['iface_tx_bytes_per_sec'], errors='coerce') / 1024.0
        n_df = n_df.dropna(subset=['iface_rx_bytes_per_sec', 'iface_tx_bytes_per_sec'])
        n_df['time'] = pd.to_numeric(n_df['time'], errors='coerce')

        if onload_start is not None and onload_end is not None:
            base_n = n_df[(n_df['time'] < onload_start) | (n_df['time'] > onload_end)]
            onload_n = n_df[(n_df['time'] >= onload_start) & (n_df['time'] <= onload_end)]
        else:
            base_n = n_df
            onload_n = pd.DataFrame()

        all_summary.append("n_monitor Base (Idle) Segment:")
        base_n_stats = compute_stats(base_n, n_cols)
        all_summary.extend(format_stats(base_n_stats, n_desc))

        all_summary.append("\nn_monitor Onload (Experiment) Segment:")
        onload_n_stats = compute_stats(onload_n, n_cols)
        all_summary.extend(format_stats(onload_n_stats, n_desc))
        all_summary.append("\n\n")

    with open(summary_file, 'w') as f:
        f.write('\n'.join(all_summary))

    print(f"Summary written to {summary_file}")

if __name__ == "__main__":
    main()
