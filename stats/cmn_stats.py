#!/usr/bin/env python3

import os
import sys
import pandas as pd
from glob import glob

def find_cm_files(directory):
    return sorted(glob(os.path.join(directory, "*_conntrackd_cm_monitor.csv")))

def summarize_cm_file(prefix, cm_file, folder_name, output_dir):
    df_cm = pd.read_csv(cm_file)

    # Convert all columns to numeric where possible
    df_cm_numeric = df_cm.copy()
    for col in df_cm.columns:
        df_cm_numeric[col] = pd.to_numeric(df_cm[col], errors='coerce')

    stats = pd.DataFrame({
        'mean': df_cm_numeric.mean(),
        'std': df_cm_numeric.std(),
        'median': df_cm_numeric.median()
    })

    # Drop any rows with all NaNs (e.g., non-numeric columns)
    stats = stats.dropna(how='all')

    # Save result
    stats_file = os.path.join(output_dir, f"{folder_name}_{prefix}_cm_stats.csv")
    stats.to_csv(stats_file)
    print(f"Saved CM stats to: {stats_file}")

def main():
    if len(sys.argv) != 2:
        print("Usage: ./statcmn.py /path/to/folder")
        sys.exit(1)

    directory = sys.argv[1]
    folder_name = os.path.basename(os.path.normpath(directory))
    cm_files = find_cm_files(directory)

    if not cm_files:
        print("No *_conntrackd_cm_monitor.csv files found.")
        sys.exit(1)

    for cm_file in cm_files:
        prefix = os.path.basename(cm_file).split('_')[0]
        summarize_cm_file(prefix, cm_file, folder_name, directory)

if __name__ == "__main__":
    main()
