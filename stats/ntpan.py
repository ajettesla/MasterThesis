#!/usr/bin/env python3
import re
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from scipy import stats
import paramiko
import os
import io
import getpass
import time
import socket
import sys
import gzip
import glob
from datetime import datetime

def acNhist2(c, figFlag=True, label='', color='k', linewidth=2):
    """
    Accurate histogram using Scott's rule - MATLAB equivalent
    Returns line plot, not bars
    """
    c = np.array(c)
    c = c[~np.isnan(c)]  # Remove NaN values
    
    if len(c) == 0:
        return None, None, None
    
    # Compute bin width by Scott's rule 
    w = 3.49 * np.std(c) * len(c)**(-1/3)
    
    # Establish bins vector (bin edges first, then centers)
    bin_edges = np.arange(min(c), max(c) + w, w)
    bins = (bin_edges[:-1] + bin_edges[1:]) / 2  # Bin centers
    
    # Use histogram to compute absolute frequencies
    freq, _ = np.histogram(c, bins=bin_edges)
    
    # Return relative frequencies (density)
    p = freq / (len(c) * w)
    
    if figFlag:
        plt.plot(bins, p, color=color, linewidth=linewidth, label=label)
    
    return bins, p, w

def compute_convolution_pdf(data1, data2):
    """
    Compute the theoretical PDF of the difference (data1 - data2)
    using convolution of distributions
    """
    # Generate PDFs using kernel density estimation
    kde1 = stats.gaussian_kde(data1)
    kde2 = stats.gaussian_kde(data2)
    
    # Create a grid for evaluation
    min_val = min(data1.min(), data2.min())
    max_val = max(data1.max(), data2.max())
    range_val = max_val - min_val
    
    # The grid needs to be fine enough for accurate convolution
    x_grid = np.linspace(min_val - range_val/2, max_val + range_val/2, 1000)
    
    # Evaluate PDFs on the grid
    pdf1 = kde1(x_grid)
    pdf2 = kde2(-x_grid)  # Flipping for convolution
    
    # Compute convolution (theoretical PDF of difference)
    dx = x_grid[1] - x_grid[0]
    conv_pdf = np.convolve(pdf1, pdf2, mode='same') * dx
    
    # The convolution result range needs adjustment
    diff_range = (data1.max() - data1.min()) + (data2.max() - data2.min())
    conv_x_grid = np.linspace(data1.mean() - data2.mean() - diff_range/2, 
                             data1.mean() - data2.mean() + diff_range/2, 
                             len(conv_pdf))
    
    return conv_x_grid, conv_pdf

def ssh_execute_command(client, command, timeout=30):
    """
    Execute a command via SSH and return the output
    """
    try:
        print(f"Executing: {command}")
        channel = client.get_transport().open_session()
        channel.settimeout(timeout)
        channel.exec_command(command)
        
        output = ""
        while True:
            if channel.exit_status_ready():
                break
            
            if channel.recv_ready():
                chunk = channel.recv(1024).decode('utf-8')
                output += chunk
                sys.stdout.write(".")
                sys.stdout.flush()
            else:
                time.sleep(0.5)
                sys.stdout.write(".")
                sys.stdout.flush()
        
        sys.stdout.write("\n")
        exit_status = channel.recv_exit_status()
        
        if exit_status != 0:
            print(f"Command exited with status {exit_status}")
            stderr_output = channel.recv_stderr(1024).decode('utf-8')
            if stderr_output:
                print(f"Error output: {stderr_output}")
            return None
        
        return output
    
    except Exception as e:
        print(f"Error executing command: {e}")
        return None

def ssh_get_log_files(hostname, log_path='/var/log/chrony/tracking.log', timeout=60):
    """
    Get chrony tracking log files from remote server, including compressed logs
    """
    print(f"Establishing SSH connection to {hostname}...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        # Use SSH config file
        ssh_config = paramiko.SSHConfig()
        user_config_file = os.path.expanduser("~/.ssh/config")
        
        if os.path.exists(user_config_file):
            with open(user_config_file) as f:
                ssh_config.parse(f)
            
            # Get config for the host
            host_config = ssh_config.lookup(hostname)
            
            # Extract connection details from SSH config
            connect_hostname = host_config.get('hostname', hostname)
            connect_username = host_config.get('user', None)
            connect_port = int(host_config.get('port', 22))
            key_filename = host_config.get('identityfile', None)
            
            if isinstance(key_filename, list) and len(key_filename) > 0:
                key_filename = key_filename[0]
            
            # Connect with SSH config parameters and timeout
            client.connect(
                connect_hostname,
                port=connect_port,
                username=connect_username,
                key_filename=key_filename,
                timeout=timeout
            )
            
            print(f"Connected to {hostname} ({connect_hostname}) using SSH config")
        else:
            print(f"SSH config file not found at {user_config_file}")
            return None
        
        # Get main log file
        log_content = ssh_execute_command(client, f"sudo -n cat {log_path} 2>&1 || echo 'SUDO_ERROR'", timeout)
        
        if log_content and 'SUDO_ERROR' in log_content:
            print(f"Sudo permission denied on {hostname}. Make sure you have passwordless sudo access.")
            return None
        
        # Look for compressed log files too
        log_dir = os.path.dirname(log_path)
        log_base = os.path.basename(log_path)
        compressed_logs_command = f"sudo -n find {log_dir} -name '{log_base}.[0-9]*.gz' -type f | sort"
        compressed_logs_list = ssh_execute_command(client, compressed_logs_command, timeout)
        
        all_log_content = log_content if log_content else ""
        
        # Process compressed logs if they exist
        if compressed_logs_list and len(compressed_logs_list.strip()) > 0:
            compressed_files = compressed_logs_list.strip().split('\n')
            print(f"Found {len(compressed_files)} compressed log files")
            
            for comp_file in compressed_files[:3]:  # Limit to the 3 most recent compressed logs
                print(f"Getting compressed log: {comp_file}")
                # Get the compressed content and decompress it
                compressed_content = ssh_execute_command(
                    client, 
                    f"sudo -n cat {comp_file} 2>/dev/null", 
                    timeout
                )
                
                if compressed_content:
                    try:
                        # Encode to bytes, decompress, and decode back to string
                        compressed_bytes = compressed_content.encode('latin1')  # Use latin1 to preserve byte values
                        decompressed_content = gzip.decompress(compressed_bytes).decode('utf-8')
                        all_log_content += "\n" + decompressed_content
                        print(f"Successfully decompressed {comp_file}")
                    except Exception as e:
                        print(f"Error decompressing {comp_file}: {e}")
        
        if not all_log_content:
            print(f"No content retrieved from {log_path} on {hostname}. Check if file exists.")
            return None
        
        print(f"Successfully retrieved log data from {hostname} ({len(all_log_content)} bytes)")
        return all_log_content
    
    except socket.timeout:
        print(f"Connection timed out to {hostname} after {timeout} seconds")
        return None
    except paramiko.ssh_exception.AuthenticationException:
        print(f"Authentication failed for {hostname}. Check your SSH key or credentials.")
        return None
    except paramiko.ssh_exception.SSHException as e:
        print(f"SSH error for {hostname}: {e}")
        return None
    except Exception as e:
        print(f"Error connecting to {hostname}: {str(e)}")
        return None
    
    finally:
        client.close()

def parse_chrony_tracking_log(log_content, source_name):
    """
    Parse chrony tracking log file and extract timing offsets with improved handling
    """
    data = []
    timestamps = []
    
    print(f"Parsing chrony tracking log from {source_name}")
    
    try:
        line_count = 0
        parsed_count = 0
        
        # The header pattern to detect and skip
        header_pattern = re.compile(r'=+|Date.*Time.*IP Address.*St.*Freq.*Skew.*Offset.*')
        
        for line in log_content.splitlines():
            line_count += 1
            
            # Skip empty lines and header lines
            if not line.strip() or header_pattern.match(line.strip()):
                continue
            
            # Process data lines - Split by whitespace
            parts = re.split(r'\s+', line.strip())
            
            # Validate the line format - needs at least date, time, and offset (7th column)
            if len(parts) >= 7:
                try:
                    # Check if this looks like a valid data line by checking if date has correct format
                    date_str = parts[0]
                    if not re.match(r'\d{4}-\d{2}-\d{2}', date_str):
                        continue
                    
                    time_str = parts[1]
                    timestamp = f"{date_str} {time_str}"
                    
                    # The offset is in the 7th column (index 6)
                    offset_str = parts[6]
                    
                    # Make sure it's a number by checking for scientific notation format
                    if not re.match(r'[-+]?\d+\.\d+e[-+]\d+', offset_str):
                        continue
                    
                    # Convert scientific notation to float and to microseconds
                    offset = float(offset_str) * 1e6  # Convert seconds to microseconds
                    
                    timestamps.append(timestamp)
                    data.append(offset)
                    parsed_count += 1
                    
                except (ValueError, IndexError) as e:
                    # This is more strict parsing, so we don't need to print every issue
                    if line_count % 10000 == 0:  # Only print occasional parsing errors
                        print(f"Warning: Could not parse line {line_count}: {e}")
        
        print(f"Processed {line_count} lines, extracted {parsed_count} measurements")
    
    except Exception as e:
        print(f"Error parsing log content: {e}")
        return None
    
    if not data:
        print(f"No valid data found in log from {source_name}")
        return None
        
    # Create Series with timestamps as index
    return pd.Series(data, name=f'{source_name}_offset', index=pd.to_datetime(timestamps))

def iqr_filter(data):
    """
    Remove outliers using IQR method
    """
    if len(data) == 0:
        return data
    
    Q1 = data.quantile(0.25)
    Q3 = data.quantile(0.75)
    IQR = Q3 - Q1
    lower_bound = Q1 - 1.5 * IQR
    upper_bound = Q3 + 1.5 * IQR
    
    filtered = data[(data >= lower_bound) & (data <= upper_bound)]
    
    removed_count = len(data) - len(filtered)
    print(f"  Original: {len(data)}, After filtering: {len(filtered)}, Removed: {removed_count} outliers")
    
    return filtered

def plot_combined_distributions(f1, f2, server1, server2):
    """
    Plot 1: Individual distributions of server1 and server2 overlaid
    """
    print("\n=== Creating Combined Distribution Plot ===")
    
    plt.figure(figsize=(14, 7))
    
    # Use Scott's rule for each dataset - LINE PLOTS
    bins1, p1, _ = acNhist2(f1, figFlag=False)
    bins2, p2, _ = acNhist2(f2, figFlag=False)
    
    if bins1 is not None and p1 is not None:
        plt.plot(bins1, p1, 'b-', linewidth=2, label=f'{server1} (n={len(f1)})')
    
    if bins2 is not None and p2 is not None:
        plt.plot(bins2, p2, 'g-', linewidth=2, label=f'{server2} (n={len(f2)})')
    
    plt.title(f'NTP Timing Offset Distributions ({server1} vs {server2})', fontsize=16)
    plt.xlabel('Offset (μs)', fontsize=14)
    plt.ylabel('Density', fontsize=14)
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.legend()
    plt.tight_layout()
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'combined_ntp_{server1}_{server2}_{timestamp}.png'
    plt.savefig(filename, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Saved combined histogram as '{filename}'")

def plot_difference_analysis(f1, f2, server1, server2):
    """
    Plot 2: Difference analysis (server1 - server2) with statistics
    """
    print("\n=== Creating Difference Analysis Plot ===")
    
    # Calculate difference - handle different lengths
    if len(f1) == len(f2) and f1.index.equals(f2.index):
        print("Using aligned data (same timestamps)")
        diff = f1.values - f2.values
        method = "aligned"
    else:
        # Use common timestamps
        common_idx = f1.index.intersection(f2.index)
        if len(common_idx) > 0:
            print(f"Different timestamps - using {len(common_idx)} common timestamps")
            diff = f1.loc[common_idx].values - f2.loc[common_idx].values
            method = "common timestamps"
        else:
            # No common timestamps, use reindexing
            print("No common timestamps - resampling to align data")
            min_len = min(len(f1), len(f2))
            diff = f1.iloc[:min_len].values - f2.iloc[:min_len].values
            method = "truncated"
    
    # Apply IQR filtering to difference
    diff_series = pd.Series(diff)
    diff_filtered = iqr_filter(diff_series)
    
    # Calculate statistics
    mean_val = diff_filtered.mean()
    median_val = diff_filtered.median()
    std_val = diff_filtered.std()
    count = len(diff_filtered)
    
    print(f"\nDifference Statistics:")
    print(f"  Mean: {mean_val:.3f} μs")
    print(f"  Median: {median_val:.3f} μs")
    print(f"  Std Dev: {std_val:.3f} μs")
    print(f"  Sample Count: {count}")
    
    # Confidence intervals
    confidence_levels = [97, 95, 90, 75, 60, 50, 25]
    ci_bounds = {}
    for level in confidence_levels:
        try:
            ci = stats.norm.interval(level / 100, loc=mean_val, scale=std_val / np.sqrt(count))
            ci_bounds[level] = ci
        except:
            # Handle the case when confidence interval calculation fails
            ci_bounds[level] = (float('nan'), float('nan'))
    
    # Plot difference using Scott's rule - LINE PLOT (MATLAB style)
    plt.figure(figsize=(14, 7))
    
    bins, density, _ = acNhist2(diff_filtered, figFlag=False)
    
    if bins is not None and density is not None:
        plt.plot(bins, density, 'k-', linewidth=2, label=f'{server1} - {server2} (Empirical)')
        max_density = max(density)
    else:
        max_density = 1
        print("Warning: Could not calculate density for difference")
    
    plt.title(f"NTP Offset Difference ({server1} - {server2})", fontsize=16)
    plt.xlabel("Difference (μs)", fontsize=14)
    plt.ylabel("Density", fontsize=14)
    plt.grid(True, linestyle='--', alpha=0.6)
    
    # Mean line (blue)
    plt.axvline(mean_val, color='blue', linestyle='-', linewidth=2)
    plt.text(mean_val, max_density*0.95, 'Mean', color='blue', rotation=90,
             va='top', ha='center', fontsize=12, fontweight='bold')
    
    # Standard deviation lines (orange dashed)
    for i in [1, 2]:
        for sign in [-1, 1]:
            pos = mean_val + sign * i * std_val
            plt.axvline(pos, color='orange', linestyle='--', linewidth=1.5)
            plt.text(pos, max_density*(0.85 - 0.05*i), f'{sign:+d}σ',
                     color='orange', rotation=90, fontsize=11,
                     ha='right' if sign < 0 else 'left', va='top', fontweight='bold')
    
    # Statistics summary box
    summary = [
        f"Mean: {mean_val:.3f} μs",
        f"Median: {median_val:.3f} μs",
        f"Std Dev: {std_val:.3f} μs", ""
    ]
    summary += [f"{lvl}% CI: [{ci[0]:.3f}, {ci[1]:.3f}]" for lvl, ci in ci_bounds.items()]
    
    plt.gca().text(
        0.985, 0.98, '\n'.join(summary),
        transform=plt.gca().transAxes,
        fontsize=12, va='top', ha='right',
        bbox=dict(facecolor='white', edgecolor='black', alpha=0.9)
    )
    
    plt.tight_layout()
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'ntp_{server1}_minus_{server2}_difference_{timestamp}.png'
    plt.savefig(filename, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Saved difference plot as '{filename}'")

def plot_detailed_convolution(f1, f2, server1, server2):
    """
    Plot 3: Detailed convolution analysis with both empirical and theoretical PDFs
    """
    print("\n=== Creating Detailed Convolution Analysis Plot ===")
    
    # Calculate empirical difference
    if len(f1) == len(f2) and f1.index.equals(f2.index):
        diff = f1.values - f2.values
    else:
        common_idx = f1.index.intersection(f2.index)
        if len(common_idx) > 0:
            diff = f1.loc[common_idx].values - f2.loc[common_idx].values
        else:
            min_len = min(len(f1), len(f2))
            diff = f1.iloc[:min_len].values - f2.iloc[:min_len].values
    
    # Apply IQR filtering to difference
    diff_filtered = iqr_filter(pd.Series(diff))
    
    # Compute convolution
    print(f"Computing convolution of {server1} and {server2} PDFs...")
    conv_x, conv_pdf = compute_convolution_pdf(f1.values, f2.values)
    
    # Create figure with two subplots
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 12), gridspec_kw={'height_ratios': [1, 1.5]})
    
    # Top subplot: Individual PDFs
    kde1 = stats.gaussian_kde(f1)
    kde2 = stats.gaussian_kde(f2)
    x = np.linspace(min(f1.min(), f2.min()), max(f1.max(), f2.max()), 1000)
    
    ax1.plot(x, kde1(x), 'b-', linewidth=2, label=f'{server1} PDF')
    ax1.plot(x, kde2(x), 'g-', linewidth=2, label=f'{server2} PDF')
    ax1.set_title(f'Individual PDFs: {server1} and {server2}', fontsize=14)
    ax1.set_xlabel('Offset (μs)', fontsize=12)
    ax1.set_ylabel('Density', fontsize=12)
    ax1.grid(True, linestyle='--', alpha=0.6)
    ax1.legend(loc='best')
    
    # Bottom subplot: Empirical histogram vs Convolution
    bins = np.linspace(diff_filtered.min(), diff_filtered.max(), 30)
    ax2.hist(diff_filtered, bins=bins, density=True, alpha=0.5, color='gray', 
             label=f'Empirical Histogram ({server1} - {server2})')
    
    # Empirical PDF (KDE)
    kde_diff = stats.gaussian_kde(diff_filtered)
    x_diff = np.linspace(diff_filtered.min(), diff_filtered.max(), 1000)
    ax2.plot(x_diff, kde_diff(x_diff), 'k-', linewidth=2, 
             label=f'Empirical PDF ({server1} - {server2})')
    
    # Convolution PDF - Scale to match range
    conv_pdf_scaled = conv_pdf / np.max(conv_pdf) * np.max(kde_diff(x_diff))
    ax2.plot(conv_x, conv_pdf_scaled, 'r-', linewidth=3, 
             label=f'Theoretical Convolution PDF ({server1} - {server2})')
    
    ax2.set_title(f'Convolution Analysis: {server1} - {server2}', fontsize=14)
    ax2.set_xlabel('Difference (μs)', fontsize=12)
    ax2.set_ylabel('Density', fontsize=12)
    ax2.grid(True, linestyle='--', alpha=0.6)
    ax2.legend(loc='best')
    
    # Add statistics
    emp_mean = diff_filtered.mean()
    emp_std = diff_filtered.std()
    theo_mean = f1.mean() - f2.mean()
    
    stats_text = (f"Empirical Mean: {emp_mean:.3f} μs\n"
                  f"Empirical Std: {emp_std:.3f} μs\n"
                  f"Theoretical Mean: {theo_mean:.3f} μs\n"
                  f"Sample sizes: {server1}={len(f1)}, {server2}={len(f2)}")
    
    ax2.text(0.02, 0.95, stats_text, transform=ax2.transAxes, 
             fontsize=12, va='top', ha='left',
             bbox=dict(facecolor='white', edgecolor='black', alpha=0.8))
    
    plt.tight_layout()
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'convolution_{server1}_{server2}_analysis_{timestamp}.png'
    plt.savefig(filename, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Saved detailed convolution analysis as '{filename}'")

def save_processed_data(data1, data2, server1, server2):
    """
    Save processed data to CSV file
    """
    # Create DataFrame with both datasets
    df1 = pd.DataFrame({f'{server1}_offset': data1})
    df2 = pd.DataFrame({f'{server2}_offset': data2})
    
    # Merge on timestamp index
    combined = pd.merge(df1, df2, left_index=True, right_index=True, how='outer')
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'ntp_{server1}_{server2}_processed_data_{timestamp}.csv'
    combined.to_csv(filename)
    print(f"Saved processed data to '{filename}'")
    
    return combined

def analyze_ntp_timing(server1, server2, log_path='/var/log/chrony/tracking.log', timeout=60):
    """
    Complete NTP timing analysis workflow with remote data collection
    """
    # Get current date/time and user for the report
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    try:
        current_user = getpass.getuser()
    except:
        current_user = os.environ.get('USER', 'ajettesla')
    
    print("=" * 60)
    print(f"NTP Timing Analysis Started")
    print(f"Current Date and Time (UTC): {current_time}")
    print(f"Current User's Login: {current_user}")
    print("=" * 60)
    
    # Get logs from remote servers, including compressed logs
    print(f"Connecting to {server1} to get chrony tracking logs...")
    server1_logs = ssh_get_log_files(server1, log_path, timeout)
    
    print(f"Connecting to {server2} to get chrony tracking logs...")
    server2_logs = ssh_get_log_files(server2, log_path, timeout)
    
    if server1_logs is None or server2_logs is None:
        print("Failed to retrieve one or both log files. Exiting.")
        return
    
    # Parse log files with improved handling
    server1_data = parse_chrony_tracking_log(server1_logs, server1)
    server2_data = parse_chrony_tracking_log(server2_logs, server2)
    
    if server1_data is None or server2_data is None or len(server1_data) == 0 or len(server2_data) == 0:
        print("No data found in log files. Exiting.")
        return
    
    # Save raw processed data and get aligned dataset
    combined_data = save_processed_data(server1_data, server2_data, server1, server2)
    
    # Filter outliers
    print("\n=== Filtering Outliers (IQR Method) ===")
    print(f"Filtering {server1} data:")
    f1 = iqr_filter(server1_data.dropna())
    print(f"Filtering {server2} data:")
    f2 = iqr_filter(server2_data.dropna())
    
    if len(f1) == 0 or len(f2) == 0:
        print("No data remaining after filtering. Check your data quality.")
        return
    
    # Plot 1: Combined distributions (individual overlaid)
    plot_combined_distributions(f1, f2, server1, server2)
    
    # Plot 2: Difference analysis (empirical)
    plot_difference_analysis(f1, f2, server1, server2)
    
    # Plot 3: Detailed convolution analysis
    plot_detailed_convolution(f1, f2, server1, server2)
    
    # Final summary
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    print("\n" + "=" * 60)
    print("ANALYSIS SUMMARY")
    print("=" * 60)
    print(f"Processed {len(f1)} values from {server1} after filtering.")
    print(f"Processed {len(f2)} values from {server2} after filtering.")
    print(f"Generated outputs:")
    print(f"  - combined_ntp_{server1}_{server2}_{timestamp}.png (individual distributions)")
    print(f"  - ntp_{server1}_minus_{server2}_difference_{timestamp}.png (empirical difference)")
    print(f"  - convolution_{server1}_{server2}_analysis_{timestamp}.png (convolution analysis)")
    print(f"  - ntp_{server1}_{server2}_processed_data_{timestamp}.csv (processed data)")
    
    # Basic statistics
    print(f"\nBasic Statistics:")
    print(f"{server1}: Mean = {f1.mean():.3f} μs, Std = {f1.std():.3f} μs")
    print(f"{server2}: Mean = {f2.mean():.3f} μs, Std = {f2.std():.3f} μs")
    print(f"Empirical difference: Mean = {f1.mean() - f2.mean():.3f} μs")
    print("=" * 60)

if __name__ == "__main__":
    # Example usage with command line arguments
    import argparse
    
    parser = argparse.ArgumentParser(description='Analyze NTP timing offsets from remote servers')
    parser.add_argument('--server1', required=True, help='Hostname of first server (from SSH config)')
    parser.add_argument('--server2', required=True, help='Hostname of second server (from SSH config)')
    parser.add_argument('--logpath', default='/var/log/chrony/tracking.log', 
                        help='Path to chrony tracking log on remote servers')
    parser.add_argument('--timeout', type=int, default=60, 
                        help='Timeout in seconds for SSH operations')
    
    args = parser.parse_args()
    
    # Run the complete analysis
    analyze_ntp_timing(
        args.server1,
        args.server2,
        args.logpath,
        args.timeout
    )
