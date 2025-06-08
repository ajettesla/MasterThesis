import re
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from scipy import stats
from datetime import datetime

def acNhist2(c, figFlag=True, label='', color='k', linewidth=2):
    """
    Accurate histogram using Scott's rule - MATLAB equivalent
    Returns line plot, not bars
    """
    c = np.array(c)
    c = c[~np.isnan(c)]  # Remove NaN values
    
    if len(c) == 0:
        return None, None
    
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
    
    return bins, p

def parse_log(log_file):
    """
    Parse PTP log file and extract timing offsets
    Expected format: YYYY-MM-DD HH:MM:SS.ssssss, field1, field2, field3, offset,
    """
    data_connt1 = []
    data_connt2 = []
    
    print(f"Parsing log file: {log_file}")
    
    try:
        with open(log_file, 'r') as file:
            line_count = 0
            parsed_count = 0
            
            for line in file:
                line_count += 1
                
                if 'connt1' in line or 'connt2' in line:
                    # Regex to match timestamp and offset value
                    match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d+\.\d+), .*?, .*?,  .*?,  ([-]?\d+\.\d+),', line)
                    
                    if match:
                        try:
                            offset = float(match.group(2)) * 1e6  # Convert seconds to microseconds
                            
                            if 'connt1' in line:
                                data_connt1.append(offset)
                            else:
                                data_connt2.append(offset)
                            
                            parsed_count += 1
                            
                        except ValueError as e:
                            print(f"Warning: Could not parse offset on line {line_count}: {e}")
            
            print(f"Processed {line_count} lines, extracted {parsed_count} measurements")
            print(f"connt1 measurements: {len(data_connt1)}")
            print(f"connt2 measurements: {len(data_connt2)}")
    
    except FileNotFoundError:
        print(f"Error: Log file {log_file} not found")
        return None, None
    except Exception as e:
        print(f"Error reading log file: {e}")
        return None, None
    
    return pd.Series(data_connt1, name='connt1_offset'), pd.Series(data_connt2, name='connt2_offset')

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

def plot_combined_distributions(f1, f2):
    """
    Plot 1: Individual distributions of connt1 and connt2 overlaid (MATLAB-style line plots)
    """
    print("\n=== Creating Combined Distribution Plot ===")
    
    plt.figure(figsize=(14, 7))
    
    # Use Scott's rule for each dataset - LINE PLOTS
    bins1, p1 = acNhist2(f1, figFlag=False)
    bins2, p2 = acNhist2(f2, figFlag=False)
    
    if bins1 is not None and p1 is not None:
        plt.plot(bins1, p1, 'b-', linewidth=2, label=f'connt1 (n={len(f1)})')
    
    if bins2 is not None and p2 is not None:
        plt.plot(bins2, p2, 'g-', linewidth=2, label=f'connt2 (n={len(f2)})')
    
    plt.title('PTP Timing Offset Distributions (connt1 vs connt2)', fontsize=16)
    plt.xlabel('Offset (μs)', fontsize=14)
    plt.ylabel('Density', fontsize=14)
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.legend()
    plt.tight_layout()
    
    filename = 'combined_connt1_connt2.png'
    plt.savefig(filename, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Saved combined histogram as '{filename}'")

def plot_difference_analysis(f1, f2):
    """
    Plot 2: Difference analysis (connt1 - connt2) with statistics
    """
    print("\n=== Creating Difference Analysis Plot ===")
    
    # Calculate difference - handle different lengths
    if len(f1) == len(f2):
        print("Using aligned data (same length after filtering)")
        diff = f1.values - f2.values
        method = "aligned"
    else:
        # Use minimum length to ensure proper pairing
        min_len = min(len(f1), len(f2))
        print(f"Different lengths - using first {min_len} samples from each")
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
    ci_bounds = {
        level: stats.norm.interval(level / 100, loc=mean_val, scale=std_val / np.sqrt(count))
        for level in confidence_levels
    }
    
    # Plot difference using Scott's rule - LINE PLOT (MATLAB style)
    plt.figure(figsize=(14, 7))
    
    bins, density = acNhist2(diff_filtered, figFlag=False)
    
    if bins is not None and density is not None:
        plt.plot(bins, density, 'k-', linewidth=2, label='connt1 - connt2')
        max_density = max(density)
    else:
        max_density = 1
        print("Warning: Could not calculate density for difference")
    
    plt.title("Offset Difference (connt1 - connt2)", fontsize=16)
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
    filename = 'connt1_minus_connt2_difference.png'
    plt.savefig(filename, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Saved difference plot as '{filename}'")

def save_processed_data(connt1, connt2):
    """
    Save processed data to CSV file
    """
    # Create DataFrame with proper alignment
    max_len = max(len(connt1), len(connt2))
    df = pd.DataFrame({
        'connt1_offset': connt1.reindex(range(max_len)),
        'connt2_offset': connt2.reindex(range(max_len))
    })
    
    filename = 'test02200_processed_data.csv'
    df.to_csv(filename, index=False)
    print(f"Saved processed data to '{filename}'")

def analyze_ptp_timing(log_file='/var/log/ptp.log'):
    """
    Complete PTP timing analysis workflow
    """
    print("=" * 60)
    print(f"PTP Timing Analysis Started")
    print(f"Date: 2025-06-08 14:34:41 UTC")
    print(f"User: ajettesla")
    print("=" * 60)
    
    # Parse log file
    connt1, connt2 = parse_log(log_file)
    
    if connt1 is None or connt2 is None:
        print("Failed to parse log file. Exiting.")
        return
    
    if len(connt1) == 0 and len(connt2) == 0:
        print("No data found in log file. Exiting.")
        return
    
    # Save raw processed data
    save_processed_data(connt1, connt2)
    
    # Filter outliers
    print("\n=== Filtering Outliers (IQR Method) ===")
    print("Filtering connt1 data:")
    f1 = iqr_filter(connt1.dropna())
    print("Filtering connt2 data:")
    f2 = iqr_filter(connt2.dropna())
    
    if len(f1) == 0 or len(f2) == 0:
        print("No data remaining after filtering. Check your data quality.")
        return
    
    # Plot 1: Combined distributions (individual overlaid)
    plot_combined_distributions(f1, f2)
    
    # Plot 2: Difference analysis
    plot_difference_analysis(f1, f2)
    
    # Final summary
    print("\n" + "=" * 60)
    print("ANALYSIS SUMMARY")
    print("=" * 60)
    print(f"Processed {len(f1)} values from connt1 after filtering.")
    print(f"Processed {len(f2)} values from connt2 after filtering.")
    print(f"Generated plots:")
    print(f"  - combined_connt1_connt2.png (individual distributions)")
    print(f"  - connt1_minus_connt2_difference.png (difference analysis)")
    print(f"  - test02200_processed_data.csv (processed data)")
    
    # Basic statistics
    print(f"\nBasic Statistics:")
    print(f"connt1: Mean = {f1.mean():.3f} μs, Std = {f1.std():.3f} μs")
    print(f"connt2: Mean = {f2.mean():.3f} μs, Std = {f2.std():.3f} μs")
    print(f"Mean difference: {f1.mean() - f2.mean():.3f} μs")
    print("=" * 60)

if __name__ == "__main__":
    # Run the complete analysis
    analyze_ptp_timing('/var/log/ptp.log')
