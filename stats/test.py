import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from scipy import stats
import warnings
warnings.filterwarnings('ignore')
from datetime import datetime

def analyze_conntrackd_realistic_delays():
    """
    Conntrackd analysis with realistic delay bounds based on experiment duration
    """
    print("=" * 90)
    print(f"CONNTRACKD ANALYSIS - REALISTIC DELAY BOUNDS")
    print(f"Date: 2025-06-08 20:02:15 UTC")
    print(f"User: ajettesla")
    print(f"Analysis: Forward sync delays with experiment-duration constraints")
    print("=" * 90)
    
    # Experiment parameters
    EXPERIMENT_DURATION_SEC = 700  # Your experiment duration
    MAX_REALISTIC_DELAY_MS = EXPERIMENT_DURATION_SEC * 1000 * 0.1  # Max 10% of experiment duration
    
    print(f"Experiment Constraints:")
    print(f"  Experiment duration: {EXPERIMENT_DURATION_SEC} seconds")
    print(f"  Maximum realistic delay: {MAX_REALISTIC_DELAY_MS} ms ({MAX_REALISTIC_DELAY_MS/1000} seconds)")
    print(f"  Rationale: Delays > 10% of experiment duration are measurement artifacts")
    
    # Load data
    filename = 'test02200_processed_data.csv'
    try:
        df = pd.read_csv(filename)
        print(f"\nLoaded {len(df):,} conntrackd sync events from CSV")
    except FileNotFoundError:
        print(f"Error: File {filename} not found")
        return
    
    if 'timediff' not in df.columns:
        print("Available columns:", df.columns.tolist())
        return
    
    # Convert to milliseconds
    print("Converting conntrackd sync delay from nanoseconds to milliseconds...")
    sync_delay_ms = df['timediff'] / 1e6  # ns to ms
    
    print(f"Original range: [{sync_delay_ms.min():.3f}, {sync_delay_ms.max():.3f}] ms")
    
    # Apply realistic filtering
    realistic_delays = apply_realistic_filtering(sync_delay_ms, MAX_REALISTIC_DELAY_MS)
    
    # Analyze realistic delays
    analyze_realistic_patterns(realistic_delays)
    
    # Distribution analysis with realistic data
    best_distribution = analyze_realistic_distribution(realistic_delays)
    
    # Create realistic plots
    create_realistic_plots(sync_delay_ms, realistic_delays, best_distribution)
    
    # Performance assessment
    assess_realistic_performance(realistic_delays)

def apply_realistic_filtering(data, max_delay_ms):
    """
    Apply realistic filtering based on experiment constraints
    """
    print(f"\n=== Realistic Delay Filtering ===")
    
    original_count = len(data)
    
    # Step 1: Remove negative delays (reverse sync artifacts)
    positive_delays = data[data >= 0]
    negative_removed = original_count - len(positive_delays)
    
    # Step 2: Remove delays exceeding experiment duration constraints
    realistic_delays = positive_delays[positive_delays <= max_delay_ms]
    unrealistic_removed = len(positive_delays) - len(realistic_delays)
    
    # Step 3: Analyze what we removed
    print(f"Filtering Steps:")
    print(f"  1. Original samples: {original_count:,}")
    print(f"  2. Negative delays removed: {negative_removed:,} ({negative_removed/original_count*100:.2f}%)")
    print(f"  3. Positive delays: {len(positive_delays):,} ({len(positive_delays)/original_count*100:.2f}%)")
    print(f"  4. Unrealistic delays removed: {unrealistic_removed:,} ({unrealistic_removed/len(positive_delays)*100:.2f}%)")
    print(f"  5. Final realistic delays: {len(realistic_delays):,} ({len(realistic_delays)/original_count*100:.2f}%)")
    
    print(f"\nRealistic delay range: [{realistic_delays.min():.3f}, {realistic_delays.max():.3f}] ms")
    
    # Analyze the unrealistic delays we removed
    if unrealistic_removed > 0:
        unrealistic_delays = positive_delays[positive_delays > max_delay_ms]
        print(f"\nUnrealistic Delays Analysis:")
        print(f"  Count: {len(unrealistic_delays):,}")
        print(f"  Range: [{unrealistic_delays.min():.1f}, {unrealistic_delays.max():.1f}] ms")
        print(f"  Mean: {unrealistic_delays.mean():.1f} ms")
        print(f"  These are likely measurement artifacts or system errors")
        
        # Show distribution of unrealistic delays
        percentiles = [50, 90, 95, 99]
        print(f"  Percentiles of unrealistic delays:")
        for p in percentiles:
            value = unrealistic_delays.quantile(p/100)
            print(f"    {p}th: {value:.1f} ms ({value/1000:.1f} seconds)")
    
    return realistic_delays

def analyze_realistic_patterns(data):
    """
    Analyze realistic delay patterns
    """
    print(f"\n=== Realistic Conntrackd Sync Analysis ({len(data):,} samples) ===")
    
    # Basic statistics
    mean_delay = data.mean()
    median_delay = data.median()
    std_delay = data.std()
    
    print(f"Realistic Sync Statistics:")
    print(f"  Mean delay: {mean_delay:.3f} ms")
    print(f"  Median delay: {median_delay:.3f} ms")
    print(f"  Standard deviation: {std_delay:.3f} ms")
    print(f"  Coefficient of variation: {std_delay/mean_delay:.3f}")
    print(f"  Range: [{data.min():.3f}, {data.max():.3f}] ms")
    
    # Detailed percentile analysis
    percentiles = [1, 5, 10, 25, 50, 75, 90, 95, 99, 99.5, 99.9]
    print(f"\nRealistic Delay Percentiles:")
    for p in percentiles:
        value = data.quantile(p / 100)
        print(f"  {p:5.1f}th percentile: {value:8.3f} ms")
    
    # Performance categories with realistic bounds
    print(f"\nRealistic Performance Categories:")
    
    excellent = data[data < 1]               # < 1ms
    good = data[(data >= 1) & (data < 10)]            # 1-10ms
    acceptable = data[(data >= 10) & (data < 50)]     # 10-50ms
    slow = data[(data >= 50) & (data < 200)]          # 50-200ms
    concerning = data[(data >= 200) & (data < 1000)]  # 200ms-1s
    very_slow = data[data >= 1000]                     # > 1s
    
    total = len(data)
    print(f"  Excellent (<1ms):       {len(excellent):,} ({len(excellent)/total*100:.1f}%)")
    print(f"  Good (1-10ms):          {len(good):,} ({len(good)/total*100:.1f}%)")
    print(f"  Acceptable (10-50ms):   {len(acceptable):,} ({len(acceptable)/total*100:.1f}%)")
    print(f"  Slow (50-200ms):        {len(slow):,} ({len(slow)/total*100:.1f}%)")
    print(f"  Concerning (0.2-1s):    {len(concerning):,} ({len(concerning)/total*100:.1f}%)")
    print(f"  Very Slow (>1s):        {len(very_slow):,} ({len(very_slow)/total*100:.1f}%)")
    
    # Distribution characteristics
    skewness = stats.skew(data)
    kurtosis = stats.kurtosis(data)
    
    print(f"\nDistribution Shape (Realistic Data):")
    print(f"  Skewness: {skewness:.3f} ", end="")
    if skewness > 2:
        print("(Highly right-skewed)")
    elif skewness > 1:
        print("(Right-skewed)")
    elif skewness > 0.5:
        print("(Slightly right-skewed)")
    else:
        print("(Nearly symmetric)")
    
    print(f"  Kurtosis: {kurtosis:.3f} ", end="")
    if kurtosis > 3:
        print("(Heavy tails)")
    elif kurtosis > 0:
        print("(Some excess kurtosis)")
    else:
        print("(Normal or light tails)")

def analyze_realistic_distribution(data):
    """
    Distribution analysis with realistic delay bounds
    """
    print(f"\n=== Distribution Analysis - Realistic Delays ===")
    
    # Use larger sample for more accurate results
    if len(data) > 1000000:
        sample_data = data.sample(n=1000000, random_state=42)
        print(f"Using random sample of 1,000,000 points for distribution fitting")
    else:
        sample_data = data
        print(f"Using all {len(sample_data):,} points for distribution fitting")
    
    # Test distributions appropriate for bounded positive delays
    realistic_distributions = [
        ('Exponential', stats.expon, 'Memoryless processing delays'),
        ('Gamma', stats.gamma, 'Multi-stage processing pipeline'),
        ('Log-Normal', stats.lognorm, 'Multiplicative network effects'),
        ('Weibull', stats.weibull_min, 'System reliability patterns'),
        ('Chi-Square', stats.chi2, 'Sum of squared delays'),
        ('Inverse Gaussian', stats.invgauss, 'First passage time'),
        ('Log-Logistic', stats.fisk, 'Heavy-tailed network delays'),
        ('Pareto', stats.pareto, 'Self-similar traffic'),
        ('Beta', stats.beta, 'Bounded delays with shape'),
        ('Uniform', stats.uniform, 'Constant processing time')
    ]
    
    results = []
    print(f"\nTesting {len(realistic_distributions)} distributions...")
    print(f"{'Distribution':<15} {'AIC':<12} {'BIC':<12} {'KS p-val':<12} {'R²':<8}")
    print("-" * 70)
    
    for name, dist, description in realistic_distributions:
        try:
            # Handle different distribution requirements
            if name == 'Beta':
                # Beta requires [0,1] range
                test_data = (sample_data - sample_data.min()) / (sample_data.max() - sample_data.min())
            elif name == 'Uniform':
                # Uniform uses location and scale
                test_data = sample_data
            else:
                # Most distributions work with positive data
                test_data = sample_data
            
            # Fit distribution
            params = dist.fit(test_data)
            
            # Calculate metrics
            if name == 'Beta':
                log_likelihood = np.sum(dist.logpdf(test_data, *params))
            else:
                log_likelihood = np.sum(dist.logpdf(test_data, *params))
            
            k = len(params)
            n = len(test_data)
            aic = 2 * k - 2 * log_likelihood
            bic = k * np.log(n) - 2 * log_likelihood
            
            # KS test with reasonable sample
            ks_sample = test_data.sample(n=min(10000, len(test_data)), random_state=42)
            ks_stat, ks_p = stats.kstest(ks_sample, dist.cdf, args=params)
            
            # R-squared calculation
            hist_counts, bin_edges = np.histogram(test_data, bins=100, density=True)
            bin_centers = (bin_edges[:-1] + bin_edges[1:]) / 2
            
            if name == 'Beta':
                theoretical_density = dist.pdf(bin_centers, *params)
            else:
                theoretical_density = dist.pdf(bin_centers, *params)
            
            ss_res = np.sum((hist_counts - theoretical_density) ** 2)
            ss_tot = np.sum((hist_counts - np.mean(hist_counts)) ** 2)
            r_squared = 1 - (ss_res / ss_tot) if ss_tot != 0 else 0
            
            results.append({
                'name': name,
                'distribution': dist,
                'params': params,
                'aic': aic,
                'bic': bic,
                'ks_p': ks_p,
                'r_squared': r_squared,
                'description': description,
                'test_data': test_data
            })
            
            print(f"{name:<15} {aic:<12.1f} {bic:<12.1f} {ks_p:<12.6f} {r_squared:<8.3f}")
            
        except Exception as e:
            print(f"{name:<15} FAILED: {str(e)[:35]}")
    
    if results:
        # Sort by AIC
        results.sort(key=lambda x: x['aic'])
        
        print(f"\n=== Top 5 Best Fits for Realistic Delays ===")
        for i, result in enumerate(results[:5], 1):
            print(f"{i}. {result['name']:<15} AIC: {result['aic']:.1f}, R²: {result['r_squared']:.3f}")
        
        best_fit = results[0]
        print(f"\n=== BEST FIT FOR REALISTIC CONNTRACKD DELAYS ===")
        print(f"Distribution: {best_fit['name']}")
        print(f"Description: {best_fit['description']}")
        print(f"AIC Score: {best_fit['aic']:.1f}")
        print(f"R-squared: {best_fit['r_squared']:.3f}")
        print(f"Parameters: {best_fit['params']}")
        
        return best_fit
    
    return None

def create_realistic_plots(original_data, realistic_data, best_distribution=None):
    """
    Create plots comparing original vs realistic delay analysis
    """
    fig, axes = plt.subplots(3, 2, figsize=(18, 20))
    fig.suptitle(f'Conntrackd Realistic Delay Analysis\nExperiment Duration: 700s, Max Realistic Delay: 70s', 
                 fontsize=16, fontweight='bold')
    
    # Plot 1: Original vs Realistic data comparison
    ax1 = axes[0, 0]
    
    categories = ['Original\nData', 'Realistic\nDelays', 'Removed\nArtifacts']
    values = [len(original_data), len(realistic_data), len(original_data) - len(realistic_data)]
    colors = ['lightcoral', 'lightgreen', 'lightgray']
    
    bars = ax1.bar(categories, values, color=colors, alpha=0.7)
    ax1.set_title('Data Quality Improvement')
    ax1.set_ylabel('Number of Samples')
    
    for bar, value in zip(bars, values):
        height = bar.get_height()
        pct = value / len(original_data) * 100
        ax1.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                f'{value:,}\n({pct:.1f}%)', ha='center', va='bottom', fontsize=10)
    
    ax1.grid(True, alpha=0.3)
    
    # Plot 2: Realistic delay histogram with performance zones
    ax2 = axes[0, 1]
    
    sample_realistic = realistic_data.sample(n=min(100000, len(realistic_data)), random_state=42)
    
    counts, bins, patches = ax2.hist(sample_realistic, bins=100, density=True, 
                                    alpha=0.7, color='lightblue', edgecolor='black')
    
    # Color performance zones
    for i, patch in enumerate(patches):
        bin_center = (bins[i] + bins[i+1]) / 2
        if bin_center < 1:
            patch.set_facecolor('green')
        elif bin_center < 10:
            patch.set_facecolor('lightgreen')
        elif bin_center < 50:
            patch.set_facecolor('yellow')
        elif bin_center < 200:
            patch.set_facecolor('orange')
        else:
            patch.set_facecolor('red')
    
    # Statistical markers
    mean_val = realistic_data.mean()
    median_val = realistic_data.median()
    
    ax2.axvline(mean_val, color='red', linestyle='-', linewidth=2, label=f'Mean: {mean_val:.1f}ms')
    ax2.axvline(median_val, color='blue', linestyle='--', linewidth=2, label=f'Median: {median_val:.1f}ms')
    
    # Best fit overlay
    if best_distribution:
        x_range = np.linspace(sample_realistic.min(), sample_realistic.max(), 1000)
        try:
            if best_distribution['name'] == 'Beta':
                pdf_values = best_distribution['distribution'].pdf(
                    (x_range - sample_realistic.min()) / (sample_realistic.max() - sample_realistic.min()),
                    *best_distribution['params'])
                pdf_values = pdf_values / (sample_realistic.max() - sample_realistic.min())
            else:
                pdf_values = best_distribution['distribution'].pdf(x_range, *best_distribution['params'])
            
            ax2.plot(x_range, pdf_values, 'purple', linewidth=3, 
                    label=f'Best Fit: {best_distribution["name"]}')
        except:
            pass
    
    ax2.set_title('Realistic Delay Distribution with Performance Zones')
    ax2.set_xlabel('Sync Delay (ms)')
    ax2.set_ylabel('Density')
    ax2.legend()
    ax2.grid(True, alpha=0.3)
    
    # Plot 3: Before/After percentile comparison
    ax3 = axes[1, 0]
    
    percentiles = [50, 75, 90, 95, 99]
    
    # Calculate percentiles for both datasets
    positive_original = original_data[original_data >= 0]
    original_percentiles = [positive_original.quantile(p/100) for p in percentiles]
    realistic_percentiles = [realistic_data.quantile(p/100) for p in percentiles]
    
    x = np.arange(len(percentiles))
    width = 0.35
    
    bars1 = ax3.bar(x - width/2, original_percentiles, width, label='Original (Positive)', alpha=0.7, color='red')
    bars2 = ax3.bar(x + width/2, realistic_percentiles, width, label='Realistic', alpha=0.7, color='green')
    
    ax3.set_title('Percentile Comparison: Original vs Realistic')
    ax3.set_xlabel('Percentile')
    ax3.set_ylabel('Delay (ms)')
    ax3.set_xticks(x)
    ax3.set_xticklabels([f'{p}%' for p in percentiles])
    ax3.legend()
    ax3.set_yscale('log')
    ax3.grid(True, alpha=0.3)
    
    # Plot 4: Performance category breakdown
    ax4 = axes[1, 1]
    
    excellent = len(realistic_data[realistic_data < 1])
    good = len(realistic_data[(realistic_data >= 1) & (realistic_data < 10)])
    acceptable = len(realistic_data[(realistic_data >= 10) & (realistic_data < 50)])
    slow = len(realistic_data[(realistic_data >= 50) & (realistic_data < 200)])
    concerning = len(realistic_data[(realistic_data >= 200) & (realistic_data < 1000)])
    very_slow = len(realistic_data[realistic_data >= 1000])
    
    categories = ['Excellent\n<1ms', 'Good\n1-10ms', 'Acceptable\n10-50ms', 
                  'Slow\n50-200ms', 'Concerning\n0.2-1s', 'Very Slow\n>1s']
    values = [excellent, good, acceptable, slow, concerning, very_slow]
    colors = ['green', 'lightgreen', 'yellow', 'orange', 'red', 'darkred']
    
    # Only show non-zero categories
    non_zero_idx = [i for i, v in enumerate(values) if v > 0]
    filtered_categories = [categories[i] for i in non_zero_idx]
    filtered_values = [values[i] for i in non_zero_idx]
    filtered_colors = [colors[i] for i in non_zero_idx]
    
    bars = ax4.bar(filtered_categories, filtered_values, color=filtered_colors, alpha=0.7)
    ax4.set_title('Performance Category Distribution')
    ax4.set_ylabel('Number of Events')
    
    # Add percentage labels
    total = len(realistic_data)
    for bar, value in zip(bars, filtered_values):
        height = bar.get_height()
        pct = value / total * 100
        ax4.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                f'{value:,}\n({pct:.1f}%)', ha='center', va='bottom', fontsize=9)
    
    ax4.grid(True, alpha=0.3)
    plt.setp(ax4.xaxis.get_majorticklabels(), rotation=45, ha='right')
    
    # Plot 5: Time series view (if applicable)
    ax5 = axes[2, 0]
    
    time_sample = realistic_data.head(min(50000, len(realistic_data)))
    ax5.plot(range(len(time_sample)), time_sample, alpha=0.6, linewidth=0.5, color='blue')
    
    # Add moving average
    if len(time_sample) > 1000:
        window_size = len(time_sample) // 100
        moving_avg = time_sample.rolling(window=window_size, center=True).mean()
        ax5.plot(range(len(moving_avg)), moving_avg, color='red', linewidth=2, 
                label=f'Moving Average (window={window_size})')
        ax5.legend()
    
    ax5.set_title(f'Realistic Delay Time Series\nFirst {len(time_sample):,} events')
    ax5.set_xlabel('Event Number')
    ax5.set_ylabel('Delay (ms)')
    ax5.grid(True, alpha=0.3)
    
    # Plot 6: Summary and recommendations
    ax6 = axes[2, 1]
    ax6.axis('off')
    
    # Calculate key metrics
    fast_events = (excellent + good) / len(realistic_data) * 100
    problem_events = (concerning + very_slow) / len(realistic_data) * 100
    
    summary_text = f"""REALISTIC CONNTRACKD ANALYSIS

Experiment Constraints:
• Duration: 700 seconds
• Max Realistic Delay: 70 seconds
• Data Retained: {len(realistic_data)/len(original_data)*100:.1f}%

Performance Summary:
• Mean Delay: {realistic_data.mean():.2f} ms
• Median Delay: {realistic_data.median():.2f} ms
• 95th Percentile: {realistic_data.quantile(0.95):.2f} ms
• 99th Percentile: {realistic_data.quantile(0.99):.2f} ms

Quality Metrics:
• Fast Events (<10ms): {fast_events:.1f}%
• Problem Events (>200ms): {problem_events:.1f}%

Distribution:
"""
    
    if best_distribution:
        summary_text += f"• Best Fit: {best_distribution['name']}\n"
        summary_text += f"• R² Score: {best_distribution['r_squared']:.3f}\n"
    
    # Performance rating
    if fast_events > 50 and problem_events < 10:
        rating = "GOOD"
    elif fast_events > 30 and problem_events < 20:
        rating = "ACCEPTABLE"
    else:
        rating = "NEEDS IMPROVEMENT"
    
    summary_text += f"\nOverall Rating: {rating}"
    
    ax6.text(0.05, 0.95, summary_text, transform=ax6.transAxes, fontsize=10,
             verticalalignment='top', fontfamily='monospace',
             bbox=dict(boxstyle='round', facecolor='lightgray', alpha=0.9))
    
    plt.tight_layout()
    filename = 'conntrackd_realistic_analysis.png'
    plt.savefig(filename, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"\nSaved realistic analysis: {filename}")

def assess_realistic_performance(data):
    """
    Performance assessment with realistic constraints
    """
    print(f"\n=== Realistic Performance Assessment ===")
    
    mean_delay = data.mean()
    median_delay = data.median()
    p95 = data.quantile(0.95)
    p99 = data.quantile(0.99)
    
    print(f"Realistic Conntrackd Metrics:")
    print(f"  Sample size: {len(data):,}")
    print(f"  Mean delay: {mean_delay:.3f} ms")
    print(f"  Median delay: {median_delay:.3f} ms")
    print(f"  95th percentile: {p95:.3f} ms")
    print(f"  99th percentile: {p99:.3f} ms")
    
    # Performance categories
    excellent = len(data[data < 1])
    good = len(data[(data >= 1) & (data < 10)])
    acceptable = len(data[(data >= 10) & (data < 50)])
    slow = len(data[(data >= 50) & (data < 200)])
    concerning = len(data[(data >= 200) & (data < 1000)])
    very_slow = len(data[data >= 1000])
    
    total = len(data)
    
    print(f"\nRealistic Performance Distribution:")
    print(f"  Excellent (<1ms):     {excellent:,} ({excellent/total*100:.1f}%)")
    print(f"  Good (1-10ms):        {good:,} ({good/total*100:.1f}%)")
    print(f"  Acceptable (10-50ms): {acceptable:,} ({acceptable/total*100:.1f}%)")
    print(f"  Slow (50-200ms):      {slow:,} ({slow/total*100:.1f}%)")
    print(f"  Concerning (0.2-1s):  {concerning:,} ({concerning/total*100:.1f}%)")
    print(f"  Very Slow (>1s):      {very_slow:,} ({very_slow/total*100:.1f}%)")
    
    # Overall assessment
    fast_events = (excellent + good) / total
    problem_events = (concerning + very_slow) / total
    
    print(f"\nKey Performance Indicators:")
    print(f"  Fast events (<10ms): {fast_events*100:.1f}%")
    print(f"  Problem events (>200ms): {problem_events*100:.1f}%")
    
    if fast_events > 0.5 and problem_events < 0.1:
        rating = "EXCELLENT"
    elif fast_events > 0.3 and problem_events < 0.2:
        rating = "GOOD"
    elif fast_events > 0.1 and problem_events < 0.3:
        rating = "ACCEPTABLE"
    else:
        rating = "NEEDS IMPROVEMENT"
    
    print(f"  Overall Rating: {rating}")
    
    print(f"\nRealistic Insights:")
    print(f"  • Median delay of {median_delay:.1f}ms is {'excellent' if median_delay < 10 else 'good' if median_delay < 50 else 'acceptable'}")
    print(f"  • 99th percentile of {p99:.1f}ms is {'reasonable' if p99 < 1000 else 'concerning'}")
    print(f"  • Data quality: Realistic bounds applied, artifacts removed")

if __name__ == "__main__":
    analyze_conntrackd_realistic_delays()
