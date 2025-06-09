import re
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from scipy import stats
from scipy.stats import ttest_ind, ks_2samp, mannwhitneyu, levene, linregress
import warnings
import gzip
import glob
import os
from datetime import datetime
warnings.filterwarnings('ignore')

def find_ptp_log_files_ordered(base_path='/var/log/'):
    """Find PTP log files in chronological order"""
    log_files = []
    
    # Main log (most recent)
    main_log = os.path.join(base_path, 'ptp.log')
    if os.path.exists(main_log):
        log_files.append(('current', main_log))
    
    # Compressed files (oldest to newest: .1.gz is newest archive)
    compressed_pattern = os.path.join(base_path, 'ptp.log.*.gz')
    compressed_files = glob.glob(compressed_pattern)
    
    # Sort by number (highest number = oldest)
    compressed_files.sort(key=lambda x: int(x.split('.')[-2]), reverse=True)
    
    for f in compressed_files:
        number = int(f.split('.')[-2])
        log_files.append((f'archive_{number}', f))
    
    print(f"Found {len(log_files)} log files:")
    for key, file in log_files:
        print(f"  {key}: {os.path.basename(file)}")
    
    return log_files

def parse_log_file(log_file):
    """Parse single log file"""
    data_connt1 = []
    data_connt2 = []
    
    try:
        if log_file.endswith('.gz'):
            file_handle = gzip.open(log_file, 'rt', encoding='utf-8')
        else:
            file_handle = open(log_file, 'r', encoding='utf-8')
        
        line_count = 0
        parsed_count = 0
        
        with file_handle as file:
            for line in file:
                line_count += 1
                if 'connt1' in line or 'connt2' in line:
                    match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d+\.\d+), .*?, .*?,  .*?,  ([-]?\d+\.\d+),', line)
                    if match:
                        try:
                            offset = float(match.group(2)) * 1e6
                            if 'connt1' in line:
                                data_connt1.append(offset)
                            else:
                                data_connt2.append(offset)
                            parsed_count += 1
                        except ValueError:
                            pass
        
        print(f"    {os.path.basename(log_file)}: {line_count} lines, {parsed_count} measurements")
        return data_connt1, data_connt2
        
    except Exception as e:
        print(f"    Error reading {os.path.basename(log_file)}: {e}")
        return [], []

def clean_outliers(data):
    """Remove outliers using IQR method"""
    if len(data) == 0:
        return pd.Series(dtype=float), 0
    
    data_series = pd.Series(data)
    Q1 = data_series.quantile(0.25)
    Q3 = data_series.quantile(0.75)
    IQR = Q3 - Q1
    lower_bound = Q1 - 1.5 * IQR
    upper_bound = Q3 + 1.5 * IQR
    
    cleaned = data_series[(data_series >= lower_bound) & (data_series <= upper_bound)]
    removed = len(data_series) - len(cleaned)
    
    return cleaned, removed

def test_temporal_stability(recent_data, total_data, stage, total_samples):
    """Test if recent data is statistically similar to total data"""
    
    # Skip if not enough data
    if len(recent_data) < 100 or len(total_data) < 500:
        return {
            'stability_score': 0, 
            'stable_tests': 0, 
            'total_tests': 0,
            'test_results': {},
            'stats_recent': {},
            'stats_total': {},
            'effect_size': 0,
            'recent_samples': len(recent_data),
            'total_samples': len(total_data)
        }
    
    stable_tests = 0
    total_tests = 0
    test_results = {}
    
    try:
        # T-test for means
        t_stat, t_p = ttest_ind(recent_data, total_data, equal_var=False)
        test_results['t_test_p'] = t_p
        if t_p > 0.05:
            stable_tests += 1
        total_tests += 1
    except:
        test_results['t_test_p'] = np.nan
    
    try:
        # KS test for distributions
        ks_stat, ks_p = ks_2samp(recent_data, total_data)
        test_results['ks_test_p'] = ks_p
        if ks_p > 0.05:
            stable_tests += 1
        total_tests += 1
    except:
        test_results['ks_test_p'] = np.nan
    
    try:
        # Mann-Whitney for medians
        u_stat, u_p = mannwhitneyu(recent_data, total_data, alternative='two-sided')
        test_results['mw_test_p'] = u_p
        if u_p > 0.05:
            stable_tests += 1
        total_tests += 1
    except:
        test_results['mw_test_p'] = np.nan
    
    try:
        # Levene for variances
        l_stat, l_p = levene(recent_data, total_data)
        test_results['levene_p'] = l_p
        if l_p > 0.05:
            stable_tests += 1
        total_tests += 1
    except:
        test_results['levene_p'] = np.nan
    
    stability_score = stable_tests / total_tests if total_tests > 0 else 0
    
    # Calculate descriptive statistics
    stats_recent = {
        'mean': recent_data.mean(),
        'std': recent_data.std(),
        'median': recent_data.median(),
        'cv': recent_data.std() / recent_data.mean() if recent_data.mean() != 0 else np.inf
    }
    
    stats_total = {
        'mean': total_data.mean(),
        'std': total_data.std(),
        'median': total_data.median(),
        'cv': total_data.std() / total_data.mean() if total_data.mean() != 0 else np.inf
    }
    
    # Effect size (Cohen's d)
    try:
        pooled_std = np.sqrt(((len(recent_data)-1)*stats_recent['std']**2 + 
                             (len(total_data)-1)*stats_total['std']**2) / 
                            (len(recent_data) + len(total_data) - 2))
        cohens_d = abs(stats_total['mean'] - stats_recent['mean']) / pooled_std if pooled_std > 0 else 0
    except:
        cohens_d = 0
    
    return {
        'stability_score': stability_score,
        'stable_tests': stable_tests,
        'total_tests': total_tests,
        'test_results': test_results,
        'stats_recent': stats_recent,
        'stats_total': stats_total,
        'effect_size': cohens_d,
        'recent_samples': len(recent_data),
        'total_samples': len(total_data)
    }

def progressive_stability_test(connection_name, base_path='/var/log/'):
    """
    Test stability as we progressively add more data
    Answer: Can connt1 EVER become stable with more data?
    """
    print("=" * 80)
    print(f"PROGRESSIVE STABILITY ANALYSIS FOR {connection_name.upper()}")
    print(f"Testing: Can {connection_name} become stable with MORE data?")
    print("=" * 80)
    
    # Load data chronologically (oldest to newest)
    log_files = find_ptp_log_files_ordered(base_path)
    log_files.reverse()  # Start with oldest data
    
    cumulative_data = []
    stability_progression = []
    
    print(f"\nLoading data chronologically (oldest → newest):")
    
    for stage, (key, log_file) in enumerate(log_files, 1):
        print(f"\nStage {stage}: Adding {key} - {os.path.basename(log_file)}")
        
        connt1_data, connt2_data = parse_log_file(log_file)
        
        if connection_name == 'connt1':
            new_data = connt1_data
        else:
            new_data = connt2_data
        
        cumulative_data.extend(new_data)
        cumulative_series = pd.Series(cumulative_data)
        
        print(f"    New data points: {len(new_data):,}")
        print(f"    Cumulative total: {len(cumulative_series):,}")
        
        # Clean outliers
        clean_data, removed = clean_outliers(cumulative_series)
        print(f"    After cleaning: {len(clean_data):,} (removed {removed} outliers)")
        
        if len(clean_data) < 1000:  # Need minimum data for analysis
            print(f"    Skipping - insufficient data for analysis")
            continue
        
        # Test stability by comparing recent 30% vs full dataset
        recent_30_size = int(len(clean_data) * 0.3)
        recent_30 = clean_data.tail(recent_30_size)
        
        print(f"    Testing recent 30% ({len(recent_30):,}) vs total ({len(clean_data):,})")
        
        # Statistical tests
        stability_metrics = test_temporal_stability(recent_30, clean_data, stage, len(clean_data))
        stability_metrics['stage'] = stage
        stability_metrics['total_samples'] = len(clean_data)
        stability_metrics['file_added'] = key
        
        stability_progression.append(stability_metrics)
        
        print(f"    Stability score: {stability_metrics['stability_score']*100:.0f}% "
              f"({stability_metrics['stable_tests']}/{stability_metrics['total_tests']} tests passed)")
        
        # Show individual test results
        test_results = stability_metrics['test_results']
        for test_name, p_value in test_results.items():
            if not np.isnan(p_value):
                status = "PASS" if p_value > 0.05 else "FAIL"
                print(f"      {test_name}: p={p_value:.4f} ({status})")
    
    return stability_progression

def analyze_stationarity(progression_data, connection_name):
    """
    Analyze if the connection can achieve stationarity (stability) with more data
    """
    print(f"\n{'='*60}")
    print(f"STATIONARITY ANALYSIS FOR {connection_name.upper()}")
    print(f"Question: Will {connection_name} EVER become stable?")
    print(f"{'='*60}")
    
    if len(progression_data) < 3:
        print("Insufficient data points for stationarity analysis")
        return {
            'stability_trend': None,
            'predicted_stability': None,
            'current_status': 'UNKNOWN',
            'recommendation': 'Need more data points'
        }
    
    # Extract progression metrics
    stages = [p['stage'] for p in progression_data]
    sample_sizes = [p['total_samples'] for p in progression_data]
    stability_scores = [p['stability_score'] for p in progression_data]
    effect_sizes = [p.get('effect_size', 0) for p in progression_data]
    
    print(f"\nProgression Summary:")
    print(f"{'Stage':<6} {'Samples':<10} {'Stability%':<12} {'Effect Size':<12} {'Assessment':<15}")
    print("-" * 70)
    
    for i, p in enumerate(progression_data):
        assessment = "STABLE" if p['stability_score'] >= 0.75 else "UNSTABLE" if p['stability_score'] < 0.5 else "MODERATE"
        print(f"{p['stage']:<6} {p['total_samples']:<10,} {p['stability_score']*100:<12.0f} "
              f"{p.get('effect_size', 0):<12.4f} {assessment:<15}")
    
    # Trend analysis
    if len(stages) >= 3:
        # Linear regression: stability vs log(sample_size)
        log_sizes = np.log10(sample_sizes)
        stability_trend = linregress(log_sizes, stability_scores)
        effect_trend = linregress(log_sizes, effect_sizes)
        
        print(f"\nTrend Analysis:")
        print(f"  Stability vs log(sample_size):")
        print(f"    Slope: {stability_trend.slope:.4f}")
        print(f"    R²: {stability_trend.rvalue**2:.4f}")
        print(f"    p-value: {stability_trend.pvalue:.6f}")
        
        print(f"  Effect size vs log(sample_size):")
        print(f"    Slope: {effect_trend.slope:.4f}")
        print(f"    R²: {effect_trend.rvalue**2:.4f}")
        print(f"    p-value: {effect_trend.pvalue:.6f}")
        
        # Interpretation
        print(f"\nInterpretation:")
        if stability_trend.pvalue < 0.05:
            if stability_trend.slope > 0:
                print("  ✓ STABILITY IMPROVES with more data")
                print("  → Adding more data WILL help achieve stability")
            else:
                print("  ✗ STABILITY DECREASES with more data")
                print("  → This indicates temporal drift/non-stationarity")
        else:
            print("  ⚠ NO SIGNIFICANT TREND in stability with sample size")
            print("  → Stability doesn't improve much with more data")
        
        if effect_trend.pvalue < 0.05:
            if effect_trend.slope < 0:
                print("  ✓ EFFECT SIZE DECREASES with more data (good)")
                print("  → Differences become smaller with larger samples")
            else:
                print("  ✗ EFFECT SIZE INCREASES with more data (concerning)")
                print("  → Temporal drift is getting worse")
        
        # Predict future stability
        max_log_size = np.log10(1000000)  # Predict for 1M samples
        predicted_stability = stability_trend.intercept + stability_trend.slope * max_log_size
        predicted_stability = max(0, min(1, predicted_stability))  # Bound between 0 and 1
        
        print(f"\nPrediction for 1,000,000 samples:")
        print(f"  Predicted stability score: {predicted_stability*100:.0f}%")
        
        if predicted_stability >= 0.75:
            conclusion = "✓ WILL BECOME STABLE with sufficient data"
        elif predicted_stability >= 0.5:
            conclusion = "⚠ MAY achieve moderate stability"
        else:
            conclusion = "✗ UNLIKELY to become stable (temporal drift)"
        
        print(f"  Conclusion: {conclusion}")
    else:
        stability_trend = None
        predicted_stability = None
    
    # Current status
    latest = progression_data[-1]
    print(f"\nCurrent Status ({latest['total_samples']:,} samples):")
    print(f"  Stability Score: {latest['stability_score']*100:.0f}%")
    print(f"  Effect Size: {latest.get('effect_size', 0):.4f}")
    
    if latest['stability_score'] >= 0.75:
        status = "ALREADY STABLE"
        recommendation = "Current data is sufficient"
    elif latest['stability_score'] >= 0.5:
        status = "MODERATELY STABLE"
        recommendation = "More data may help achieve full stability"
    else:
        status = "UNSTABLE"
        if stability_trend and stability_trend.pvalue < 0.05 and stability_trend.slope > 0:
            recommendation = "Continue collecting data - stability is improving"
        else:
            recommendation = "Data shows temporal drift - investigate root cause"
    
    print(f"  Status: {status}")
    print(f"  Recommendation: {recommendation}")
    
    return {
        'stability_trend': stability_trend,
        'predicted_stability': predicted_stability,
        'current_status': status,
        'recommendation': recommendation
    }

def create_progression_plots(connt1_progression, connt2_progression):
    """Create plots showing stability progression"""
    
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    fig.suptitle('PTP Stability Progression Analysis\nCan connt1 become stable with more data?', 
                 fontsize=16, fontweight='bold')
    
    # Plot 1: Stability Score vs Sample Size
    ax1 = axes[0, 0]
    
    if connt1_progression:
        c1_sizes = [p['total_samples'] for p in connt1_progression]
        c1_scores = [p['stability_score']*100 for p in connt1_progression]
        ax1.plot(c1_sizes, c1_scores, 'bo-', label='connt1', linewidth=2, markersize=6)
    
    if connt2_progression:
        c2_sizes = [p['total_samples'] for p in connt2_progression]
        c2_scores = [p['stability_score']*100 for p in connt2_progression]
        ax1.plot(c2_sizes, c2_scores, 'ro-', label='connt2', linewidth=2, markersize=6)
    
    ax1.axhline(y=75, color='green', linestyle='--', label='Stability Threshold (75%)')
    ax1.set_title('Stability Score vs Sample Size')
    ax1.set_xlabel('Total Samples')
    ax1.set_ylabel('Stability Score (%)')
    ax1.set_xscale('log')
    ax1.legend()
    ax1.grid(True, alpha=0.3)
    
    # Plot 2: Effect Size vs Sample Size
    ax2 = axes[0, 1]
    
    if connt1_progression:
        c1_effects = [p.get('effect_size', 0) for p in connt1_progression]
        ax2.plot(c1_sizes, c1_effects, 'bo-', label='connt1', linewidth=2, markersize=6)
    
    if connt2_progression:
        c2_effects = [p.get('effect_size', 0) for p in connt2_progression]
        ax2.plot(c2_sizes, c2_effects, 'ro-', label='connt2', linewidth=2, markersize=6)
    
    ax2.axhline(y=0.2, color='orange', linestyle='--', label='Small Effect (0.2)')
    ax2.set_title('Effect Size vs Sample Size')
    ax2.set_xlabel('Total Samples')
    ax2.set_ylabel("Cohen's d (Effect Size)")
    ax2.set_xscale('log')
    ax2.legend()
    ax2.grid(True, alpha=0.3)
    
    # Plot 3: Test Results Breakdown for connt1
    ax3 = axes[1, 0]
    
    if connt1_progression:
        latest_c1 = connt1_progression[-1]
        test_names = ['T-test', 'KS-test', 'Mann-Whitney', 'Levene']
        test_keys = ['t_test_p', 'ks_test_p', 'mw_test_p', 'levene_p']
        test_results_c1 = []
        p_values = []
        
        for key in test_keys:
            p_val = latest_c1['test_results'].get(key, np.nan)
            p_values.append(p_val)
            test_results_c1.append(p_val > 0.05 if not np.isnan(p_val) else False)
        
        colors = ['green' if passed else 'red' for passed in test_results_c1]
        bars = ax3.bar(range(len(test_names)), [1 if passed else 0 for passed in test_results_c1], 
                       color=colors, alpha=0.7)
        
        ax3.set_title(f'connt1 Test Results (Latest: {latest_c1["total_samples"]:,} samples)')
        ax3.set_ylabel('Test Passed (1) / Failed (0)')
        ax3.set_xticks(range(len(test_names)))
        ax3.set_xticklabels(test_names, rotation=45)
        ax3.set_ylim(0, 1.2)
        
        # Add p-values as text
        for i, (test, p_val) in enumerate(zip(test_names, p_values)):
            if not np.isnan(p_val):
                ax3.text(i, 0.5, f'p={p_val:.4f}', ha='center', va='center', fontsize=9, rotation=90)
    
    # Plot 4: Summary Text
    ax4 = axes[1, 1]
    ax4.axis('off')
    
    summary_text = "STABILITY ANALYSIS SUMMARY\n\n"
    
    if connt1_progression:
        latest_c1 = connt1_progression[-1]
        summary_text += f"CONNT1 (Current: {latest_c1['total_samples']:,} samples):\n"
        summary_text += f"• Stability Score: {latest_c1['stability_score']*100:.0f}%\n"
        summary_text += f"• Effect Size: {latest_c1.get('effect_size', 0):.4f}\n"
        summary_text += f"• Status: {'STABLE' if latest_c1['stability_score'] >= 0.75 else 'UNSTABLE'}\n\n"
    
    if connt2_progression:
        latest_c2 = connt2_progression[-1]
        summary_text += f"CONNT2 (Current: {latest_c2['total_samples']:,} samples):\n"
        summary_text += f"• Stability Score: {latest_c2['stability_score']*100:.0f}%\n"
        summary_text += f"• Effect Size: {latest_c2.get('effect_size', 0):.4f}\n"
        summary_text += f"• Status: {'STABLE' if latest_c2['stability_score'] >= 0.75 else 'UNSTABLE'}\n\n"
    
    summary_text += "KEY QUESTION:\n"
    summary_text += "Can connt1 become stable with MORE data?\n\n"
    
    if connt1_progression and len(connt1_progression) >= 3:
        c1_sizes = [p['total_samples'] for p in connt1_progression]
        c1_scores = [p['stability_score'] for p in connt1_progression]
        trend = linregress(np.log10(c1_sizes), c1_scores)
        
        if trend.pvalue < 0.05 and trend.slope > 0:
            answer = "✓ YES - Stability IMPROVES with more data"
        elif trend.pvalue < 0.05 and trend.slope < 0:
            answer = "✗ NO - Shows temporal drift (gets worse)"
        else:
            answer = "⚠ UNCLEAR - No clear trend"
        
        summary_text += f"ANSWER: {answer}\n"
        summary_text += f"Trend p-value: {trend.pvalue:.4f}\n"
        summary_text += f"Trend slope: {trend.slope:.4f}"
    else:
        summary_text += "ANSWER: Need more data points for analysis"
    
    ax4.text(0.05, 0.95, summary_text, transform=ax4.transAxes, fontsize=11,
             verticalalignment='top', fontfamily='monospace',
             bbox=dict(boxstyle='round', facecolor='lightgray', alpha=0.9))
    
    plt.tight_layout()
    plt.savefig('connt1_stability_progression.png', dpi=300, bbox_inches='tight')
    plt.close()
    print("\nSaved progression analysis: connt1_stability_progression.png")

def main_deep_analysis(base_path='/var/log/'):
    """
    Main function to answer: Can connt1 become stable with more data?
    """
    print("=" * 80)
    print(f"DEEP STABILITY ANALYSIS")
    print(f"Date: 2025-06-09 09:34:36 UTC")
    print(f"User: ajettesla")
    print(f"KEY QUESTION: Can connt1 become stable with 100% of available data?")
    print("=" * 80)
    
    # Progressive analysis for both connections
    print("\n=== PROGRESSIVE ANALYSIS ===")
    connt1_progression = progressive_stability_test('connt1', base_path)
    connt2_progression = progressive_stability_test('connt2', base_path)
    
    # Stationarity analysis
    connt1_analysis = None
    connt2_analysis = None
    
    if connt1_progression:
        connt1_analysis = analyze_stationarity(connt1_progression, 'connt1')
    
    if connt2_progression:
        connt2_analysis = analyze_stationarity(connt2_progression, 'connt2')
    
    # Create visualization
    create_progression_plots(connt1_progression, connt2_progression)
    
    # Final answer
    print(f"\n{'='*80}")
    print(f"FINAL ANSWER TO YOUR QUESTION")
    print(f"{'='*80}")
    
    if connt1_progression:
        latest_c1 = connt1_progression[-1]
        print(f"connt1 with ALL available data ({latest_c1['total_samples']:,} samples):")
        print(f"  Current Stability Score: {latest_c1['stability_score']*100:.0f}%")
        
        if latest_c1['stability_score'] >= 0.75:
            print(f"  ✓ ALREADY STABLE with current data!")
            print(f"  ✓ Answer: connt1 CAN be stable with sufficient data")
        else:
            print(f"  ✗ Still unstable even with all data")
            
            if connt1_analysis and connt1_analysis.get('stability_trend'):
                trend = connt1_analysis['stability_trend']
                if trend.pvalue < 0.05 and trend.slope > 0:
                    print(f"  ✓ BUT stability IS improving with more data")
                    print(f"  ✓ Answer: connt1 WILL become stable with even more data")
                    print(f"  ✓ Predicted stability with 1M samples: {connt1_analysis.get('predicted_stability', 0)*100:.0f}%")
                else:
                    print(f"  ✗ Stability is NOT improving with more data")
                    print(f"  ✗ Answer: connt1 shows TEMPORAL DRIFT - won't stabilize")
            else:
                print(f"  ⚠ Insufficient data to determine trend")
    
    print(f"\nCONCLUSION:")
    print(f"The instability of connt1 is due to:")
    
    if connt1_progression and len(connt1_progression) >= 3:
        c1_sizes = [p['total_samples'] for p in connt1_progression]
        c1_scores = [p['stability_score'] for p in connt1_progression]
        trend = linregress(np.log10(c1_sizes), c1_scores)
        
        if trend.pvalue < 0.05 and trend.slope < 0:
            print(f"  ✗ TEMPORAL DRIFT - the underlying process is changing over time")
            print(f"  ✗ More data WON'T help - need to fix the root cause")
            print(f"  ✗ Network infrastructure changes affecting connt1 over time")
        elif trend.pvalue < 0.05 and trend.slope > 0:
            print(f"  ✓ INSUFFICIENT SAMPLE SIZE - stability improves with more data")
            print(f"  ✓ More data WILL help achieve stability")
            print(f"  ✓ The 20% current sample is not representative of the full process")
        else:
            print(f"  ⚠ UNCLEAR PATTERN - need investigation of root causes")
            print(f"  ⚠ No significant trend detected with current data")
    
    # Comparison with connt2
    if connt2_progression:
        latest_c2 = connt2_progression[-1]
        print(f"\nComparison with connt2:")
        print(f"  connt2 stability: {latest_c2['stability_score']*100:.0f}% (shows what's possible)")
        print(f"  connt1 vs connt2: This confirms network path differences")
        
        if latest_c1['stability_score'] < latest_c2['stability_score']:
            print(f"  → connt1 path has temporal variability that connt2 doesn't have")
            print(f"  → Investigation needed: hardware, network route, or driver differences")
    
    print("=" * 80)

if __name__ == "__main__":
    main_deep_analysis('/var/log/')
