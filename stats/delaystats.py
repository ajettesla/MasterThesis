#!/usr/bin/env python3
import os
import glob
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import argparse
import re
from datetime import datetime
from math import sqrt
import warnings

try:
    from scipy import stats
    from sklearn.preprocessing import PowerTransformer, QuantileTransformer
except ImportError:
    print("Required packages missing. Please install with: pip install scipy scikit-learn pandas matplotlib")
    exit(1)

def log_message(message, level="INFO"):
    """Print message with timestamp and level."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}")

def get_file_number(filename):
    """Extract the number from a filename like '123_ca.csv'"""
    match = re.search(r'(\d+)_ca\.csv', filename)
    if match:
        return int(match.group(1))
    return None

def trim_outliers(data, trim_percentile=95, sample_size=200000):
    """Trims the upper outliers from the first and last N samples of the data."""
    if data.size == 0: return data
    if data.size <= sample_size * 2:
        percentile_value = np.percentile(data, trim_percentile)
        return data[data <= percentile_value]
    
    first_chunk, middle_chunk, last_chunk = data[:sample_size], data[sample_size:-sample_size], data[-sample_size:]
    percentile_first = np.percentile(first_chunk, trim_percentile)
    percentile_last = np.percentile(last_chunk, trim_percentile)
    return np.concatenate([first_chunk[first_chunk <= percentile_first], middle_chunk, last_chunk[last_chunk <= percentile_last]])

def get_efficient_percentile_ci(data, ci=95):
    """
    Calculate percentile confidence interval directly from the data without sorting the entire dataset.
    Uses NumPy's efficient percentile computation method which is optimized for large arrays.
    """
    if data.size < 30:
        return np.nan, np.nan
        
    lower_percentile = (100 - ci) / 2
    upper_percentile = 100 - lower_percentile
    
    # NumPy's percentile uses an efficient algorithm without requiring a full sort
    log_message(f"Efficiently computing {lower_percentile}th and {upper_percentile}th percentiles on {data.size:,} data points...", "DEBUG")
    ci_lower = np.percentile(data, lower_percentile, method='linear')
    ci_upper = np.percentile(data, upper_percentile, method='linear')
    
    return ci_lower, ci_upper

def evaluate_normality(data, test_method="multiple"):
    """
    Evaluate normality using multiple tests for better reliability.
    
    Parameters:
    - data: The data to test
    - test_method: One of "shapiro", "anderson", "d'agostino", "multiple"
    
    Returns:
    - Dict with test results
    """
    result = {
        "normal": False,
        "p_value": 0.0,
        "skewness": 0.0,
        "kurtosis": 0.0,
        "tests": {}
    }
    
    # Skip if not enough data
    if len(data) < 8:
        return result
    
    # Calculate skewness and kurtosis regardless of test
    result["skewness"] = stats.skew(data)
    result["kurtosis"] = stats.kurtosis(data)
    
    # For very large datasets, sample to keep tests manageable
    test_data = data
    if len(data) > 5000:
        test_data = np.random.choice(data, size=5000, replace=False)
    
    # Shapiro-Wilk test
    if test_method in ["shapiro", "multiple"]:
        try:
            shapiro_stat, shapiro_p = stats.shapiro(test_data)
            result["tests"]["shapiro"] = {
                "statistic": shapiro_stat,
                "p_value": shapiro_p,
                "normal": shapiro_p > 0.05
            }
        except Exception as e:
            result["tests"]["shapiro"] = {"error": str(e)}
    
    # Anderson-Darling test
    if test_method in ["anderson", "multiple"]:
        try:
            anderson_result = stats.anderson(test_data, dist='norm')
            # Anderson-Darling doesn't return a p-value directly, but critical values
            # We'll compare the test statistic to the critical value at 5%
            anderson_stat = anderson_result.statistic
            anderson_critical = anderson_result.critical_values[2]  # 5% significance level
            anderson_normal = anderson_stat < anderson_critical
            result["tests"]["anderson"] = {
                "statistic": anderson_stat,
                "critical_5pct": anderson_critical,
                "normal": anderson_normal
            }
        except Exception as e:
            result["tests"]["anderson"] = {"error": str(e)}
    
    # D'Agostino's K-squared test
    if test_method in ["d'agostino", "multiple"]:
        try:
            dagostino_stat, dagostino_p = stats.normaltest(test_data)
            result["tests"]["dagostino"] = {
                "statistic": dagostino_stat,
                "p_value": dagostino_p,
                "normal": dagostino_p > 0.05
            }
        except Exception as e:
            result["tests"]["dagostino"] = {"error": str(e)}
    
    # Determine overall normality
    if test_method == "multiple":
        # Consider data normal if at least 2 tests and reasonable skewness/kurtosis confirm it
        normality_votes = sum([
            result["tests"].get("shapiro", {}).get("normal", False),
            result["tests"].get("anderson", {}).get("normal", False),
            result["tests"].get("dagostino", {}).get("normal", False),
            abs(result["skewness"]) < 0.5,
            abs(result["kurtosis"]) < 0.5
        ])
        
        # Need at least 2 test votes or 1 test vote plus good skewness/kurtosis
        result["normal"] = normality_votes >= 3
        
        # For p-value, use D'Agostino (best for large samples) or Shapiro as fallback
        if "dagostino" in result["tests"] and "p_value" in result["tests"]["dagostino"]:
            result["p_value"] = result["tests"]["dagostino"]["p_value"]
        elif "shapiro" in result["tests"] and "p_value" in result["tests"]["shapiro"]:
            result["p_value"] = result["tests"]["shapiro"]["p_value"]
    else:
        # Use the single test's result
        if test_method == "shapiro" and "shapiro" in result["tests"]:
            result["normal"] = result["tests"]["shapiro"].get("normal", False)
            result["p_value"] = result["tests"]["shapiro"].get("p_value", 0.0)
        elif test_method == "anderson" and "anderson" in result["tests"]:
            result["normal"] = result["tests"]["anderson"].get("normal", False)
            # No direct p-value for Anderson-Darling
        elif test_method == "d'agostino" and "dagostino" in result["tests"]:
            result["normal"] = result["tests"]["dagostino"].get("normal", False)
            result["p_value"] = result["tests"]["dagostino"].get("p_value", 0.0)
    
    return result

def stratified_sample(data, n_samples=500_000, n_strata=10):
    """
    Take a stratified sample from data to better represent the distribution.
    
    Parameters:
    - data: The dataset to sample from
    - n_samples: Target number of samples
    - n_strata: Number of strata (quantile bins) to use
    
    Returns:
    - Stratified sample of size approximately n_samples
    """
    if len(data) <= n_samples:
        return data
    
    # Determine quantile breakpoints
    quantiles = np.linspace(0, 1, n_strata+1)
    breakpoints = np.quantile(data, quantiles)
    
    # Allocate samples per stratum proportional to original data
    samples_per_stratum = []
    strata_indices = []
    
    for i in range(n_strata):
        stratum_mask = (data >= breakpoints[i]) & (data <= breakpoints[i+1])
        stratum_indices = np.where(stratum_mask)[0]
        stratum_size = len(stratum_indices)
        
        # Calculate proportional sample size
        stratum_samples = int(n_samples * (stratum_size / len(data)))
        
        # Ensure minimum representation
        if stratum_size > 0 and stratum_samples == 0:
            stratum_samples = 1
            
        samples_per_stratum.append((stratum_indices, stratum_samples))
    
    # Adjust for rounding errors to hit target sample size
    total_allocated = sum(s[1] for s in samples_per_stratum)
    remainder = n_samples - total_allocated
    
    if remainder > 0:
        # Add remainder to largest strata
        strata_sizes = [(i, s[1]) for i, s in enumerate(samples_per_stratum)]
        sorted_strata = sorted(strata_sizes, key=lambda x: x[1], reverse=True)
        
        for i in range(min(remainder, len(sorted_strata))):
            samples_per_stratum[sorted_strata[i][0]] = (
                samples_per_stratum[sorted_strata[i][0]][0], 
                samples_per_stratum[sorted_strata[i][0]][1] + 1
            )
    
    # Take samples from each stratum
    stratified_samples = []
    for indices, n in samples_per_stratum:
        if len(indices) > 0 and n > 0:
            # If we need more samples than available, sample with replacement
            if n > len(indices):
                stratum_samples = np.random.choice(data[indices], size=n, replace=True)
            else:
                stratum_samples = np.random.choice(data[indices], size=n, replace=False)
            stratified_samples.append(stratum_samples)
    
    # Combine all strata samples
    return np.concatenate(stratified_samples)

def auto_find_best_transform(data, sample_size=500000, stratified=True):
    """
    Automatically find the best transformation using multiple methods.
    Uses a large sample size (500,000 points) for more accurate transformation selection.
    
    Parameters:
    - data: The dataset to transform
    - sample_size: Maximum size of sample to use for transformation analysis
    - stratified: Whether to use stratified sampling (recommended for skewed data)
    
    Returns:
    - best_transform: The best transformer object
    - transform_name: Name/description of the transform
    - normality_info: Result of normality tests
    - report: Detailed text report of transformation analysis
    """
    if data.size <= 0:
        return None, "No data", {"p_value": 0, "normal": False}, "No data to analyze"
    
    # Take a sample if data is too large
    if data.size > sample_size:
        log_message(f"Taking a {sample_size:,} point {'stratified ' if stratified else ''}sample for transformation optimization", "DEBUG")
        if stratified:
            sample_data = stratified_sample(data, n_samples=sample_size)
        else:
            sample_data = np.random.choice(data, size=sample_size, replace=False)
    else:
        sample_data = data.copy()
    
    # Make sure data is valid for transformations
    positive_sample = sample_data[sample_data > 0]  # For log and BoxCox
    if len(positive_sample) < 100:  # Need enough data for meaningful tests
        return None, "Insufficient positive data points", {"p_value": 0, "normal": False}, "Not enough positive data points"
    
    transformers = []
    
    # 1. No transformation (baseline)
    transformers.append({
        "name": "No Transform",
        "transformer": None,
        "data": sample_data
    })
    
    # 2. Log transform
    try:
        log_data = np.log(positive_sample)
        transformers.append({
            "name": "Log",
            "transformer": "log",
            "data": log_data
        })
    except Exception as e:
        log_message(f"Log transform failed: {e}", "DEBUG")
    
    # 3. Square Root transform
    try:
        sqrt_data = np.sqrt(positive_sample)
        transformers.append({
            "name": "Square Root",
            "transformer": "sqrt",
            "data": sqrt_data
        })
    except Exception as e:
        log_message(f"Square root transform failed: {e}", "DEBUG")
    
    # 4. Box-Cox transform
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            bc_transformer = PowerTransformer(method='box-cox')
            bc_data = bc_transformer.fit_transform(positive_sample.reshape(-1, 1)).flatten()
            transformers.append({
                "name": f"Box-Cox (λ={bc_transformer.lambdas_[0]:.4f})",
                "transformer": bc_transformer,
                "data": bc_data
            })
    except Exception as e:
        log_message(f"Box-Cox transform failed: {e}", "DEBUG")
    
    # 5. Yeo-Johnson transform
    try:
        yj_transformer = PowerTransformer(method='yeo-johnson')
        yj_data = yj_transformer.fit_transform(sample_data.reshape(-1, 1)).flatten()
        transformers.append({
            "name": f"Yeo-Johnson (λ={yj_transformer.lambdas_[0]:.4f})",
            "transformer": yj_transformer,
            "data": yj_data
        })
    except Exception as e:
        log_message(f"Yeo-Johnson transform failed: {e}", "DEBUG")
    
    # 6. Quantile transform (Gaussian output)
    try:
        qt_transformer = QuantileTransformer(output_distribution='normal')
        qt_data = qt_transformer.fit_transform(sample_data.reshape(-1, 1)).flatten()
        transformers.append({
            "name": "Quantile (Gaussian)",
            "transformer": qt_transformer,
            "data": qt_data
        })
    except Exception as e:
        log_message(f"Quantile transform failed: {e}", "DEBUG")

    # Test normality of each transformation using multiple tests for reliability
    best_score = -1
    best_transformer = None
    best_name = "No suitable transform found"
    
    for t in transformers:
        if "data" not in t or len(t["data"]) < 8:  # Need at least 8 points for normality tests
            continue
        
        # Use multiple normality tests for more reliable assessment
        normality_result = evaluate_normality(t["data"], test_method="multiple")
        t["normality"] = normality_result
        
        # Calculate a more balanced normality score that doesn't over-penalize for large sample sizes
        # and puts appropriate weight on skewness and kurtosis
        p_value = normality_result.get("p_value", 0)
        skewness = normality_result.get("skewness", 99)
        kurtosis = normality_result.get("kurtosis", 99)
        
        # More sophisticated scoring based on practical normality criteria
        # This scoring system is less sensitive to sample size effects
        skewness_score = 1 / (1 + abs(skewness))
        kurtosis_score = 1 / (1 + abs(kurtosis - 3)/2)  # Normal kurtosis is 3
        
        # Use a blend of test results and distribution shape metrics
        anderson_normal = normality_result.get("tests", {}).get("anderson", {}).get("normal", False)
        dagostino_p = normality_result.get("tests", {}).get("dagostino", {}).get("p_value", 0)
        
        # Calculate the composite score - weighted to emphasize shape over p-values
        normality_score = 0.3 * min(p_value * 20, 1) + 0.35 * skewness_score + 0.35 * kurtosis_score
        
        # Bonus for passing multiple tests
        if anderson_normal:
            normality_score += 0.1
        if dagostino_p > 0.01:
            normality_score += 0.1
            
        # Cap at 1.0
        normality_score = min(normality_score, 1.0)
        
        t["normality"]["score"] = normality_score
        
        if normality_score > best_score:
            best_score = normality_score
            best_transformer = t["transformer"]
            best_name = t["name"]
    
    # Generate a summary report of all transformations
    report = "--- Transformation Analysis with Multiple Normality Tests ---\n"
    for t in transformers:
        if "normality" not in t:
            continue
            
        if "error" in t.get("normality", {}):
            report += f"{t['name']}: Failed - {t['normality']['error']}\n"
        else:
            normality = t["normality"]
            normal_status = "NORMAL" if normality.get("normal", False) else "NOT NORMAL"
            score = normality.get("score", 0)
            skew = normality.get("skewness", 0)
            kurt = normality.get("kurtosis", 0)
            
            # Get individual test results
            tests = normality.get("tests", {})
            shapiro_p = tests.get("shapiro", {}).get("p_value", None)
            anderson_normal = tests.get("anderson", {}).get("normal", None)
            dagostino_p = tests.get("dagostino", {}).get("p_value", None)
            
            test_results = []
            if shapiro_p is not None:
                test_results.append(f"Shapiro-Wilk: p={shapiro_p:.4f}")
            if anderson_normal is not None:
                test_results.append(f"Anderson-Darling: {'normal' if anderson_normal else 'not normal'}")
            if dagostino_p is not None:
                test_results.append(f"D'Agostino: p={dagostino_p:.4f}")
                
            tests_str = ", ".join(test_results)
            
            report += (f"{t['name']}: {normal_status} (skew={skew:.2f}, kurt={kurt:.2f}, "
                     f"score={score:.4f}, {tests_str})\n")
    
    best_transformer_info = next((t for t in transformers if t["name"] == best_name), None)
    
    return best_transformer, best_name, best_transformer_info.get("normality", {"normal": False}) if best_transformer_info else {"normal": False}, report

def transform_data(data, transformer):
    """Apply a transformer to data."""
    if transformer is None:
        return data
    
    if transformer == "log":
        return np.log(data[data > 0])
    elif transformer == "sqrt":
        return np.sqrt(data[data > 0])
    else:
        # Must be a sklearn transformer
        if hasattr(transformer, 'transform'):
            return transformer.transform(data.reshape(-1, 1)).flatten()
        else:
            return data

def inverse_transform(data, transformer):
    """Apply inverse transformation to data."""
    if transformer is None:
        return data
    
    if transformer == "log":
        return np.exp(data)
    elif transformer == "sqrt":
        return data ** 2
    else:
        # Must be a sklearn transformer
        if hasattr(transformer, 'inverse_transform'):
            return transformer.inverse_transform(data.reshape(-1, 1)).flatten()
        else:
            return data

def get_bootstrap_ci(data, stat_func=np.median, ci=95, n_resamples=1000, subsample_size=750_000, use_stratified=True):
    """
    Calculate bootstrap CI using memory-safe manual loop with subsampling.
    Uses stratified sampling for better representation of skewed data.
    
    Parameters:
    - data: The dataset to bootstrap
    - stat_func: The statistic function (np.median, np.mean, etc.)
    - ci: Confidence level (e.g., 95 for 95% CI)
    - n_resamples: Number of bootstrap resamples
    - subsample_size: Maximum size of subsample to use
    - use_stratified: Whether to use stratified sampling (recommended for skewed data)
    """
    if data.size < 30:
        return np.nan, np.nan
    
    # Apply subsampling if needed
    data_to_sample = data
    if data.size > subsample_size:
        if use_stratified:
            log_message(f"Dataset is large ({data.size:,} points). Using a stratified subsample of ~{subsample_size:,} for bootstrapping.", "DEBUG")
            data_to_sample = stratified_sample(data, n_samples=subsample_size)
        else:
            log_message(f"Dataset is large ({data.size:,} points). Using a random subsample of {subsample_size:,} for bootstrapping.", "DEBUG")
            data_to_sample = np.random.choice(data, size=subsample_size, replace=False)

    log_message(f"Calculating bootstrap CI of {stat_func.__name__} using manual, memory-safe loop on {data_to_sample.size:,} data points...", "DEBUG")
    
    bootstrap_stats = np.empty(n_resamples)
    for i in range(n_resamples):
        resample = np.random.choice(data_to_sample, size=len(data_to_sample), replace=True)
        bootstrap_stats[i] = stat_func(resample)

    lower_percentile = (100 - ci) / 2
    upper_percentile = 100 - lower_percentile
    ci_lower = np.percentile(bootstrap_stats, lower_percentile)
    ci_upper = np.percentile(bootstrap_stats, upper_percentile)
    
    return ci_lower, ci_upper

def get_transformed_percentile_ci(data, transformer, ci=95, subsample_size=750_000):
    """
    Calculate CI for transformed data by transforming, finding percentiles, then back-transforming.
    This avoids the symmetry assumption of parametric CIs in the transformed space.
    
    Parameters:
    - data: The dataset to analyze
    - transformer: The transformer to apply
    - ci: Confidence level (e.g., 95 for 95% CI)
    - subsample_size: Maximum size of subsample to use
    """
    if transformer is None or data.size < 30:
        return None, None
    
    try:
        # Apply transformation to appropriate data
        positive_data = data[data > 0] if transformer in ["log", "sqrt"] else data
        
        if len(positive_data) < 30:
            return None, None
        
        # Use subsampling for very large datasets
        if len(positive_data) > subsample_size:
            log_message(f"Dataset is large ({len(positive_data):,} points). Using stratified subsample for transformed CI.", "DEBUG")
            sample_data = stratified_sample(positive_data, n_samples=subsample_size)
        else:
            sample_data = positive_data
            
        # Transform the data
        transformed_data = transform_data(sample_data, transformer)
        
        # Calculate percentiles in transformed space
        lower_percentile = (100 - ci) / 2
        upper_percentile = 100 - lower_percentile
        
        ci_lower_trans = np.percentile(transformed_data, lower_percentile)
        ci_upper_trans = np.percentile(transformed_data, upper_percentile)
        
        # Back-transform to original scale
        ci_lower = inverse_transform(np.array([ci_lower_trans]), transformer)[0]
        ci_upper = inverse_transform(np.array([ci_upper_trans]), transformer)[0]
        
        return ci_lower, ci_upper
        
    except Exception as e:
        log_message(f"Error calculating transformed percentile CI: {e}", "DEBUG")
        return None, None

def get_transformed_parametric_ci(data, transformer, ci=95, subsample_size=500_000):
    """
    Calculate parametric CI using transformed data (if it's normal).
    For comparison with percentile-based method.
    """
    if transformer is None:
        return None, None
    
    try:
        # Apply transformation 
        positive_data = data[data > 0] if transformer in ["log", "sqrt"] else data
        
        if len(positive_data) < 30:
            return None, None
        
        # Use subsampling for very large datasets to avoid memory issues
        if len(positive_data) > subsample_size:
            log_message(f"Dataset is large ({len(positive_data):,} points). Using stratified subsample for transformed parametric CI.", "DEBUG")
            positive_data = stratified_sample(positive_data, n_samples=subsample_size)
            
        transformed_data = transform_data(positive_data, transformer)
        
        # Calculate CI on transformed data
        mean = np.mean(transformed_data)
        std_dev = np.std(transformed_data, ddof=1)
        se = std_dev / np.sqrt(len(transformed_data))
        
        # For very large samples, don't use arbitrary minimum SE
        # Instead, use a statistically justified approach
        z_score = stats.norm.ppf((1 + ci/100) / 2)
        
        ci_lower_trans = mean - z_score * se
        ci_upper_trans = mean + z_score * se
        
        # Back-transform to original scale
        ci_lower = inverse_transform(np.array([ci_lower_trans]), transformer)[0]
        ci_upper = inverse_transform(np.array([ci_upper_trans]), transformer)[0]
        
        # Ensure bounds are different
        if abs(ci_lower - ci_upper) < 0.001:
            log_message("Transformed parametric CI bounds are too close. Using percentile method instead.", "DEBUG")
            return get_transformed_percentile_ci(data, transformer, ci, subsample_size)
        
        return ci_lower, ci_upper
    
    except Exception as e:
        log_message(f"Error calculating transformed parametric CI: {e}", "DEBUG")
        return None, None

def get_stats_text(data_ms):
    """Generates comprehensive stats with multiple confidence interval methods."""
    if data_ms.size < 30: return "Not enough data for stats"
    
    # Calculate percentile CI directly (most efficient for large datasets)
    percentile_ci_lower, percentile_ci_upper = get_efficient_percentile_ci(data_ms)
    
    # Bootstrap CIs with stratified sampling for better representation
    median_ci_lower, median_ci_upper = get_bootstrap_ci(data_ms, np.median, use_stratified=True)
    mean_ci_lower, mean_ci_upper = get_bootstrap_ci(data_ms, np.mean, use_stratified=True)
    
    # Auto-transformation analysis with enhanced normality testing
    transformer, transform_name, normality_info, transform_report = auto_find_best_transform(data_ms, stratified=True)
    
    # Get both percentile-based and parametric transformed CIs for comparison
    transform_pct_ci = get_transformed_percentile_ci(data_ms, transformer)
    transform_param_ci = get_transformed_parametric_ci(data_ms, transformer)
    
    # Basic statistics
    stats_dict = {
        "n": len(data_ms), 
        "Mean": np.mean(data_ms),
        "Median": np.median(data_ms),
        "Std Dev": np.std(data_ms), 
        "Min": np.min(data_ms), 
        "Max": np.max(data_ms),
        "Skewness": stats.skew(data_ms),
        "Kurtosis": stats.kurtosis(data_ms),
        "95% CI (Direct Percentile)": f"[{percentile_ci_lower:.3f}, {percentile_ci_upper:.3f}]",
        "95% CI (Bootstrap of Median)": f"[{median_ci_lower:.3f}, {median_ci_upper:.3f}]",
        "95% CI (Bootstrap of Mean)": f"[{mean_ci_lower:.3f}, {mean_ci_upper:.3f}]",
        "Best Transform": transform_name,
        "Transform Normal": "Yes" if normality_info.get("normal", False) else "No",
        "Transform Score": f"{normality_info.get('score', 0):.4f}"
    }
    
    # Add transformed CIs if available
    if transform_pct_ci[0] is not None and transform_pct_ci[1] is not None:
        stats_dict["95% CI (Transformed Percentile)"] = f"[{transform_pct_ci[0]:.3f}, {transform_pct_ci[1]:.3f}]"
    else:
        stats_dict["95% CI (Transformed Percentile)"] = "Not available"
        
    if transform_param_ci[0] is not None and transform_param_ci[1] is not None:
        stats_dict["95% CI (Transformed Parametric)"] = f"[{transform_param_ci[0]:.3f}, {transform_param_ci[1]:.3f}]"
    else:
        stats_dict["95% CI (Transformed Parametric)"] = "Not available"
    
    stats_text = (f"n = {stats_dict['n']:,}\n"
                 f"Mean: {stats_dict['Mean']:.3f} ms\n"
                 f"Median: {stats_dict['Median']:.3f} ms\n"
                 f"Std Dev: {stats_dict['Std Dev']:.3f} ms\n"
                 f"Skewness: {stats_dict['Skewness']:.3f}\n"
                 f"Kurtosis: {stats_dict['Kurtosis']:.3f}\n"
                 f"95% CI (Direct Percentile): {stats_dict['95% CI (Direct Percentile)']}\n"
                 f"95% CI (Bootstrap of Median): {stats_dict['95% CI (Bootstrap of Median)']}\n"
                 f"95% CI (Bootstrap of Mean): {stats_dict['95% CI (Bootstrap of Mean)']}\n"
                 f"Best Transform: {stats_dict['Best Transform']}\n"
                 f"Transform Normal: {stats_dict['Transform Normal']} (score: {stats_dict['Transform Score']})\n"
                 f"95% CI (Transformed Percentile): {stats_dict['95% CI (Transformed Percentile)']}\n"
                 f"95% CI (Transformed Parametric): {stats_dict['95% CI (Transformed Parametric)']}\n"
                 f"Min: {stats_dict['Min']:.3f} ms\n"
                 f"Max: {stats_dict['Max']:.3f} ms\n\n"
                 f"{transform_report}")
    
    return stats_text

def create_distribution_plots(data_ms, title, run_output_dir):
    """Creates multiple plots showing raw and transformed distributions."""
    if data_ms.size < 30: return []
    
    figs = []
    
    # 1. Log histogram of raw data
    fig1, ax1 = plt.subplots(figsize=(11.69, 8.27))
    stats_string = get_stats_text(data_ms)
    
    data_ms_positive = data_ms[data_ms > 0]
    if data_ms_positive.any():
        min_val, max_val = data_ms_positive.min(), data_ms_positive.max()
        log_min = np.log10(min_val) if min_val > 0 else 0
        log_max = np.log10(max_val) if max_val > min_val else log_min + 1
        bins = np.logspace(log_min, log_max, 100)
        
        ax1.hist(data_ms_positive, bins=bins, density=True, color='skyblue', edgecolor='black', alpha=0.7, label='PDF')
        ax1.set_xscale('log')
        ax1.set_xlabel('Delay (ms, log scale)')
        ax1.set_ylabel('Probability Density')
        ax1.set_title(f'{title} - Log Scale')
        ax1.legend()
        ax1.grid(True, which="both", linestyle=':')
        figs.append(fig1)
    
    # 2. Transformation plots
    # Get best transformer for visualization using stratified sample
    transformer, transform_name, _, _ = auto_find_best_transform(data_ms, stratified=True)
    if transformer is not None and transform_name != "No Transform":
        try:
            # Transform the data
            if transform_name.startswith("Box-Cox") or transform_name.startswith("Yeo-Johnson"):
                original = data_ms
                if transform_name.startswith("Box-Cox"):
                    original = data_ms[data_ms > 0]  # Box-Cox requires positive values
                
                # For visualization, use a stratified subsample if data is too large
                if len(original) > 1_000_000:
                    visual_sample = stratified_sample(original, n_samples=1_000_000)
                else:
                    visual_sample = original
                    
                transformed = transform_data(visual_sample, transformer)
                
                # Create Q-Q plot of transformed data
                fig2, ax2 = plt.subplots(figsize=(11.69, 8.27))
                stats.probplot(transformed, dist="norm", plot=ax2)
                ax2.set_title(f'Q-Q Plot of {transform_name} Transformed Data')
                ax2.grid(True)
                figs.append(fig2)
                
                # Create histogram of transformed data
                fig3, ax3 = plt.subplots(figsize=(11.69, 8.27))
                ax3.hist(transformed, bins=50, density=True, alpha=0.7, color='green')
                
                # Add normal distribution curve
                mu, sigma = np.mean(transformed), np.std(transformed)
                x = np.linspace(mu - 3*sigma, mu + 3*sigma, 100)
                ax3.plot(x, stats.norm.pdf(x, mu, sigma), 'r-', lw=2, 
                         label=f'Normal: μ={mu:.2f}, σ={sigma:.2f}')
                
                ax3.set_title(f'Histogram of {transform_name} Transformed Data')
                ax3.set_xlabel('Transformed Value')
                ax3.set_ylabel('Probability Density')
                ax3.legend()
                ax3.grid(True)
                figs.append(fig3)
                
                # Save transformation details to file
                with open(os.path.join(run_output_dir, "transformation_details.txt"), 'w') as f:
                    f.write(f"Transformation: {transform_name}\n\n")
                    f.write(f"Original Data Statistics:\n")
                    f.write(f"Mean: {np.mean(original):.4f}\n")
                    f.write(f"Median: {np.median(original):.4f}\n")
                    f.write(f"Std Dev: {np.std(original):.4f}\n")
                    f.write(f"Skewness: {stats.skew(original):.4f}\n")
                    f.write(f"Kurtosis: {stats.kurtosis(original):.4f}\n\n")
                    
                    f.write(f"Transformed Data Statistics:\n")
                    f.write(f"Mean: {np.mean(transformed):.4f}\n")
                    f.write(f"Median: {np.median(transformed):.4f}\n")
                    f.write(f"Std Dev: {np.std(transformed):.4f}\n")
                    f.write(f"Skewness: {stats.skew(transformed):.4f}\n")
                    f.write(f"Kurtosis: {stats.kurtosis(transformed):.4f}\n\n")
                    
                    # Get comprehensive normality assessment
                    normality = evaluate_normality(transformed, test_method="multiple")
                    f.write(f"Normality Assessment of Transformed Data:\n")
                    
                    for test_name, test_result in normality.get("tests", {}).items():
                        if "error" in test_result:
                            f.write(f"- {test_name}: Error - {test_result['error']}\n")
                        elif "p_value" in test_result:
                            f.write(f"- {test_name}: p-value = {test_result['p_value']:.6f} "
                                   f"({'normal' if test_result.get('normal', False) else 'not normal'})\n")
                        elif "normal" in test_result:
                            f.write(f"- {test_name}: {'normal' if test_result['normal'] else 'not normal'}\n")
                    
                    f.write(f"- Skewness: {normality.get('skewness', 0):.4f} "
                           f"({'good' if abs(normality.get('skewness', 0)) < 0.5 else 'high'})\n")
                    f.write(f"- Kurtosis: {normality.get('kurtosis', 0):.4f} "
                           f"({'good' if abs(normality.get('kurtosis', 0)) < 0.5 else 'high'})\n")
                    f.write(f"- Overall: {'Normal' if normality.get('normal', False) else 'Not Normal'}\n")
        
        except Exception as e:
            log_message(f"Error creating transformation plots: {e}", "ERROR")
    
    # Add stats text to the first plot
    if figs:
        ax1 = figs[0].axes[0]
        text_box = ax1.text(0.5, 0.95, stats_string, transform=ax1.transAxes, fontsize=10,
                        verticalalignment='top', horizontalalignment='center', 
                        bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
        
        # Adjust text box to fit
        renderer = figs[0].canvas.get_renderer()
        bbox = text_box.get_window_extent(renderer=renderer)
        bbox_inches = bbox.transformed(figs[0].dpi_scale_trans.inverted())
        
        # If text box is too big, save full stats to a separate file
        if bbox_inches.height > 0.4:  # If text takes more than 40% of plot height
            with open(os.path.join(run_output_dir, "full_statistics.txt"), 'w') as f:
                f.write(stats_string)
            
            # Use a shorter version in the plot
            short_stats = (f"n = {len(data_ms):,}\n"
                          f"Mean: {np.mean(data_ms):.3f} ms\n"
                          f"Median: {np.median(data_ms):.3f} ms\n"
                          f"Best Transform: {transform_name}\n"
                          f"See full_statistics.txt for complete details")
            text_box.set_text(short_stats)
    
    return figs

def run_stability_analysis(all_delays_list, run_output_dir, use_transformed_stability=True):
    """
    Perform stability analysis on raw data using SEM.
    Can also analyze stability in transformed space if a good transformation is found.
    
    Parameters:
    - all_delays_list: List of delay data arrays
    - run_output_dir: Directory to save output files
    - use_transformed_stability: Whether to also analyze stability in transformed space
    """
    os.makedirs(run_output_dir, exist_ok=True)
    num_files = len(all_delays_list)
    MIN_FILES_FOR_STABILITY_CHECK = 5
    if num_files < MIN_FILES_FOR_STABILITY_CHECK:
        return None, "Not enough data"

    log_message("Running stability analysis using SEM of RAW data...", "DEBUG")
    
    # First get combined data to find best transformation
    all_data = np.concatenate([d for d in all_delays_list if d.size > 0])
    transformer, transform_name, normality_info, _ = auto_find_best_transform(all_data, stratified=True)
    
    sem_history = []
    transformed_sem_history = [] if use_transformed_stability and transformer is not None else None
    
    for i in range(2, num_files + 1):
        cumulative_data = np.concatenate([d for d in all_delays_list[:i] if d.size > 0])
        if cumulative_data.size > 1:
            sem_history.append({'file_index': i, 'sem': stats.sem(cumulative_data)})
            
            # Also calculate SEM on transformed data if requested and transformation exists
            if transformed_sem_history is not None:
                # Apply transformation appropriate for the data type
                if transform_name.startswith("Box-Cox"):
                    # Box-Cox requires positive values
                    positive_data = cumulative_data[cumulative_data > 0]
                    if positive_data.size > 1:
                        transformed_data = transform_data(positive_data, transformer)
                        transformed_sem_history.append({'file_index': i, 'sem': stats.sem(transformed_data)})
                    else:
                        transformed_sem_history.append({'file_index': i, 'sem': np.nan})
                else:
                    # Other transformations can handle zeros or all values
                    transformed_data = transform_data(cumulative_data, transformer)
                    transformed_sem_history.append({'file_index': i, 'sem': stats.sem(transformed_data)})

    # Check stability on raw data first
    stability_point, stability_achieved, consecutive_stable_files = -1, False, 0
    STABILITY_THRESHOLD_RATIO, CONSECUTIVE_NEEDED = 0.05, 3
    if len(sem_history) > 1:
        for i in range(1, len(sem_history)):
            prev_sem, current_sem = sem_history[i-1]['sem'], sem_history[i]['sem']
            if prev_sem > 0 and abs(current_sem - prev_sem) / prev_sem < STABILITY_THRESHOLD_RATIO:
                consecutive_stable_files += 1
            else:
                consecutive_stable_files = 0
            if consecutive_stable_files >= CONSECUTIVE_NEEDED:
                stability_point, stability_achieved = sem_history[i]['file_index'], True
                break

    # Check stability on transformed data if we have it
    transformed_stability_point, transformed_stability_achieved = -1, False
    if transformed_sem_history is not None and len(transformed_sem_history) > 1:
        consecutive_stable_files = 0
        for i in range(1, len(transformed_sem_history)):
            prev_sem = transformed_sem_history[i-1]['sem']
            current_sem = transformed_sem_history[i-1]['sem']
            
            if np.isnan(prev_sem) or np.isnan(current_sem):
                continue
                
            if prev_sem > 0 and abs(current_sem - prev_sem) / prev_sem < STABILITY_THRESHOLD_RATIO:
                consecutive_stable_files += 1
            else:
                consecutive_stable_files = 0
            if consecutive_stable_files >= CONSECUTIVE_NEEDED:
                transformed_stability_point, transformed_stability_achieved = transformed_sem_history[i]['file_index'], True
                break

    # Create figure for raw data stability
    fig, ax = plt.subplots(figsize=(11.69, 8.27))
    if sem_history:
        indices, sems = [h['file_index'] for h in sem_history], [h['sem'] for h in sem_history]
        ax.plot(indices, sems, 'o-', color='purple', label='SEM of Raw Data')
        if stability_achieved: ax.axvline(x=stability_point, color='green', linestyle='--', label=f'Stability Point ({stability_point} files)')
        ax.set_xticks(range(2, num_files + 1))
    ax.set_xlabel('Number of Cumulative Files Processed'); ax.set_ylabel('SEM of Delay (ms)'); ax.set_title('SEM Stability Analysis on Raw Data')
    ax.legend(); ax.grid(True, which="both", linestyle=':')

    # Create figure for transformed data stability if available
    fig_trans = None
    if transformed_sem_history is not None and any(not np.isnan(h['sem']) for h in transformed_sem_history):
        fig_trans, ax_trans = plt.subplots(figsize=(11.69, 8.27))
        indices = [h['file_index'] for h in transformed_sem_history]
        sems = [h['sem'] for h in transformed_sem_history]
        ax_trans.plot(indices, sems, 'o-', color='green', label=f'SEM of {transform_name} Transformed Data')
        if transformed_stability_achieved: 
            ax_trans.axvline(x=transformed_stability_point, color='blue', linestyle='--', 
                           label=f'Stability Point ({transformed_stability_point} files)')
        ax_trans.set_xticks(range(2, num_files + 1))
        ax_trans.set_xlabel('Number of Cumulative Files Processed')
        ax_trans.set_ylabel('SEM in Transformed Space')
        ax_trans.set_title(f'SEM Stability Analysis on {transform_name} Transformed Data')
        ax_trans.legend()
        ax_trans.grid(True, which="both", linestyle=':')

    # Determine final stability status - prefer raw if both are stable
    if stability_achieved:
        aggregation_point = stability_point
        final_status_message = "Stable (Raw Data)"
    elif transformed_stability_achieved:
        aggregation_point = transformed_stability_point
        final_status_message = f"Stable (in {transform_name} Transformed Space)"
    else:
        aggregation_point = num_files
        final_status_message = "Not Stable"
    
    summary_data = np.concatenate([d for d in all_delays_list[:aggregation_point] if d.size > 0])
    
    # Get detailed stats
    stats_text = get_stats_text(summary_data)
    
    # Save full report
    report_content = (f"--- Analysis Summary ---\n"
                      f"Analysis performed by ajetanroop on: 2025-07-13 18:37:20 UTC\n"
                      f"Methodology: Enhanced analysis with multiple normality tests, stratified sampling, "
                      f"and improved confidence intervals.\n"
                      f"Stability Status: {final_status_message}\n\n"
                      f"--- Statistics of {'Stable' if (stability_achieved or transformed_stability_achieved) else 'Full'} Dataset ---\n{stats_text}\n")
    
    summary_filepath = os.path.join(run_output_dir, "stability_summary.txt")
    with open(summary_filepath, 'w') as f: f.write(report_content)
    log_message(f"Analysis summary saved to '{summary_filepath}'", "SUCCESS")
    
    return [fig, fig_trans] if fig_trans else [fig], final_status_message

def main():
    parser = argparse.ArgumentParser(description='Generate enhanced statistical analysis with improved methods for skewed data.')
    parser.add_argument('folder', help='Folder containing CSV files')
    parser.add_argument('--output-dir', default='.', help='Base directory to save the results folder.')
    args = parser.parse_args()
    
    folder_basename = os.path.basename(os.path.normpath(args.folder))
    run_output_dir = os.path.join(args.output_dir, f"{folder_basename}_results_Enhanced")
    os.makedirs(run_output_dir, exist_ok=True)
    pdf_filepath = os.path.join(run_output_dir, f"{folder_basename}_report_Enhanced.pdf")

    all_delays_list = []
    files_to_process = sorted(glob.glob(os.path.join(args.folder, "*_ca.csv")), key=lambda f: get_file_number(os.path.basename(f)) or 0)
    
    for f in files_to_process:
        log_message(f"Processing file: {os.path.basename(f)}")
        try:
            data_ms = pd.read_csv(f, usecols=['time_diff_ns'])['time_diff_ns'].dropna().values / 1_000_000
            data_ms_positive = data_ms[data_ms >= 0]
            all_delays_list.append(trim_outliers(data_ms_positive))
        except Exception as e:
            log_message(f"Could not process file {f}: {e}", "ERROR")

    if not all_delays_list:
        log_message("No data processed. Exiting.", "ERROR")
        return

    with PdfPages(pdf_filepath) as pdf:
        stability_figs, _ = run_stability_analysis(all_delays_list, run_output_dir, use_transformed_stability=True)
        for fig in stability_figs:
            pdf.savefig(fig)
            plt.close(fig)

        all_delays_combined = np.concatenate([d for d in all_delays_list if d.size > 0])
        if all_delays_combined.size > 0:
            figs = create_distribution_plots(all_delays_combined, 'Delay Distribution', run_output_dir)
            for fig in figs:
                pdf.savefig(fig)
                plt.close(fig)

    log_message("Processing complete.", level="SUCCESS")

if __name__ == "__main__":
    main()
