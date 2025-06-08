import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from scipy import stats

print("Starting accurate histogram scaled by actual timestamp range...")

# Load CSV file
filename = 'test02200_processed_data.csv'
print(f"Loading CSV file: {filename}")
df = pd.read_csv(filename)

print("Converting 'timediff' from nanoseconds to milliseconds...")
timediff_ms = df['timediff'] / 1e6  # Convert from ns to ms

# Filter out extreme values using IQR method
print("Filtering out extreme values using IQR method...")
Q1 = timediff_ms.quantile(0.25)
Q3 = timediff_ms.quantile(0.75)
IQR = Q3 - Q1
lower_bound = Q1 - 1.5 * IQR
upper_bound = Q3 + 1.5 * IQR

filtered = timediff_ms[(timediff_ms >= lower_bound) & (timediff_ms <= upper_bound)]
print(f"Data points after filtering: {len(filtered)} (original: {len(timediff_ms)})")

# Descriptive statistics
mean_val = filtered.mean()
median_val = filtered.median()
std_val = filtered.std()

# Confidence intervals
confidence_levels = [97, 95, 90, 75, 60, 50, 25]
ci_bounds = {}

for level in confidence_levels:
    ci = stats.norm.interval(level / 100, loc=mean_val, scale=std_val / np.sqrt(len(filtered)))
    ci_bounds[level] = ci

# Histogram setup
min_val = filtered.min()
max_val = filtered.max()
w = 3.49 * std_val * len(filtered) ** (-1/3)
bins = np.arange(min_val + w / 2, max_val, w)
freq, bin_edges = np.histogram(filtered, bins=bins)
density = freq / (len(filtered) * w)
bin_centers = (bin_edges[:-1] + bin_edges[1:]) / 2

# Plot
plt.figure(figsize=(14, 7))
plt.plot(bin_centers, density, 'k-', linewidth=2, label='Density')
plt.title("Timediff Distribution (ms) with Confidence Intervals & Std Dev", fontsize=16)
plt.xlabel("Timediff (ms)", fontsize=14)
plt.ylabel("Density", fontsize=14)
plt.grid(True, linestyle='--', alpha=0.6)

# Plot mean line
plt.axvline(x=mean_val, color='blue', linestyle='-', linewidth=2)
plt.text(mean_val, max(density)*0.98, 'Mean', color='blue', rotation=90,
         va='top', ha='center', fontsize=12, fontweight='bold')

# Plot std dev lines (±1σ, ±2σ)
for i, offset in enumerate([1, 2], start=1):
    plt.axvline(x=mean_val + offset * std_val, color='orange', linestyle='--', linewidth=1.8)
    plt.axvline(x=mean_val - offset * std_val, color='orange', linestyle='--', linewidth=1.8)
    plt.text(mean_val + offset * std_val, max(density)*(0.85 - i*0.05), f'+{i}σ',
             color='orange', rotation=90, fontsize=11, ha='left', va='top', fontweight='bold')
    plt.text(mean_val - offset * std_val, max(density)*(0.85 - i*0.05), f'-{i}σ',
             color='orange', rotation=90, fontsize=11, ha='right', va='top', fontweight='bold')

# Prepare stats summary text with CIs
stats_lines = [
    f"Mean: {mean_val:.3f} ms",
    f"Median: {median_val:.3f} ms",
    f"Std Dev: {std_val:.3f} ms",
    ""
]
for level in confidence_levels:
    ci = ci_bounds[level]
    stats_lines.append(f"{level}% CI: [{ci[0]:.3f}, {ci[1]:.3f}]")

# Add stats box (top right)
plt.gca().text(
    0.985, 0.98,
    '\n'.join(stats_lines),
    transform=plt.gca().transAxes,
    fontsize=12,
    va='top', ha='right',
    bbox=dict(facecolor='white', alpha=0.9, edgecolor='black')
)

plt.tight_layout()

# Save plot
output_file = './timediff_histogram_with_ci_summary_box.png'
plt.savefig(output_file)
plt.close()
print(f"Saved plot with right-aligned CI summary to: {output_file}")
