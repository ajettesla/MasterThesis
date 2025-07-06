#!/bin/bash

# Function to print a header with date and user information (to file, not stdout)
print_header() {
    local current_date=$(date -u "+%Y-%m-%d %H:%M:%S")
    local current_user=$(whoami)
    {
        echo "============================================================"
        echo "Chrony Log Analysis Report"
        echo "============================================================"
        echo "Date and Time (UTC): $current_date"
        echo "User: $current_user"
        echo "============================================================"
        echo ""
    } >> "$1"
}

# Function to setup the chrony directory (silent operation)
setup_chrony_dir() {
    local id=$1
    local mode=$2
    local dir="/tmp/exp/$id/chrony"
    
    # Create directory if it doesn't exist
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir" > /dev/null 2>&1
    fi
    
    # Clean up any previous files in pre mode
    if [ "$mode" = "pre" ]; then
        rm -f "$dir"/* > /dev/null 2>&1
    fi
}

# Function to extract and analyze chrony tracking log data
analyze_chrony_data() {
    local mode=$1     # "pre" or "post"
    local id=$2       # unique ID for directory
    local start_timestamp=$3  # Only used in "post" mode
    
    # Setup chrony directory silently
    setup_chrony_dir "$id" "$mode"
    local chrony_dir="/tmp/exp/$id/chrony"
    
    local output_file="$chrony_dir/chrony_analysis_${mode}.txt"
    local log_file="/var/log/chrony/tracking.log"
    local sample_count_file="$chrony_dir/chrony_${mode}_sample_counts.txt"
    local temp_data_file="$chrony_dir/chrony_data_temp.txt"
    local timestamp_file="$chrony_dir/chrony_last_timestamp.txt"
    local stats_file="$chrony_dir/chrony_${mode}_stats.txt"
    local analysis_log="$chrony_dir/chrony_${mode}_analysis.log"
    
    # Start logging all detailed output to the analysis log
    print_header "$analysis_log"
    
    echo "Running ${mode} analysis..." # Line 1 of stdout
    
    # Log details to file instead of stdout
    {
        echo "Running ${mode}-experimentation analysis..."
        echo "Directory: $chrony_dir"
        echo "Log file: $log_file"
    } >> "$analysis_log"
    
    # For pre-experimentation: get last 50 data lines
    if [ "$mode" = "pre" ]; then
        # Get the last 50 non-header lines from the log file
        grep -v "=\|Date (UTC) Time" "$log_file" | tail -50 > "$temp_data_file"
        
        # Store the last timestamp for post-experimentation
        last_timestamp=$(tail -1 "$temp_data_file" | awk '{print $1 " " $2}')
        echo "$last_timestamp" > "$timestamp_file"
        echo "Timestamp captured: $last_timestamp" >> "$analysis_log"
        
    # For post-experimentation: get data from the stored timestamp onwards
    else
        if [ -z "$start_timestamp" ]; then
            echo "Error: No start timestamp found" # Line 2 of stdout on error
            echo "Error: No start timestamp provided for post-experimentation analysis" >> "$analysis_log"
            return 1
        fi
        
        # Convert timestamp to a format that can be used for comparison
        formatted_timestamp=$(date -d "$start_timestamp" +"%Y-%m-%d %H:%M:%S")
        echo "Analyzing data from $formatted_timestamp onwards" >> "$analysis_log"
        
        # Extract lines with timestamps after or equal to the start timestamp
        awk -v ts="$formatted_timestamp" '
            $1 " " $2 >= ts && !/=|Date \(UTC\) Time/ {print}
        ' "$log_file" > "$temp_data_file"
    fi
    
    # Count total samples and samples per IP
    total_samples=$(wc -l < "$temp_data_file")
    echo "Total samples for ${mode}-experimentation: $total_samples" > "$sample_count_file"
    
    # Count samples per IP
    awk '{print $3}' "$temp_data_file" | sort | uniq -c | while read count ip; do
        echo "IP $ip: $count samples" >> "$sample_count_file"
    done
    
    # Calculate time range of samples
    if [ "$total_samples" -gt 0 ]; then
        first_timestamp=$(head -1 "$temp_data_file" | awk '{print $1 " " $2}')
        last_timestamp=$(tail -1 "$temp_data_file" | awk '{print $1 " " $2}')
        
        # Calculate duration if both timestamps are available
        if [ -n "$first_timestamp" ] && [ -n "$last_timestamp" ]; then
            first_seconds=$(date -d "$first_timestamp" +%s)
            last_seconds=$(date -d "$last_timestamp" +%s)
            duration_seconds=$((last_seconds - first_seconds))
            
            # Convert seconds to a more readable format
            duration_formatted=$(date -u -d @"$duration_seconds" +"%H:%M:%S")
            echo "Time range: $first_timestamp to $last_timestamp (duration: $duration_formatted)" >> "$sample_count_file"
        fi
    fi
    
    # Process the extracted data for unique IPs and calculate averages, min, max
    awk '
    BEGIN {
        print "IP Address,Count,Avg_Freq_ppm,Avg_Skew_ppm,Avg_Offset,Avg_Root_delay,Avg_Root_disp,Avg_Max_error"
        
        # Initialize global min/max trackers for overall stats
        global_min_freq = 1e10; global_max_freq = -1e10;
        global_min_skew = 1e10; global_max_skew = -1e10;
        global_min_offset = 1e10; global_max_offset = -1e10;
        global_min_root_delay = 1e10; global_max_root_delay = -1e10;
        global_min_root_disp = 1e10; global_max_root_disp = -1e10;
        global_min_max_error = 1e10; global_max_max_error = -1e10;
        
        global_sum_freq = 0; global_sum_skew = 0; global_sum_offset = 0;
        global_sum_root_delay = 0; global_sum_root_disp = 0; global_sum_max_error = 0;
        global_count = 0;
    }
    {
        ip = $3;
        freq = $5;
        skew = $7;
        offset = $8;
        root_delay = $13;
        root_disp = $15;
        max_error = $17;
        
        count[ip]++;
        global_count++;
        
        # First sample for this IP, initialize min/max
        if (count[ip] == 1) {
            min_freq[ip] = max_freq[ip] = freq;
            min_skew[ip] = max_skew[ip] = skew;
            min_offset[ip] = max_offset[ip] = offset;
            min_root_delay[ip] = max_root_delay[ip] = root_delay;
            min_root_disp[ip] = max_root_disp[ip] = root_disp;
            min_max_error[ip] = max_max_error[ip] = max_error;
        } else {
            # Update min/max for this IP
            if (freq < min_freq[ip]) min_freq[ip] = freq;
            if (freq > max_freq[ip]) max_freq[ip] = freq;
            
            if (skew < min_skew[ip]) min_skew[ip] = skew;
            if (skew > max_skew[ip]) max_skew[ip] = skew;
            
            if (offset < min_offset[ip]) min_offset[ip] = offset;
            if (offset > max_offset[ip]) max_offset[ip] = offset;
            
            if (root_delay < min_root_delay[ip]) min_root_delay[ip] = root_delay;
            if (root_delay > max_root_delay[ip]) max_root_delay[ip] = root_delay;
            
            if (root_disp < min_root_disp[ip]) min_root_disp[ip] = root_disp;
            if (root_disp > max_root_disp[ip]) max_root_disp[ip] = root_disp;
            
            if (max_error < min_max_error[ip]) min_max_error[ip] = max_error;
            if (max_error > max_max_error[ip]) max_max_error[ip] = max_error;
        }
        
        # Update global min/max
        if (freq < global_min_freq) global_min_freq = freq;
        if (freq > global_max_freq) global_max_freq = freq;
        
        if (skew < global_min_skew) global_min_skew = skew;
        if (skew > global_max_skew) global_max_skew = skew;
        
        if (offset < global_min_offset) global_min_offset = offset;
        if (offset > global_max_offset) global_max_offset = offset;
        
        if (root_delay < global_min_root_delay) global_min_root_delay = root_delay;
        if (root_delay > global_max_root_delay) global_max_root_delay = root_delay;
        
        if (root_disp < global_min_root_disp) global_min_root_disp = root_disp;
        if (root_disp > global_max_root_disp) global_max_root_disp = root_disp;
        
        if (max_error < global_min_max_error) global_min_max_error = max_error;
        if (max_error > global_max_max_error) global_max_max_error = max_error;
        
        # Accumulate sums for averages
        sum_freq[ip] += freq;
        sum_skew[ip] += skew;
        sum_offset[ip] += offset;
        sum_root_delay[ip] += root_delay;
        sum_root_disp[ip] += root_disp;
        sum_max_error[ip] += max_error;
        
        # Accumulate global sums
        global_sum_freq += freq;
        global_sum_skew += skew;
        global_sum_offset += offset;
        global_sum_root_delay += root_delay;
        global_sum_root_disp += root_disp;
        global_sum_max_error += max_error;
    }
    END {
        # Output per-IP statistics
        for (ip in count) {
            printf "%s,%d,%.6f,%.6f,%.6e,%.6e,%.6e,%.6e\n", 
                ip, count[ip],
                sum_freq[ip]/count[ip],
                sum_skew[ip]/count[ip],
                sum_offset[ip]/count[ip],
                sum_root_delay[ip]/count[ip],
                sum_root_disp[ip]/count[ip],
                sum_max_error[ip]/count[ip];
        }
        
        # Output global statistics to a separate file with units
        if (global_count > 0) {
            print "OVERALL STATISTICS" > "/tmp/chrony_stats.tmp";
            print "Total samples across all IPs: " global_count > "/tmp/chrony_stats.tmp";
            print "" > "/tmp/chrony_stats.tmp";
            
            print "Frequency (ppm):" > "/tmp/chrony_stats.tmp";
            printf "  Min: %.6f ppm\n", global_min_freq > "/tmp/chrony_stats.tmp";
            printf "  Max: %.6f ppm\n", global_max_freq > "/tmp/chrony_stats.tmp";
            printf "  Avg: %.6f ppm\n", global_sum_freq/global_count > "/tmp/chrony_stats.tmp";
            print "" > "/tmp/chrony_stats.tmp";
            
            print "Skew (ppm):" > "/tmp/chrony_stats.tmp";
            printf "  Min: %.6f ppm\n", global_min_skew > "/tmp/chrony_stats.tmp";
            printf "  Max: %.6f ppm\n", global_max_skew > "/tmp/chrony_stats.tmp";
            printf "  Avg: %.6f ppm\n", global_sum_skew/global_count > "/tmp/chrony_stats.tmp";
            print "" > "/tmp/chrony_stats.tmp";
            
            print "Offset:" > "/tmp/chrony_stats.tmp";
            printf "  Min: %.6e seconds\n", global_min_offset > "/tmp/chrony_stats.tmp";
            printf "  Max: %.6e seconds\n", global_max_offset > "/tmp/chrony_stats.tmp";
            printf "  Avg: %.6e seconds\n", global_sum_offset/global_count > "/tmp/chrony_stats.tmp";
            print "" > "/tmp/chrony_stats.tmp";
            
            print "Root Delay:" > "/tmp/chrony_stats.tmp";
            printf "  Min: %.6e seconds\n", global_min_root_delay > "/tmp/chrony_stats.tmp";
            printf "  Max: %.6e seconds\n", global_max_root_delay > "/tmp/chrony_stats.tmp";
            printf "  Avg: %.6e seconds\n", global_sum_root_delay/global_count > "/tmp/chrony_stats.tmp";
            print "" > "/tmp/chrony_stats.tmp";
            
            print "Root Dispersion:" > "/tmp/chrony_stats.tmp";
            printf "  Min: %.6e seconds\n", global_min_root_disp > "/tmp/chrony_stats.tmp";
            printf "  Max: %.6e seconds\n", global_max_root_disp > "/tmp/chrony_stats.tmp";
            printf "  Avg: %.6e seconds\n", global_sum_root_disp/global_count > "/tmp/chrony_stats.tmp";
            print "" > "/tmp/chrony_stats.tmp";
            
            print "Max Error:" > "/tmp/chrony_stats.tmp";
            printf "  Min: %.6e seconds\n", global_min_max_error > "/tmp/chrony_stats.tmp";
            printf "  Max: %.6e seconds\n", global_max_max_error > "/tmp/chrony_stats.tmp";
            printf "  Avg: %.6e seconds\n", global_sum_max_error/global_count > "/tmp/chrony_stats.tmp";
        }
    }
    ' "$temp_data_file" > "$output_file"
    
    # Move the temporary stats file to the final stats file
    if [ "$mode" = "post" ] && [ -f "/tmp/chrony_stats.tmp" ]; then
        mv "/tmp/chrony_stats.tmp" "$stats_file"
    fi
    
    # Log all the detailed output instead of sending to stdout
    {
        echo "Analysis complete. Results stored in $output_file"
        cat "$output_file"
        
        echo ""
        echo "Sample statistics:"
        cat "$sample_count_file"
        
        if [ "$mode" = "post" ] && [ -f "$stats_file" ]; then
            echo ""
            echo "Overall statistics:"
            cat "$stats_file"
        fi
    } >> "$analysis_log"
    
    echo "Analysis complete. Details in $analysis_log" # Line 2 of stdout
    
    # Return the last timestamp for pre-experimentation
    if [ "$mode" = "pre" ]; then
        echo "Timestamp: $last_timestamp" # Line 3 of stdout for pre mode
    fi
}

# Function to compare pre and post experimentation results
compare_results() {
    local id=$1
    local chrony_dir="/tmp/exp/$id/chrony"
    
    local pre_file="$chrony_dir/chrony_analysis_pre.txt"
    local post_file="$chrony_dir/chrony_analysis_post.txt"
    local pre_samples_file="$chrony_dir/chrony_pre_sample_counts.txt"
    local post_samples_file="$chrony_dir/chrony_post_sample_counts.txt"
    local post_stats_file="$chrony_dir/chrony_post_stats.txt"
    local threshold=30  # 30% variation threshold
    local failure_reason_file="$chrony_dir/chrony_failure_reasons.txt"
    local detailed_report_file="$chrony_dir/chrony_detailed_report.txt"
    local comparison_file="$chrony_dir/chrony_comparison.txt"
    
    if [ ! -f "$pre_file" ] || [ ! -f "$post_file" ]; then
        echo "Error: Analysis files not found" # Line 3 of stdout on error
        return 1
    fi
    
    echo "Comparing results..." # Line 3 of stdout
    
    # Create a temporary file to store comparison results and failure reasons
    echo "IP Address,Status,Freq_Var%,Skew_Var%,Offset_Var%,Root_delay_Var%,Root_disp_Var%,Max_error_Var%" > "$comparison_file"
    > "$failure_reason_file"  # Initialize empty failure reason file
    
    # Start building a detailed report
    print_header "$detailed_report_file"
    
    {
        echo "EXPERIMENT ANALYSIS DETAILED REPORT"
        echo "====================================="
        echo ""
        
        echo "PRE-EXPERIMENTATION SAMPLE STATISTICS"
        echo "-------------------------------------"
        cat "$pre_samples_file"
        echo ""
        
        echo "POST-EXPERIMENTATION SAMPLE STATISTICS"
        echo "--------------------------------------"
        cat "$post_samples_file"
        echo ""
        
        if [ -f "$post_stats_file" ]; then
            echo "POST-EXPERIMENTATION OVERALL STATISTICS"
            echo "--------------------------------------"
            cat "$post_stats_file"
            echo ""
        fi
        
        echo "COMPARISON RESULTS (Threshold: ${threshold}%)"
        echo "-------------------------------------"
    } >> "$detailed_report_file"
    
    # Extract the data using grep and process line by line
    for ip in $(tail -n +2 "$pre_file" | cut -d, -f1); do
        pre_line=$(grep "^$ip," "$pre_file")
        post_line=$(grep "^$ip," "$post_file")
        
        if [ -n "$post_line" ]; then
            # Extract values from pre line
            pre_count=$(echo "$pre_line" | cut -d, -f2)
            pre_freq=$(echo "$pre_line" | cut -d, -f3)
            pre_skew=$(echo "$pre_line" | cut -d, -f4)
            pre_offset=$(echo "$pre_line" | cut -d, -f5)
            pre_root_delay=$(echo "$pre_line" | cut -d, -f6)
            pre_root_disp=$(echo "$pre_line" | cut -d, -f7)
            pre_max_error=$(echo "$pre_line" | cut -d, -f8)
            
            # Extract values from post line
            post_count=$(echo "$post_line" | cut -d, -f2)
            post_freq=$(echo "$post_line" | cut -d, -f3)
            post_skew=$(echo "$post_line" | cut -d, -f4)
            post_offset=$(echo "$post_line" | cut -d, -f5)
            post_root_delay=$(echo "$post_line" | cut -d, -f6)
            post_root_disp=$(echo "$post_line" | cut -d, -f7)
            post_max_error=$(echo "$post_line" | cut -d, -f8)
            
            # Using awk for simple percentage calculations - much safer than bc
            freq_var=$(awk -v pre="$pre_freq" -v post="$post_freq" 'BEGIN {
                if (pre == 0 && post == 0) { print "0.00"; exit; }
                if (pre == 0) { print "100.00"; exit; }
                diff = post - pre;
                if (diff < 0) diff = -diff;
                if (pre < 0) pre = -pre;
                printf "%.2f", (100 * diff / pre);
            }')
            
            skew_var=$(awk -v pre="$pre_skew" -v post="$post_skew" 'BEGIN {
                if (pre == 0 && post == 0) { print "0.00"; exit; }
                if (pre == 0) { print "100.00"; exit; }
                diff = post - pre;
                if (diff < 0) diff = -diff;
                if (pre < 0) pre = -pre;
                printf "%.2f", (100 * diff / pre);
            }')
            
            offset_var=$(awk -v pre="$pre_offset" -v post="$post_offset" 'BEGIN {
                if (pre == 0 && post == 0) { print "0.00"; exit; }
                if (pre == 0) { print "100.00"; exit; }
                diff = post - pre;
                if (diff < 0) diff = -diff;
                if (pre < 0) pre = -pre;
                printf "%.2f", (100 * diff / pre);
            }')
            
            root_delay_var=$(awk -v pre="$pre_root_delay" -v post="$post_root_delay" 'BEGIN {
                if (pre == 0 && post == 0) { print "0.00"; exit; }
                if (pre == 0) { print "100.00"; exit; }
                diff = post - pre;
                if (diff < 0) diff = -diff;
                if (pre < 0) pre = -pre;
                printf "%.2f", (100 * diff / pre);
            }')
            
            root_disp_var=$(awk -v pre="$pre_root_disp" -v post="$post_root_disp" 'BEGIN {
                if (pre == 0 && post == 0) { print "0.00"; exit; }
                if (pre == 0) { print "100.00"; exit; }
                diff = post - pre;
                if (diff < 0) diff = -diff;
                if (pre < 0) pre = -pre;
                printf "%.2f", (100 * diff / pre);
            }')
            
            max_error_var=$(awk -v pre="$pre_max_error" -v post="$post_max_error" 'BEGIN {
                if (pre == 0 && post == 0) { print "0.00"; exit; }
                if (pre == 0) { print "100.00"; exit; }
                diff = post - pre;
                if (diff < 0) diff = -diff;
                if (pre < 0) pre = -pre;
                printf "%.2f", (100 * diff / pre);
            }')
            
            # Determine status - using awk for comparison to avoid bc
            status="PASS"
            
            # Create an array of metrics and their variations to check
            metrics=("Freq" "Skew" "Offset" "Root_delay" "Root_disp" "Max_error")
            variations=("$freq_var" "$skew_var" "$offset_var" "$root_delay_var" "$root_disp_var" "$max_error_var")
            pre_values=("$pre_freq" "$pre_skew" "$pre_offset" "$pre_root_delay" "$pre_root_disp" "$pre_max_error")
            post_values=("$post_freq" "$post_skew" "$post_offset" "$post_root_delay" "$post_root_disp" "$post_max_error")
            
            # Check if any variation exceeds the threshold
            for i in "${!metrics[@]}"; do
                var="${variations[$i]}"
                if [ -n "$var" ]; then
                    # Use a simple numeric comparison with awk
                    exceeds=$(awk -v var="$var" -v threshold="$threshold" 'BEGIN { print (var > threshold) ? "yes" : "no" }')
                    if [ "$exceeds" = "yes" ]; then
                        status="FAIL"
                        failure_msg="IP $ip: ${metrics[$i]} variation ($var%) exceeds threshold ($threshold%)"
                        failure_detail="  Pre-value: ${pre_values[$i]}, Post-value: ${post_values[$i]}, Samples: Pre=$pre_count, Post=$post_count"
                        echo "$failure_msg" >> "$failure_reason_file"
                        echo "$failure_detail" >> "$failure_reason_file"
                    fi
                fi
            done
            
            echo "$ip,$status,$freq_var,$skew_var,$offset_var,$root_delay_var,$root_disp_var,$max_error_var" >> "$comparison_file"
            
            # Add to detailed report
            {
                echo "IP: $ip"
                echo "  Status: $status"
                echo "  Samples: Pre=$pre_count, Post=$post_count"
                echo "  Variations:"
                echo "    Freq: $freq_var% (Pre=$pre_freq ppm, Post=$post_freq ppm)"
                echo "    Skew: $skew_var% (Pre=$pre_skew ppm, Post=$post_skew ppm)"
                echo "    Offset: $offset_var% (Pre=$pre_offset seconds, Post=$post_offset seconds)"
                echo "    Root delay: $root_delay_var% (Pre=$pre_root_delay seconds, Post=$post_root_delay seconds)"
                echo "    Root disp: $root_disp_var% (Pre=$pre_root_disp seconds, Post=$post_root_disp seconds)"
                echo "    Max error: $max_error_var% (Pre=$pre_max_error seconds, Post=$post_max_error seconds)"
                echo ""
            } >> "$detailed_report_file"
            
        else
            echo "$ip,NOT_FOUND_IN_POST,N/A,N/A,N/A,N/A,N/A,N/A" >> "$comparison_file"
            echo "IP $ip: Not found in post-experimentation data" >> "$failure_reason_file"
            
            # Add to detailed report
            {
                echo "IP: $ip"
                echo "  Status: NOT_FOUND_IN_POST"
                echo "  Samples: Pre=$pre_count, Post=0"
                echo ""
            } >> "$detailed_report_file"
        fi
    done
    
    # Check for any new IPs in post that weren't in pre
    for ip in $(tail -n +2 "$post_file" | cut -d, -f1); do
        if ! grep -q "^$ip," "$pre_file"; then
            post_count=$(grep "^$ip," "$post_file" | cut -d, -f2)
            echo "$ip,NEW_IP_IN_POST,N/A,N/A,N/A,N/A,N/A,N/A" >> "$comparison_file"
            echo "IP $ip: New IP found only in post-experimentation data" >> "$failure_reason_file"
            
            # Add to detailed report
            {
                echo "IP: $ip"
                echo "  Status: NEW_IP_IN_POST"
                echo "  Samples: Pre=0, Post=$post_count"
                echo ""
            } >> "$detailed_report_file"
        fi
    done
    
    # Add overall status to detailed report
    {
        echo "OVERALL EXPERIMENT RESULT"
        echo "========================="
    } >> "$detailed_report_file"
    
    # Overall experiment status
    if grep -q "FAIL" "$comparison_file"; then
        echo "RESULT: FAIL (See $detailed_report_file for details)" # Line 4 of stdout
        
        # Add failure reasons to detailed report
        {
            echo "Status: FAIL"
            echo "Reasons for failure:"
            cat "$failure_reason_file"
        } >> "$detailed_report_file"
        
        return 1
    else
        echo "RESULT: PASS (See $detailed_report_file for details)" # Line 4 of stdout
        
        # Add success message to detailed report
        {
            echo "Status: PASS"
            echo "All metrics are within acceptable threshold limits (${threshold}%)."
        } >> "$detailed_report_file"
        
        return 0
    fi
}

# Main function
main() {
    # Check if ID is provided
    if [ -z "$2" ]; then
        echo "Usage: $0 {pre|post} <unique_id>"
        exit 1
    fi
    
    local mode="$1"
    local id="$2"
    
    case "$mode" in
        pre)
            # Pre-experimentation analysis
            analyze_chrony_data "pre" "$id"
            ;;
        post)
            # Get the stored timestamp from pre-experimentation
            local timestamp_file="/tmp/exp/$id/chrony/chrony_last_timestamp.txt"
            if [ ! -f "$timestamp_file" ]; then
                echo "Error: No stored timestamp found. Run pre-experimentation analysis first."
                exit 1
            fi
            start_timestamp=$(cat "$timestamp_file")
            
            # Post-experimentation analysis
            analyze_chrony_data "post" "$id" "$start_timestamp"
            
            # Compare results
            compare_results "$id"
            ;;
        *)
            echo "Usage: $0 {pre|post} <unique_id>"
            exit 1
            ;;
    esac
}

# Execute main function with provided arguments
main "$@"
