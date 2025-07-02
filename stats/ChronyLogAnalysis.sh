#!/bin/bash

# Function to print a header with date and user information
print_header() {
    local current_date=$(date -u "+%Y-%m-%d %H:%M:%S")
    local current_user=$(whoami)
    
    echo "============================================================"
    echo "Chrony Log Analysis Report"
    echo "============================================================"
    echo "Date and Time (UTC): $current_date"
    echo "User: $current_user"
    echo "============================================================"
    echo ""
}

# Function to setup the chrony directory
setup_chrony_dir() {
    local id=$1
    local mode=$2
    local dir="/tmp/exp/$id/chrony"
    
    # Create directory if it doesn't exist
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
        echo "Created directory: $dir"
    else
        echo "Directory already exists: $dir"
    fi
    
    # Clean up any previous files in pre mode
    if [ "$mode" = "pre" ]; then
        echo "Cleaning up previous files in $dir..."
        rm -f "$dir"/*
    fi
    
    echo "Using directory: $dir"
    echo ""
    
    # Return the directory path without printing anything
    # This is crucial - don't add any echo statements here
}

# Function to extract and analyze chrony tracking log data
analyze_chrony_data() {
    local mode=$1     # "pre" or "post"
    local id=$2       # unique ID for directory
    local start_timestamp=$3  # Only used in "post" mode
    
    # Setup chrony directory without capturing output
    setup_chrony_dir "$id" "$mode"
    local chrony_dir="/tmp/exp/$id/chrony"
    
    local output_file="$chrony_dir/chrony_analysis_${mode}.txt"
    local log_file="/var/log/chrony/tracking.log"
    local sample_count_file="$chrony_dir/chrony_${mode}_sample_counts.txt"
    local temp_data_file="$chrony_dir/chrony_data_temp.txt"
    local timestamp_file="$chrony_dir/chrony_last_timestamp.txt"
    
    echo "Running ${mode}-experimentation analysis..."
    
    # For pre-experimentation: get last 50 data lines
    if [ "$mode" = "pre" ]; then
        # Get the last 50 non-header lines from the log file
        grep -v "=\|Date (UTC) Time" "$log_file" | tail -50 > "$temp_data_file"
        
        # Store the last timestamp for post-experimentation
        last_timestamp=$(tail -1 "$temp_data_file" | awk '{print $1 " " $2}')
        echo "$last_timestamp" > "$timestamp_file"
        echo "Last timestamp: $last_timestamp"
        
    # For post-experimentation: get data from the stored timestamp onwards
    else
        if [ -z "$start_timestamp" ]; then
            echo "Error: No start timestamp provided for post-experimentation analysis"
            return 1
        fi
        
        # Convert timestamp to a format that can be used for comparison
        formatted_timestamp=$(date -d "$start_timestamp" +"%Y-%m-%d %H:%M:%S")
        echo "Reading data from timestamp: $formatted_timestamp onwards"
        
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
    
    # Process the extracted data for unique IPs and calculate averages
    awk '
    BEGIN {
        print "IP Address,Count,Avg_Freq_ppm,Avg_Skew_ppm,Avg_Offset,Avg_Root_delay,Avg_Root_disp,Avg_Max_error"
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
        sum_freq[ip] += freq;
        sum_skew[ip] += skew;
        sum_offset[ip] += offset;
        sum_root_delay[ip] += root_delay;
        sum_root_disp[ip] += root_disp;
        sum_max_error[ip] += max_error;
    }
    END {
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
    }
    ' "$temp_data_file" > "$output_file"
    
    echo "Analysis complete. Results stored in $output_file"
    cat "$output_file"
    
    echo ""
    echo "Sample statistics:"
    cat "$sample_count_file"
    echo ""
    
    # Return the last timestamp for pre-experimentation
    if [ "$mode" = "pre" ]; then
        echo "$last_timestamp"
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
    local threshold=30  # 30% variation threshold
    local failure_reason_file="$chrony_dir/chrony_failure_reasons.txt"
    local detailed_report_file="$chrony_dir/chrony_detailed_report.txt"
    local comparison_file="$chrony_dir/chrony_comparison.txt"
    
    if [ ! -f "$pre_file" ] || [ ! -f "$post_file" ]; then
        echo "Error: Pre or post analysis files not found"
        return 1
    fi
    
    echo "Comparing pre and post experimentation results..."
    
    # Create a temporary file to store comparison results and failure reasons
    echo "IP Address,Status,Freq_Var%,Skew_Var%,Offset_Var%,Root_delay_Var%,Root_disp_Var%,Max_error_Var%" > "$comparison_file"
    > "$failure_reason_file"  # Initialize empty failure reason file
    
    # Start building a detailed report
    {
        print_header
        
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
        
        echo "COMPARISON RESULTS (Threshold: ${threshold}%)"
        echo "-------------------------------------"
    } > "$detailed_report_file"
    
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
            status="SUCCESS"
            
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
                        status="FAILURE"
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
                echo "    Freq: $freq_var% (Pre=$pre_freq, Post=$post_freq)"
                echo "    Skew: $skew_var% (Pre=$pre_skew, Post=$post_skew)"
                echo "    Offset: $offset_var% (Pre=$pre_offset, Post=$post_offset)"
                echo "    Root delay: $root_delay_var% (Pre=$pre_root_delay, Post=$post_root_delay)"
                echo "    Root disp: $root_disp_var% (Pre=$pre_root_disp, Post=$post_root_disp)"
                echo "    Max error: $max_error_var% (Pre=$pre_max_error, Post=$post_max_error)"
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
    
    echo "Comparison complete. Results stored in $comparison_file"
    cat "$comparison_file"
    
    # Add overall status to detailed report
    {
        echo "OVERALL EXPERIMENT RESULT"
        echo "========================="
    } >> "$detailed_report_file"
    
    # Overall experiment status
    if grep -q "FAILURE" "$comparison_file"; then
        echo "OVERALL EXPERIMENT STATUS: FAILURE"
        echo "Reasons for failure:" 
        cat "$failure_reason_file"
        
        # Add failure reasons to detailed report
        {
            echo "Status: FAILURE"
            echo "Reasons for failure:"
            cat "$failure_reason_file"
        } >> "$detailed_report_file"
        
        echo ""
        echo "Detailed report available at: $detailed_report_file"
        echo "To view: cat $detailed_report_file"
        
        return 1
    else
        echo "OVERALL EXPERIMENT STATUS: SUCCESS"
        
        # Add success message to detailed report
        {
            echo "Status: SUCCESS"
            echo "All metrics are within acceptable threshold limits (${threshold}%)."
        } >> "$detailed_report_file"
        
        echo ""
        echo "Detailed report available at: $detailed_report_file"
        echo "To view: cat $detailed_report_file"
        
        return 0
    fi
}

# Main function
main() {
    print_header
    
    # Check if ID is provided
    if [ -z "$2" ]; then
        echo "Error: No ID provided. Usage: $0 {pre|post} <unique_id>"
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
