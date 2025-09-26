#!/bin/bash

# Chrony PRE/POST validator (compact) with:
#  - Per-sample absolute bands (offset/freq/skew)
#  - Global offset mean/std percent rule
#  - Global offset std rule
#  - Empirical 97.5% percentiles & parametric mean+1.96*std
#  - Per-IP distributions for offset std & mean/std% (for percentile extraction)
#
# Environment:
#   CHRONY_LOG_FILE (/var/log/chrony/tracking.log)
#   SAMPLE_COUNT_PRE (50)
#   MAX_OFFSET_SEC (0.000450) MAX_FREQ_PPM (65) MAX_SKEW_PPM (0.065)
#   OFFSET_STD_MAX (RECOMMENDED e.g. 0.000050)  # If unset => skip std check
#   OFFSET_MEAN_STD_PERCENT_MAX (10)            # mean/std*100 threshold
#   MIN_SAMPLES_FOR_SYNC (1)
#   ENABLE_JSON (1)
#   JSON_PRETTY (1)
#   SHOW_PHASE_RESULT_STDOUT (1)
#   FIELD_FREQ (5) FIELD_SKEW (7) FIELD_OFFSET (8)
#
# Output (per id): /tmp/exp/<id>/chrony/
#   chrony_pre_raw.txt / chrony_post_raw.txt
#   chrony_last_timestamp.txt
#   chrony_<phase>_per_sample_policy.csv
#   chrony_<phase>_per_ip_stats.csv
#   chrony_<phase>_phase_summary.txt
#   chrony_final_report.txt
#
# PASS CRITERIA per phase:
#   samples >= MIN_SAMPLES_FOR_SYNC
#   per-sample policy PASS
#   (if OFFSET_STD_MAX set) global_offset_std <= OFFSET_STD_MAX
#   (offset_std>0) => (|offset_mean|/offset_std*100) <= OFFSET_MEAN_STD_PERCENT_MAX
#   if offset_std=0 then offset_mean must be 0
#
# OVERALL PASS = Pre PASS AND Post PASS
set -euo pipefail
IFS=$'\n\t'

CHRONY_LOG_FILE="${CHRONY_LOG_FILE:-/var/log/chrony/tracking.log}"
SAMPLE_COUNT_PRE="${SAMPLE_COUNT_PRE:-50}"

MAX_OFFSET_SEC="${MAX_OFFSET_SEC:-0.000450}"
MAX_FREQ_PPM="${MAX_FREQ_PPM:-65}"
MAX_SKEW_PPM="${MAX_SKEW_PPM:-0.065}"

OFFSET_STD_MAX="${OFFSET_STD_MAX:-}"                       # optional (if empty -> skip)
OFFSET_MEAN_STD_PERCENT_MAX="${OFFSET_MEAN_STD_PERCENT_MAX:-1}"

MIN_SAMPLES_FOR_SYNC="${MIN_SAMPLES_FOR_SYNC:-1}"
ENABLE_JSON="${ENABLE_JSON:-1}"
JSON_PRETTY="${JSON_PRETTY:-1}"
SHOW_PHASE_RESULT_STDOUT="${SHOW_PHASE_RESULT_STDOUT:-1}"

FIELD_FREQ="${FIELD_FREQ:-5}"
FIELD_SKEW="${FIELD_SKEW:-7}"
FIELD_OFFSET="${FIELD_OFFSET:-8}"

# ---------- Helpers ----------
timestamp_filter() {
  awk '/^[0-9]{4}-[0-9]{2}-[0-9]{2}[[:space:]][0-9]{2}:[0-9]{2}:[0-9]{2}/'
}
safe_epoch() { date -d "$1" +%s 2>/dev/null || echo ""; }
abs() { awk -v v="$1" 'BEGIN{if(v<0)v=-v;print v}'; }

empirical_q97_5() {
  # read values from stdin, one per line
  awk '
    NF {
      a[++n]=$1
    }
    END{
      if(n==0){print "NA"; exit}
      asort(a)
      idx=int(0.975*n); if((0.975*n)>idx) idx++
      if(idx<1) idx=1
      if(idx>n) idx=n
      printf "%.15g", a[idx]
    }'
}
parametric_97_5() {
  # args: mean std
  awk -v m="$1" -v s="$2" 'BEGIN{printf "%.15g", m+1.96*s}'
}

# ---------- Collection ----------
collect_pre() {
  local id="$1" dir="/tmp/exp/$id/chrony"
  mkdir -p "$dir"; rm -f "$dir"/* || true
  local raw="$dir/chrony_pre_raw.txt" log="$dir/chrony_pre_phase_summary.txt"
  echo "Running pre analysis..."
  if [ ! -f "$CHRONY_LOG_FILE" ]; then
    echo "ERROR: chrony log not found: $CHRONY_LOG_FILE"
    return 1
  fi
  tail -"$SAMPLE_COUNT_PRE" "$CHRONY_LOG_FILE" | timestamp_filter > "$raw"
  local total
  total=$(wc -l < "$raw" || echo 0)
  local last_ts="NO_TIMESTAMP"
  if [ "$total" -gt 0 ]; then
    last_ts=$(tail -1 "$raw" | awk '{print $1" "$2}')
    echo "$last_ts" > "$dir/chrony_last_timestamp.txt"
  fi
  analyze_phase pre "$id" "$raw" "$log"
  local rc=$?
  if [ "$SHOW_PHASE_RESULT_STDOUT" = "1" ]; then
    local ps; ps=$(grep '^PHASE_PASS=' "$log" | cut -d'=' -f2)
    echo "Pre analysis result: $ps (details in $log)"
  fi
  echo "Timestamp: $last_ts"
  return $rc
}

collect_post() {
  local id="$1" dir="/tmp/exp/$id/chrony"
  mkdir -p "$dir"
  local raw="$dir/chrony_post_raw.txt" log="$dir/chrony_post_phase_summary.txt"
  local anchor="$dir/chrony_last_timestamp.txt"
  echo "Running post analysis..."
  if [ ! -f "$CHRONY_LOG_FILE" ]; then
    echo "ERROR: chrony log not found: $CHRONY_LOG_FILE"
    return 1
  fi
  if [ ! -f "$anchor" ]; then
    echo "ERROR: missing pre baseline timestamp (run pre first)"
    return 1
  fi
  local baseline; baseline=$(cat "$anchor")
  local ep; ep=$(safe_epoch "$baseline")
  if [ -z "$ep" ]; then
    echo "ERROR: invalid baseline timestamp"
    return 1
  fi
  timestamp_filter < "$CHRONY_LOG_FILE" | awk -v bts="$baseline" '$1" "$2 >= bts' > "$raw"
  analyze_phase post "$id" "$raw" "$log"
  local rc=$?
  return $rc
}

# ---------- Phase Analysis ----------
analyze_phase() {
  local phase="$1" id="$2" raw="$3" out="$4"
  local dir="/tmp/exp/$id/chrony"
  local per_sample="$dir/chrony_${phase}_per_sample_policy.csv"
  local per_ip="$dir/chrony_${phase}_per_ip_stats.csv"

  local total; total=$( [ -f "$raw" ] && wc -l < "$raw" || echo 0 )

  # Per-sample policy file
  {
    echo "Index,IP,Offset_s,Freq_ppm,Skew_ppm,Offset_OK,Freq_OK,Skew_OK,All_OK"
    if [ "$total" -gt 0 ]; then
      awk -v OFREQ=$FIELD_FREQ -v OSKEW=$FIELD_SKEW -v OOFF=$FIELD_OFFSET \
          -v mo="$MAX_OFFSET_SEC" -v mf="$MAX_FREQ_PPM" -v ms="$MAX_SKEW_PPM" '
        function abs(x){return x<0?-x:x}
        /^[0-9]/ {
          ip=$3
          f=$(OFREQ)+0
          skew=$(OSKEW)+0
          off=$(OOFF)+0
          ok_o=(abs(off)<=mo); ok_f=(abs(f)<=mf); ok_s=(abs(skew)<=ms)
          all=(ok_o && ok_f && ok_s)
          if(!all){viol++}
          printf "%d,%s,%.15g,%.15g,%.15g,%s,%s,%s,%s\n",
            NR,ip,off,f,skew,(ok_o?"YES":"NO"),(ok_f?"YES":"NO"),(ok_s?"YES":"NO"),(all?"YES":"NO")
        }
        END{
          if(NR==0) print "RESULT:NO_DATA"
          else if(viol==0) print "RESULT:PASS"
          else print "RESULT:FAIL"
        }' "$raw"
    else
      echo "RESULT:NO_DATA"
    fi
  } > "$per_sample"

  local per_sample_result; per_sample_result=$(tail -1 "$per_sample" | cut -d':' -f2)

  # Collect per-IP stats (means & std)
  if [ "$total" -gt 0 ]; then
    awk -F'[[:space:]]+' -v OFREQ=$FIELD_FREQ -v OSKEW=$FIELD_SKEW -v OOFF=$FIELD_OFFSET '
      {
        ip=$3
        f=$(OFREQ)+0; sk=$(OSKEW)+0; off=$(OOFF)+0
        c[ip]++
        sf[ip]+=f; ss[ip]+=sk; so[ip]+=off
        sf2[ip]+=f*f; ss2[ip]+=sk*sk; so2[ip]+=off*off
      }
      END{
        print "IP,Count,Mean_Freq_ppm,Mean_Skew_ppm,Mean_Offset_s,Std_Freq_ppm,Std_Skew_ppm,Std_Offset_s,MeanOffsetToStdPercent"
        for(ip in c){
          n=c[ip]
          mf=sf[ip]/n; msk=ss[ip]/n; mo=so[ip]/n
          vf=(sf2[ip]/n)-(mf*mf); if(vf<0)vf=0
          vsk=(ss2[ip]/n)-(msk*msk); if(vsk<0)vsk=0
          vo=(so2[ip]/n)-(mo*mo); if(vo<0)vo=0
          sfreq=sqrt(vf); sskew=sqrt(vsk); soff=sqrt(vo)
          # mean/std percent (offset)
          msp="NA"
          if(soff==0){
            if(mo==0) msp=0.0; else msp="INF"
          } else {
            am=(mo<0?-mo:mo)
            msp= (am/soff)*100.0
          }
          printf "%s,%d,%.15g,%.15g,%.15g,%.15g,%.15g,%.15g,%.15g\n", ip,n,mf,msk,mo,sfreq,sskew,soff,msp
        }
      }' "$raw" > "$per_ip"
  else
    echo "IP,Count,Mean_Freq_ppm,Mean_Skew_ppm,Mean_Offset_s,Std_Freq_ppm,Std_Skew_ppm,Std_Offset_s,MeanOffsetToStdPercent" > "$per_ip"
  fi

  # Global aggregates (across all samples)
  # Build temporary arrays for offsets, freq, skew absolute values
  local g_mean_off=0 g_mean_freq=0 g_mean_skew=0 g_std_off=0 g_std_freq=0 g_std_skew=0
  if [ "$total" -gt 0 ]; then
    # Use awk to compute global stats and also produce lists for empirical
    local temp_global="$dir/.__global_${phase}_values.tmp"
    awk -v OFREQ=$FIELD_FREQ -v OSKEW=$FIELD_SKEW -v OOFF=$FIELD_OFFSET '
      function abs(x){return x<0?-x:x}
      /^[0-9]/ {
        off=$(OOFF)+0; f=$(OFREQ)+0; sk=$(OSKEW)+0
        o[++no]=off; fA[++nf]=f; sA[++ns]=sk
        so+=off; so2+=off*off
        sf+=f; sf2+=f*f
        ss+=sk; ss2+=sk*sk
      }
      END{
        if(no>0){
          mo=so/no; vo=(so2/no)-(mo*mo); if(vo<0)vo=0
          mf=sf/nf; vf=(sf2/nf)-(mf*mf); if(vf<0)vf=0
          ms=ss/ns; vs=(ss2/ns)-(ms*ms); if(vs<0)vs=0
          printf "G_MEAN_OFFSET %.15g\nG_STD_OFFSET %.15g\n", mo, sqrt(vo)
          printf "G_MEAN_FREQ %.15g\nG_STD_FREQ %.15g\n", mf, sqrt(vf)
          printf "G_MEAN_SKEW %.15g\nG_STD_SKEW %.15g\n", ms, sqrt(vs)
          # Output raw lists for percentiles:
          for(i=1;i<=no;i++) printf "LIST_OFFSET %.15g\n", o[i]
          for(i=1;i<=nf;i++) printf "LIST_FREQ %.15g\n", fA[i]
          for(i=1;i<=ns;i++) printf "LIST_SKEW %.15g\n", sA[i]
        }
      }' "$raw" > "$temp_global"

    g_mean_off=$(awk '/^G_MEAN_OFFSET/ {print $2}' "$temp_global")
    g_std_off=$(awk '/^G_STD_OFFSET/ {print $2}' "$temp_global")
    g_mean_freq=$(awk '/^G_MEAN_FREQ/ {print $2}' "$temp_global")
    g_std_freq=$(awk '/^G_STD_FREQ/ {print $2}' "$temp_global")
    g_mean_skew=$(awk '/^G_MEAN_SKEW/ {print $2}' "$temp_global")
    g_std_skew=$(awk '/^G_STD_SKEW/ {print $2}' "$temp_global")

    # Build empirical 97.5% for sample-level absolute values
    local emp_off emp_freq emp_skew
    emp_off=$(grep '^LIST_OFFSET' "$temp_global" | awk '{print ($2<0)?-$2:$2}' | sort -n | empirical_q97_5)
    emp_freq=$(grep '^LIST_FREQ' "$temp_global" | awk '{print ($2<0)?-$2:$2}' | sort -n | empirical_q97_5)
    emp_skew=$(grep '^LIST_SKEW' "$temp_global" | awk '{print ($2<0)?-$2:$2}' | sort -n | empirical_q97_5)

    local par_off par_freq par_skew
    par_off=$(parametric_97_5 "$g_mean_off" "$g_std_off")
    par_freq=$(parametric_97_5 "$g_mean_freq" "$g_std_freq")
    par_skew=$(parametric_97_5 "$g_mean_skew" "$g_std_skew")

    # Per-IP distributions for offset std & mean/std%
    local ip_std_p97 ip_msp_p97 ip_std_list ip_msp_list
    ip_std_list=$(tail -n +2 "$per_ip" | cut -d',' -f8 | grep -v '^$' || true)
    if [ -n "$ip_std_list" ]; then
      ip_std_p97=$(printf "%s\n" "$ip_std_list" | sort -n | empirical_q97_5)
    else
      ip_std_p97="NA"
    fi
    ip_msp_list=$(tail -n +2 "$per_ip" | cut -d',' -f9 | grep -v '^$' | grep -v 'NA' || true)
    if [ -n "$ip_msp_list" ]; then
      # Replace INF with a huge number to sort (will become FAIL anyway at validation)
      ip_msp_p97=$(printf "%s\n" "$ip_msp_list" | sed 's/INF/1e309/' | sort -n | empirical_q97_5)
      # Convert 1e309 back to INF if produced
      if [[ "$ip_msp_p97" == "inf" || "$ip_msp_p97" == "1e+309" || "$ip_msp_p97" == "1e309" ]]; then
        ip_msp_p97="INF"
      fi
    else
      ip_msp_p97="NA"
    fi

    # Global offset mean/std percent
    local global_offset_mean_std_percent="NA"
    if awk -v s="$g_std_off" 'BEGIN{exit (s==0)?0:1}'; then
      # std = 0
      if awk -v m="$g_mean_off" 'BEGIN{exit (m==0)?0:1}'; then
        global_offset_mean_std_percent="0"
      else
        global_offset_mean_std_percent="INF"
      fi
    else
      global_offset_mean_std_percent=$(awk -v m="$g_mean_off" -v s="$g_std_off" '
        function abs(x){return x<0?-x:x}
        BEGIN{ printf "%.9f", (abs(m)/s)*100.0 }')
    fi

    # Evaluate checks
    local check_sample_policy="FAIL"
    [ "$per_sample_result" = "PASS" ] && check_sample_policy="PASS"
    local check_offset_std="SKIP"
    if [ -n "$OFFSET_STD_MAX" ] && [ "$total" -gt 0 ]; then
      check_offset_std=$(awk -v s="$g_std_off" -v lim="$OFFSET_STD_MAX" 'BEGIN{print (s<=lim)?"PASS":"FAIL"}')
    fi
    local check_offset_mean_std="FAIL"
    if [ "$global_offset_mean_std_percent" = "INF" ]; then
      check_offset_mean_std="FAIL"
    elif [ "$global_offset_mean_std_percent" = "NA" ]; then
      check_offset_mean_std="FAIL"
    else
      check_offset_mean_std=$(awk -v v="$global_offset_mean_std_percent" -v lim="$OFFSET_MEAN_STD_PERCENT_MAX" 'BEGIN{print (v<=lim)?"PASS":"FAIL"}')
    fi

    local phase_pass="PASS"
    if [ "$total" -lt "$MIN_SAMPLES_FOR_SYNC" ]; then phase_pass="FAIL"; fi
    if [ "$per_sample_result" != "PASS" ]; then phase_pass="FAIL"; fi
    if [ "$check_offset_std" = "FAIL" ]; then phase_pass="FAIL"; fi
    if [ "$check_offset_mean_std" = "FAIL" ]; then phase_pass="FAIL"; fi

    {
      echo "PHASE=$phase"
      echo "TOTAL_SAMPLES=$total"
      echo "GLOBAL_OFFSET_MEAN=$g_mean_off"
      echo "GLOBAL_OFFSET_STD=$g_std_off"
      echo "GLOBAL_FREQ_MEAN=$g_mean_freq"
      echo "GLOBAL_FREQ_STD=$g_std_freq"
      echo "GLOBAL_SKEW_MEAN=$g_mean_skew"
      echo "GLOBAL_SKEW_STD=$g_std_skew"
      echo "EMP_97P5_OFFSET_ABS=$emp_off"
      echo "EMP_97P5_FREQ_ABS=$emp_freq"
      echo "EMP_97P5_SKEW_ABS=$emp_skew"
      echo "PAR_97P5_OFFSET=$par_off"
      echo "PAR_97P5_FREQ=$par_freq"
      echo "PAR_97P5_SKEW=$par_skew"
      echo "PERIP_OFFSET_STD_EMP97P5=$ip_std_p97"
      echo "PERIP_MEAN_STD_PERCENT_EMP97P5=$ip_msp_p97"
      echo "GLOBAL_OFFSET_MEAN_STD_PERCENT=$global_offset_mean_std_percent"
      echo "CHECK_SAMPLE_POLICY=$check_sample_policy"
      echo "CHECK_OFFSET_STD=$check_offset_std"
      echo "CHECK_OFFSET_MEAN_STD_PERCENT=$check_offset_mean_std"
      echo "OFFSET_STD_MAX=${OFFSET_STD_MAX:-<unset>}"
      echo "OFFSET_MEAN_STD_PERCENT_MAX=$OFFSET_MEAN_STD_PERCENT_MAX"
      echo "PHASE_PASS=$phase_pass"
    } > "$out"

    # JSON (minimal)
    if [ "$ENABLE_JSON" = "1" ]; then
      local indent=""; [ "$JSON_PRETTY" = "1" ] && indent="  "
      {
        echo "{"
        echo "${indent}\"phase\": \"$phase\","
        echo "${indent}\"total_samples\": $total,"
        echo "${indent}\"phase_pass\": \"$phase_pass\","
        echo "${indent}\"global_offset_mean\": $g_mean_off,"
        echo "${indent}\"global_offset_std\": $g_std_off,"
        echo "${indent}\"global_offset_mean_std_percent\": \"$global_offset_mean_std_percent\","
        echo "${indent}\"offset_std_check\": \"$check_offset_std\","
        echo "${indent}\"offset_mean_std_percent_check\": \"$check_offset_mean_std\","
        echo "${indent}\"empirical_97p5\": {"
        echo "${indent}  \"offset_abs\": \"$emp_off\","
        echo "${indent}  \"freq_abs\": \"$emp_freq\","
        echo "${indent}  \"skew_abs\": \"$emp_skew\","
        echo "${indent}  \"per_ip_offset_std\": \"$ip_std_p97\","
        echo "${indent}  \"per_ip_mean_std_percent\": \"$ip_msp_p97\""
        echo "${indent}},"
        echo "${indent}\"parametric_97p5\": {"
        echo "${indent}  \"offset\": \"$par_off\","
        echo "${indent}  \"freq\": \"$par_freq\","
        echo "${indent}  \"skew\": \"$par_skew\""
        echo "${indent}}"
        echo "}"
      } > "$out.json"
    fi

  else
    {
      echo "PHASE=$phase"
      echo "TOTAL_SAMPLES=0"
      echo "PHASE_PASS=FAIL"
      echo "CHECK_SAMPLE_POLICY=NO_DATA"
      echo "CHECK_OFFSET_STD=SKIP"
      echo "CHECK_OFFSET_MEAN_STD_PERCENT=FAIL"
    } > "$out"
  fi
}

# ---------- Final Report ----------
final_report() {
  local id="$1" dir="/tmp/exp/$id/chrony"
  local pre="$dir/chrony_pre_phase_summary.txt"
  local post="$dir/chrony_post_phase_summary.txt"
  local report="$dir/chrony_final_report.txt"

  local pre_pass post_pass
  pre_pass=$(grep '^PHASE_PASS=' "$pre" 2>/dev/null | cut -d'=' -f2 || echo "FAIL")
  post_pass=$(grep '^PHASE_PASS=' "$post" 2>/dev/null | cut -d'=' -f2 || echo "FAIL")

  local overall="PASS"
  [ "$pre_pass" != "PASS" ] && overall="FAIL"
  [ "$post_pass" != "PASS" ] && overall="FAIL"

  {
    echo "==== FINAL REPORT ===="
    echo "Per-sample bands: offset<=$MAX_OFFSET_SEC s freq<=$MAX_FREQ_PPM ppm skew<=$MAX_SKEW_PPM ppm"
    echo "OffsetStd threshold: ${OFFSET_STD_MAX:-<unset>}"
    echo "OffsetMean/Std% threshold: $OFFSET_MEAN_STD_PERCENT_MAX %"
    echo "Min samples per phase: $MIN_SAMPLES_FOR_SYNC"
    echo ""
    echo "Pre phase:  $pre_pass"
    echo "Post phase: $post_pass"
    echo ""

    echo "PRE SUMMARY:"
    if [ -f "$pre" ]; then
      grep -E '^(TOTAL_SAMPLES|GLOBAL_OFFSET_MEAN=|GLOBAL_OFFSET_STD=|GLOBAL_FREQ_MEAN=|GLOBAL_FREQ_STD=|GLOBAL_SKEW_MEAN=|GLOBAL_SKEW_STD=|EMP_97P5_|PAR_97P5_|PERIP_OFFSET_STD_EMP97P5=|PERIP_MEAN_STD_PERCENT_EMP97P5=|GLOBAL_OFFSET_MEAN_STD_PERCENT=|CHECK_)' "$pre"
    else
      echo " (missing)"
    fi
    echo ""
    echo "POST SUMMARY:"
    if [ -f "$post" ]; then
      grep -E '^(TOTAL_SAMPLES|GLOBAL_OFFSET_MEAN=|GLOBAL_OFFSET_STD=|GLOBAL_FREQ_MEAN=|GLOBAL_FREQ_STD=|GLOBAL_SKEW_MEAN=|GLOBAL_SKEW_STD=|EMP_97P5_|PAR_97P5_|PERIP_OFFSET_STD_EMP97P5=|PERIP_MEAN_STD_PERCENT_EMP97P5=|GLOBAL_OFFSET_MEAN_STD_PERCENT=|CHECK_)' "$post"
    else
      echo " (missing)"
    fi
    echo ""
    echo "OVERALL RESULT: $overall"
  } > "$report"

  echo "Comparing results..."
  if [ "$overall" = "PASS" ]; then
    echo "RESULT: PASS (See $report for details)"
  else
    echo "RESULT: FAIL (See $report for details)"
  fi
}

# ---------- Main ----------
usage(){ echo "Usage: $0 {pre|post} <id>"; exit 1; }

main() {
  [ $# -lt 2 ] && usage
  local mode="$1" id="$2"
  case "$mode" in
    pre)
      collect_pre "$id" || exit 1
      ;;
    post)
      collect_post "$id" || exit 1
      final_report "$id"
      ;;
    *)
      usage
      ;;
  esac
}
