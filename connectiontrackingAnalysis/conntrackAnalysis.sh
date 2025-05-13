#!/usr/bin/env bash
set -euo pipefail

usage(){
  cat <<EOF
Usage: $0 -m <marker1> -s <marker2> -l <logfile> -o <out.csv>
  -m : first marker (e.g. "connt1")
  -s : second marker (e.g. "connt2")
  -l : path to conntrack log
  -o : output CSV file (will be created/appended)
EOF
  exit 1
}

# Parse options
while getopts "m:s:l:o:" opt; do
  case $opt in
    m) MARK1="$OPTARG" ;;
    s) MARK2="$OPTARG" ;;
    l) LOGFILE="$OPTARG" ;;
    o) OUTCSV="$OPTARG" ;;
    *) usage ;;
  esac
done

[[ -v MARK1 && -v MARK2 && -v LOGFILE && -v OUTCSV ]] || usage

# Prepare output file and header if empty
if [[ ! -e $OUTCSV ]]; then
  printf "src_ip,src_port,dst_ip,dst_port,protocol,action,state,delta_ns\n" > "$OUTCSV"
fi

declare -A seen1 seen2

# Function to process one line, given marker and its seen‑table, and the opposite table
process_line(){
  local line=$1 marker=$2 this_table=$3 other_table=$4
  # Extract comma‑separated fields after the 7th space:
  #   timestamp host  marker  program  ...  comma_separated_fields
  # e.g. "2025-05-13T21:00:32... connt1 ... 1024909,1747162725...,src,port,dst,port,proto,ACT,NUM,STATE,..."
  # We want:
  #   field[2] = timestamp_ns
  #   field[3]=src_ip, [4]=src_port, [5]=dst_ip, [6]=dst_port
  #   field[7]=protocol, [8]=action, [10]=state
  # so we split off at the seventh space, then IFS=','.
  local tail=${line#* * * * * * * }  # drop first 7 space‑separated tokens
  IFS=',' read -r conn_id timestamp_ns src_ip src_port dst_ip dst_port protocol action num state _rest <<<"$tail"

  # build our key on the 5‑tuple + action + state
  local key="$src_ip,$src_port,$dst_ip,$dst_port,$protocol,$action,$state"

  # record this timestamp
  eval "$this_table"[\$key]="$timestamp_ns"

  # if the opposite table already had it, compute delta
  local other_ts
  eval "other_ts=\${${other_table}[\$key]:-}"

  if [[ -n $other_ts ]]; then
    # compute absolute delta
    local delta
    if (( timestamp_ns > other_ts )); then
      delta=$(( timestamp_ns - other_ts ))
    else
      delta=$(( other_ts - timestamp_ns ))
    fi

    # emit CSV
    printf '%s,%s,%s,%s,%s,%s,%s,%d\n' \
      "$src_ip" "$src_port" "$dst_ip" "$dst_port" "$protocol" "$action" "$state" "$delta" \
      >> "$OUTCSV"

    # forget them so we only report once
    eval "unset ${this_table}[\$key]"
    eval "unset ${other_table}[\$key]"
  fi
}

# Start following the log
tail -n0 -F "$LOGFILE" 2>/dev/null | \
while IFS= read -r line; do
  # only care about lines containing 172.16.1.1
  [[ "$line" == *"172.16.1.1"* ]] || continue

  if [[ "$line" == *"$MARK1"* ]]; then
    process_line "$line" "$MARK1" seen1 seen2
  elif [[ "$line" == *"$MARK2"* ]]; then
    process_line "$line" "$MARK2" seen2 seen1
  fi
done
