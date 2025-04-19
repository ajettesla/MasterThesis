#!/usr/bin/env bash
set -euo pipefail
# --------------------------------------------------
# 1) PYTHON VENV + Python deps
# --------------------------------------------------
if [ ! -d "venv" ]; then
  echo "[+] Creating Python3 venv…"
  python3 -m venv venv
  echo "[+] Activating venv and installing Python deps…"
  # shellcheck disable=SC1091
  source venv/bin/activate
  pip install --upgrade pip
  pip install psutil
else
  echo "[+] Python venv already exists. Activating…"
  # shellcheck disable=SC1091
  source venv/bin/activate
fi

# --------------------------------------------------
# 2) C TOOLCHAIN & LIBRARIES
# --------------------------------------------------
# Only works on Debian/Ubuntu (apt-get)
if command -v apt-get >/dev/null; then
  echo "[+] Installing C build tools + headers via apt-get…"
  sudo apt-get update
  sudo apt install -y \
       build-essential \
       libssl-dev \
       libnfnetlink-dev \
       libmnl-dev \
       libnetfilter-conntrack-dev \
       libnetfilter-queue-dev \
       libnetfilter-cttimeout-dev \
       libncurses5-dev \
       libncursesw5-dev \
       pkg-config \
       git \
       gcc \
       make
else
  echo "[!] Warning: apt-get not found. Please install:"
  echo "    - a C compiler (gcc/clang)"
  echo "    - libnetfilter-conntrack development headers"
  echo "    - OpenSSL development headers"
fi

echo "[✓] All dependencies are in place."

# Optionally, compile your C code here:
# gcc -o my_conntrack_tool src/*.c -lnetfilter_conntrack -lssl

# And you can invoke your Python script:
# python your_script.py


