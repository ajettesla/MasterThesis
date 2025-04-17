#!/bin/bash

set -e  # Exit immediately on error

echo "📦 Updating package list..."
sudo apt update

echo "📥 Installing required libraries and development tools..."
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

