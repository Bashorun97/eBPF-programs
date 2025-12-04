#!/bin/bash
set -eux -o pipefail

echo "--- Installing eBPF Dependencies ---"
apt-get update -y
apt-get install -y apt-transport-https ca-certificates curl clang llvm jq

# Install kernel headers to compile C code
apt-get install -y linux-headers-$(uname -r) linux-tools-common linux-tools-$(uname -r)

apt-get install -y libelf-dev libcap-dev libpcap-dev libbfd-dev binutils-dev build-essential make
apt-get install -y bpfcc-tools
apt-get install -y python3-pip

echo "--- Installing Debug Symbols for eBPF Tools ---"
apt-get install -y ubuntu-dbgsym-keyring
echo "deb http://ddebs.ubuntu.com $(lsb_release -cs) main restricted universe multiverse
deb http://ddebs.ubuntu.com $(lsb_release -cs)-updates main restricted universe multiverse" | \
tee -a /etc/apt/sources.list.d/ddebs.list

apt-get update -y
apt-get install -y bpftrace-dbgsym

echo "--- Final eBPF Libs ---"
apt-get install -y libbpf-dev
ln -sf /usr/include/$(uname -m)-linux-gnu/asm /usr/include/asm

echo "--- eBPF Setup Complete ---"