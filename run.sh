#!/bin/bash

INTERFACE=$1
if [ -z "$INTERFACE" ]; then
    echo "Usage: sudo ./run.sh <interface> [--block/--unblock <ip>]"
    exit 1
fi

# 1. Ensure the BPF filesystem directory exists
sudo mkdir -p /sys/fs/bpf/netspecter

# 2. Get the current Map ID from the kernel, if not found, compile and load XDP
MAP_ID=$(sudo bpftool map show | grep "blacklist_map" | cut -d: -f1 | head -n 1)

if [ -z "$MAP_ID" ]; then
    echo "[*] blacklist_map not found. Compiling and attaching XDP to $INTERFACE..."
    clang -O2 -g -target bpf -c src/kern/xdp_prog.c -o src/kern/xdp_prog.o
    sudo ip link set dev $INTERFACE xdp off 2>/dev/null
    sudo ip link set dev $INTERFACE xdpgeneric obj src/kern/xdp_prog.o sec xdp
    
    MAP_ID=$(sudo bpftool map show | grep "blacklist_map" | cut -d: -f1 | head -n 1)
    if [ -z "$MAP_ID" ]; then
        echo "[!] Error: blacklist_map still not found after loading. Check compilation."
        exit 1
    fi
fi

# 3. Always refresh the pin to ensure it matches the current Kernel Map ID
# We remove the old one first to avoid the "already exists" error
if [ -f /sys/fs/bpf/netspecter/blacklist_map ]; then
    sudo rm /sys/fs/bpf/netspecter/blacklist_map
fi

# 3. Force the pin (the -f flag handles the 'already exists' error internally)
echo "[*] Syncing Portal: Pinning Map ID $MAP_ID..."
sudo bpftool map pin id $MAP_ID /sys/fs/bpf/netspecter/blacklist_map -f

# 4. Execute the NetSpecter binary
sudo ./build/netspecter "$@"