# NetSpecter 👁️🛡️
**High-Performance eBPF/XDP Intrusion Prevention System (IPS)**

NetSpecter is a multi-layered, kernel-level network defense engine designed for high-speed threat mitigation and dynamic intelligence gathering. Built with C++20 and eBPF (Extended Berkeley Packet Filter), it intercepts, analyzes, and drops malicious traffic directly at the Network Interface Card (NIC) ring buffer before it reaches the Linux OS network stack.

Authored by Sanchay Jain.

## 🚀 Core Architecture

NetSpecter operates on a decentralized architecture bridging Kernel-space and Userspace:
1. **The Shield (eBPF/XDP):** A high-speed kernel program attached to the interface driver. It enforces policies in nanoseconds, dropping volumetric attacks natively.
2. **The Brain (Userspace Daemon):** A C++ multithreaded engine that processes packets allowed by the kernel, calculating behavioral heuristics and Deep Packet Inspection (DPI).
3. **The Matrix (State Management):** BPF Maps that synchronize threat intelligence between the Userspace engine and the Kernel firewall in real-time.

## 🛡️ Multi-Dimensional Heuristics

* **Volumetric Defense:** Tracks Packets Per Second (PPS) and bytes mapped to individual IPs, severing connections during DoS floods.
* **Behavioral Entropy Scoring:** Calculates statistical port variance to identify stealthy, low-volume reconnaissance scans (e.g., Nmap sweeps) that evade traditional firewalls.
* **Port-Agnostic DPI:** Safely extracts and scans payloads across all ephemeral ports for exploit signatures (e.g., NOP sleds `\x90`, SQLi `UNION`) using strict memory boundary constraints.

## 🥷 Operational Modes

NetSpecter features two distinct response protocols dynamically injected into the kernel configuration matrix:

* **Ghost Mode (`--ghost`):** Prioritizes absolute system survival. Flagged IPs trigger an immediate `XDP_DROP`. All system responses (including ICMP) are silenced, making the host appear physically disconnected from the network to the attacker.
* **Honey Mode (`--honey`):** Prioritizes threat intelligence. Actively routes flagged packets via `XDP_PASS` into the userspace inspection engine while maintaining a silent perimeter. Malicious payloads are asynchronously extracted, base64-encoded, and logged to `telemetry.json` without blocking the core packet processing thread.

## ⚙️ Installation & Deployment

### Prerequisites
* Linux Environment (Arch Linux / Ubuntu recommended)
* `clang` and `llvm` (for compiling BPF targets)
* `libpcap-dev`
* `bpftool` and `libbpf-dev`
* `cmake` and `make`

### Build Instructions
```bash
git clone [https://github.com/yourusername/NetSpecter.git](https://github.com/yourusername/NetSpecter.git)
cd NetSpecter
mkdir build && cd build
cmake ..
make