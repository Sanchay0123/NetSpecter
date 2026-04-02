#include "core/CaptureEngine.hpp"
#include "analytics/StatsTracker.hpp"
#include "GuardController.hpp"
#include <iostream>
#include <thread>
#include <chrono>
#include <atomic>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

std::atomic<bool> keep_running(true);

// Helper to find the current IP of the interface to avoid self-blocking
std::string get_interface_ip(const std::string& iface) {
    struct ifaddrs *ifaddr, *ifa;
    std::string ip_addr = "127.0.0.1"; // Default fallback

    if (getifaddrs(&ifaddr) == -1) return ip_addr;

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        if (ifa->ifa_addr->sa_family == AF_INET && iface == ifa->ifa_name) {
            char host[INET_ADDRSTRLEN];
            if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), 
                           host, INET_ADDRSTRLEN, NULL, 0, NI_NUMERICHOST) == 0) {
                ip_addr = host;
            }
        }
    }
    freeifaddrs(ifaddr);
    return ip_addr;
}

void nitro_watchdog(StatsTracker& tracker, GuardController& guard, std::string myIP) {
    while (keep_running) {
        // 1. NITRO SAMPLING: Check every 800ms to catch Windows Nmap bursts
        std::this_thread::sleep_for(std::chrono::milliseconds(800));
        
        // 2. REFRESH METRICS: Calculate PPS based on recent packets
        tracker.calculate_metrics();

        // 3. THREAT DETECTION: Get a current snapshot of the network state
        auto stats = tracker.get_snapshot();
        uint32_t threshold = 50; // Tuned for your Windows Nmap PPS (~250-350)

        for (auto const& [ip, data] : stats) {
            // WHITE-LIST: Skip the local machine and loopback
            if (ip == myIP || ip == "127.0.0.1") continue;

            // ENFORCEMENT LOGIC: If PPS > 150 and not already blocked
            if (!data.is_blocked && data.last_pps > threshold) {
                
                // TRIGGER KERNEL BLOCK
                if (guard.blockIP(ip)) {
                    tracker.mark_as_blocked(ip);
                    
                    // High-Visibility Alert (Prints even if Dashboard clears)
                    std::cout << "\n\033[1;31m[!] NITRO GUARD: XDP BLOCK TRIGGERED FOR " << ip 
                              << " (" << data.last_pps << " PPS)\033[0m" << std::endl;
                    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // Brief pause for visual impact
                } else {
                    std::cout << "\033[1;41m[ERROR] GuardController failed to update BPF Map for " << ip << "\033[0m" << std::endl;
                }
            }
        }

        // 4. DASHBOARD RENDERING: Refresh the UI
        std::cout << "\033[2J\033[1;1H"; 
        std::cout << "=== NETSPECTER NITRO LIVE DASHBOARD ===" << std::endl;
        std::cout << "Local IP: " << myIP << " (Whitelisted) | Threshold: " << threshold << " PPS" << std::endl;
        std::cout << "------------------------------------------------------" << std::endl;
        std::cout << "IP Address          | Pkts/Sec | Total Bytes | Status" << std::endl;
        std::cout << "------------------------------------------------------" << std::endl;
        
        for (auto const& [ip, data] : stats) {
            std::string status = data.is_blocked ? "\033[1;31m[BLOCKED]\033[0m" : "\033[1;32mActive\033[0m";
            printf("%-19s | %-8u | %-11lu | %s\n", ip.c_str(), data.last_pps, data.total_bytes, status.c_str());
        }
        std::cout << "\n[Press Enter to Stop NetSpecter]" << std::endl;
    }
}


int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: sudo ./netspecter <interface> [--block/--unblock <ip>]" << std::endl;
        return 1;
    }

    std::string interface = argv[1];
    
    try {
        GuardController guard("/sys/fs/bpf/netspecter/blacklist_map");
        
        // CLI Administrative Overrides
        if (argc == 4) {
            std::string cmd = argv[2];
            if (cmd == "--block") {
                guard.blockIP(argv[3]);
                return 0;
            } else if (cmd == "--unblock") {
                guard.unblockIP(argv[3]);
                return 0;
            }
        }

        // Identify current IP for the whitelist
        std::string myIP = get_interface_ip(interface);

        StatsTracker tracker;
        CaptureEngine engine(interface, tracker);
        if (!engine.init()) return 1;

        // Launch the Watchdog with the whitelist IP
        std::thread worker(nitro_watchdog, std::ref(tracker), std::ref(guard), myIP);

        engine.start();
        std::cin.get(); 

        keep_running = false;
        engine.stop();
        worker.join();
        tracker.print_summary();

    } catch (const std::exception& e) {
        std::cerr << "Critical Error: " << e.what() << std::endl;
    }
    return 0;
}