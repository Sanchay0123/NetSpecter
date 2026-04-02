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
#include <fstream>
#include <iomanip>


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

std::string get_timestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&now_c), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

void nitro_watchdog(StatsTracker& tracker, GuardController& guard, std::string myIP) {
    const std::string BLACKLIST_FILE = "blacklist.csv";

    while (keep_running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(800));
        tracker.calculate_metrics();

        auto stats = tracker.get_snapshot();
        uint32_t threshold = 300; 

        for (auto const& [ip, data] : stats) {
            if (ip == myIP || ip == "127.0.0.1") continue;

            if (!data.is_blocked && data.last_pps > threshold) {
                // 1. Trigger Kernel Block
                if (guard.blockIP(ip)) {
                    tracker.mark_as_blocked(ip);
                    
                    // 2. PERSISTENT LOGGING (CSV Format: Timestamp, IP, PPS)
                    std::ofstream csv_file(BLACKLIST_FILE, std::ios::app);
                    if (csv_file.is_open()) {
                        csv_file << get_timestamp() << "," << ip << "," << data.last_pps << "\n";
                        csv_file.close();
                    }

                    std::cout << "\n\033[1;31m[!] NITRO GUARD: XDP BLOCK TRIGGERED FOR " << ip 
                              << " (" << data.last_pps << " PPS) -> Logged to CSV\033[0m" << std::endl;
                    
                    std::this_thread::sleep_for(std::chrono::milliseconds(200)); 
                } else {
                    std::cout << "\033[1;41m[ERROR] GuardController failed for " << ip << "\033[0m" << std::endl;
                }
            }
        }

        // --- Dashboard Rendering ---
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
    const std::string BLACKLIST_FILE = "blacklist.csv";
    
    try {
        GuardController guard("/sys/fs/bpf/netspecter/blacklist_map");
        StatsTracker tracker;

        // --- PHASE 1: BOOTSTRAP PERSISTENT BLACKLIST ---
        std::ifstream infile(BLACKLIST_FILE);
        if (infile.is_open()) {
            std::cout << "[*] Bootstrapping Persistent Blacklist..." << std::endl;
            std::string line;
            int count = 0;
            while (std::getline(infile, line)) {
                std::stringstream ss(line);
                std::string timestamp, ip_to_block;
                // CSV Format: Timestamp, IP, PPS
                if (std::getline(ss, timestamp, ',') && std::getline(ss, ip_to_block, ',')) {
                    if (guard.blockIP(ip_to_block)) {
                        tracker.mark_as_blocked(ip_to_block);
                        count++;
                    }
                }
            }
            std::cout << "[+] Successfully restored " << count << " blocks from CSV." << std::endl;
            infile.close();
        }

        // --- PHASE 2: CLI ADMINISTRATIVE OVERRIDES ---
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

        // --- PHASE 3: ENGINE STARTUP ---
        std::string myIP = get_interface_ip(interface);
        CaptureEngine engine(interface, tracker);
        if (!engine.init()) return 1;

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