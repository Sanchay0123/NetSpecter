#include "GuardController.hpp"
#include "analytics/StatsTracker.hpp"
#include "core/CaptureEngine.hpp"
#include "telemetry/TelemetryExporter.hpp"
#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <fstream>
#include <ifaddrs.h>
#include <iomanip>
#include <iostream>
#include <netdb.h>
#include <sys/socket.h>
#include <thread>

std::atomic<bool> keep_running(true);

// Helper to find the current IP of the interface to avoid self-blocking
std::string get_interface_ip(const std::string &iface) {
  struct ifaddrs *ifaddr, *ifa;
  std::string ip_addr = "127.0.0.1"; // Default fallback

  if (getifaddrs(&ifaddr) == -1)
    return ip_addr;

  for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == nullptr)
      continue;
    if (ifa->ifa_addr->sa_family == AF_INET && iface == ifa->ifa_name) {
      char host[INET_ADDRSTRLEN];
      if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host,
                      INET_ADDRSTRLEN, NULL, 0, NI_NUMERICHOST) == 0) {
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

void nitro_watchdog(StatsTracker &tracker, GuardController &guard,
                    std::string myIP, std::string mode_str) {
  const std::string BLACKLIST_FILE = "blacklist.csv";

  while (keep_running) {
    std::this_thread::sleep_for(std::chrono::milliseconds(800));
    tracker.calculate_metrics();

    auto stats = tracker.get_snapshot();
    uint32_t threshold = 300;

    for (auto const &[ip, data] : stats) {
      if (ip == myIP || ip == "127.0.0.1")
        continue;

      if (!data.is_blocked) {
        bool block = false;
        std::string attack_type = "Unknown";

        if (data.last_pps > threshold) {
          block = true;
          attack_type = "Targeted DoS";
        }
        if (data.dpi_hits > 0) {
          block = true;
          attack_type = "DPI Exploit";
        }
        if (!block && data.unique_dst_ports.size() >= 15 &&
            data.entropy_score > 150.0f) {
          block = true;
          attack_type = "Port Scan";
        }

        if (block) {
          // 1. Trigger Kernel Block
          if (guard.blockIP(ip)) {
            tracker.mark_as_blocked(ip, attack_type);

            // 2. PERSISTENT LOGGING (CSV Format: Timestamp, IP, PPS)
            std::ofstream csv_file;
            csv_file.open(BLACKLIST_FILE, std::ios::app);

            if (csv_file.is_open()) {
              csv_file << get_timestamp() << "," << ip << "," << data.last_pps
                       << std::endl;
              csv_file.flush(); // Force write to disk immediately
              csv_file.close();
              // This will confirm in the console that the file was written
              std::cout << "[+] Blacklist updated: " << BLACKLIST_FILE
                        << std::endl;
            } else {
              // If this prints, we have a permission or path problem!
              std::cerr << "\033[1;33m[!] FILE ERROR: Could not write to "
                        << BLACKLIST_FILE << " (Check permissions/path)\033[0m"
                        << std::endl;
            }

            std::cout << "\n\033[1;31m[!] NITRO GUARD: XDP BLOCK TRIGGERED FOR "
                      << ip << " (" << data.last_pps << " PPS) [" << attack_type
                      << "] -> Logged to CSV\033[0m" << std::endl;

            std::this_thread::sleep_for(std::chrono::milliseconds(200));
          } else {
            std::cout << "\033[1;41m[ERROR] GuardController failed for " << ip
                      << "\033[0m" << std::endl;
          }
        }
      }
    }

    // --- Dashboard Rendering ---
    std::cout << "\033[2J\033[1;1H";
    std::cout << "=== NETSPECTER NITRO LIVE DASHBOARD ===" << std::endl;
    std::cout << "Local IP: " << myIP
              << " (Whitelisted) | Threshold: " << threshold << " PPS | Mode: " << mode_str
              << std::endl;
    std::cout << "-------------------------------------------------------------"
                 "-------------------------"
              << std::endl;
    std::cout << "IP Address          | Pkts/Sec | Total Bytes | Ports | "
                 "Entropy | DPI | Status"
              << std::endl;
    std::cout << "-------------------------------------------------------------"
                 "-------------------------"
              << std::endl;

    for (auto const &[ip, data] : stats) {
      std::string status =
          data.is_blocked ? "\033[1;31m[BLK:" + data.attack_type + "]\033[0m"
                          : "\033[1;32mActive\033[0m";
      printf("%-19s | %-8u | %-11lu | %-5zu | %-7.1f | %-3u | %s\n", ip.c_str(),
             data.last_pps, data.total_bytes, data.unique_dst_ports.size(),
             data.entropy_score, data.dpi_hits, status.c_str());
    }
    std::cout << "\n[Press Enter to Stop NetSpecter]" << std::endl;
  }
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    std::cerr << "Usage: sudo ./netspecter <interface> [--ghost|--honey] [--block/--unblock <ip>]"
              << std::endl;
    return 1;
  }

  std::string interface = argv[1];
  int run_mode = 0;
  std::string mode_str = "\033[1;30mGHOST\033[0m";

  for (int i = 2; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--honey") {
      run_mode = 1;
      mode_str = "\033[1;33mHONEY\033[0m";
    } else if (arg == "--ghost") {
      run_mode = 0;
      mode_str = "\033[1;30mGHOST\033[0m";
    }
  }

  const std::string BLACKLIST_FILE = "blacklist.csv";

  try {
    GuardController guard("/sys/fs/bpf/netspecter/blacklist_map");
    guard.setConfigMode(run_mode);

    StatsTracker tracker;
    TelemetryExporter exporter("/home/theimmortalcreator/Documents/NetSpecter/telemetry.json");
    if (run_mode == 1) {
      tracker.set_exporter(&exporter);
    }

    // Ensure the file exists right at startup
    std::ofstream touch_file(BLACKLIST_FILE, std::ios::app);
    touch_file.close();

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
        if (std::getline(ss, timestamp, ',') &&
            std::getline(ss, ip_to_block, ',')) {
          if (guard.blockIP(ip_to_block)) {
            tracker.mark_as_blocked(ip_to_block, "CSV Load");
            count++;
          }
        }
      }
      std::cout << "[+] Successfully restored " << count << " blocks from CSV."
                << std::endl;
      infile.close();
    }

    // CLI Administrative Overrides
    if (argc >= 4) {
      std::string cmd = argv[argc - 2];
      std::string target_ip = argv[argc - 1];

      if (cmd == "--block") {
        if (guard.blockIP(target_ip)) {
          // Log manual block to CSV
          std::ofstream csv_file(BLACKLIST_FILE, std::ios::app);
          if (csv_file.is_open()) {
            csv_file << get_timestamp() << "," << target_ip << ",MANUAL\n";
            csv_file.close();
          }
          std::cout << "[+] Manually blocked and logged: " << target_ip
                    << std::endl;
        }
        return 0;
      } else if (cmd == "--unblock") {
        std::string ip_to_remove = target_ip;
        if (guard.unblockIP(ip_to_remove)) {
          // --- PERSISTENT SYNC: Remove from CSV ---
          std::ifstream infile(BLACKLIST_FILE);
          std::vector<std::string> lines;
          std::string line;
          bool found = false;

          while (std::getline(infile, line)) {
            // If the line doesn't contain our IP, keep it
            if (line.find(ip_to_remove) == std::string::npos) {
              lines.push_back(line);
            } else {
              found = true;
            }
          }
          infile.close();

          if (found) {
            std::ofstream outfile(BLACKLIST_FILE,
                                  std::ios::trunc); // Overwrite mode
            for (const auto &l : lines) {
              outfile << l << "\n";
            }
            outfile.close();
            std::cout << "[-] Manually unblocked and removed from CSV: "
                      << ip_to_remove << std::endl;
          } else {
            std::cout << "[-] Manually unblocked " << ip_to_remove
                      << " (not found in CSV)." << std::endl;
          }
        }
        return 0;
      }
    }

    // --- PHASE 3: ENGINE STARTUP ---
    std::string myIP = get_interface_ip(interface);
    CaptureEngine engine(interface, tracker);
    if (!engine.init())
      return 1;

    std::thread worker(nitro_watchdog, std::ref(tracker), std::ref(guard),
                       myIP, mode_str);

    engine.start();
    std::cin.get();

    keep_running = false;
    engine.stop();
    worker.join();
    tracker.print_summary();

  } catch (const std::exception &e) {
    std::cerr << "Critical Error: " << e.what() << std::endl;
  }
  return 0;
}