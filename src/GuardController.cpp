#include "GuardController.hpp"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <iostream>
#include <unistd.h>

GuardController::GuardController(const std::string& pinnedPath) {
    mapFd = bpf_obj_get(pinnedPath.c_str());
    if (mapFd < 0) {
        throw std::runtime_error("Guard Portal Offline: Check if map is pinned at " + pinnedPath);
    }
}

GuardController::~GuardController() {
    if (mapFd >= 0) close(mapFd);
}

bool GuardController::blockIP(const std::string& ipStr) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ipStr.c_str(), &addr) != 1) return false;

    uint32_t key = addr.s_addr;
    uint64_t value = 0;

    if (bpf_map_update_elem(mapFd, &key, &value, BPF_ANY) != 0) {
        perror("Nitro Block Error");
        return false;
    }

    std::cout << "[NITRO] Blocked: " << ipStr << std::endl;
    return true;
}

// --- THE NEW UNBLOCK LOGIC ---
bool GuardController::unblockIP(const std::string& ipStr) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ipStr.c_str(), &addr) != 1) {
        std::cerr << "[!] Invalid IP format." << std::endl;
        return false;
    }

    uint32_t key = addr.s_addr;

    // Delete from the Kernel Map
    if (bpf_map_delete_elem(mapFd, &key) != 0) {
        std::cerr << "[!] IP not found in Nitro Blacklist: " << ipStr << std::endl;
        return false;
    }

    std::cout << "[NITRO] Unblocked: " << ipStr << std::endl;
    return true;
}

void GuardController::load_from_csv(const std::string& filename) {
    std::ifstream file(filename);
    std::string ip;
    if (!file.is_open()) return;

    std::cout << "[*] Loading Persistent Blacklist from " << filename << "..." << std::endl;
    while (std::getline(file, ip)) {
        if (!ip.empty()) {
            this->blockIP(ip); // Push to Kernel Map immediately
        }
    }
}

bool GuardController::blockIP_and_save(const std::string& ip, const std::string& filename) {
    if (this->blockIP(ip)) {
        std::ofstream file(filename, std::ios::app); // Append mode
        if (file.is_open()) {
            file << ip << "\n";
            return true;
        }
    }
    return false;
}