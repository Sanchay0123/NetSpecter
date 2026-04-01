#include "analytics/StatsTracker.hpp"
#include <iostream>
#include <algorithm>

void StatsTracker::addPacket(const std::string& protocol, uint32_t size) {
    // Atomic fetch_add is significantly faster than a Mutex Lock
    total_bytes_.fetch_add(size, std::memory_order_relaxed);

    if (protocol == "TCP") {
        tcp_count_.fetch_add(1, std::memory_order_relaxed);
    } else if (protocol == "UDP") {
        udp_count_.fetch_add(1, std::memory_order_relaxed);
    } else {
        other_count_.fetch_add(1, std::memory_order_relaxed);
    }
}

void StatsTracker::update(const std::string& flow_key, uint32_t size) {
    std::lock_guard<std::mutex> lock(flow_mutex_);
    flow_data_[flow_key] += size;
}

void StatsTracker::print_summary() const {
    // We don't need a lock here because we are reading atomics
    uint64_t total = total_bytes_.load(std::memory_order_relaxed);
    uint64_t tcp = tcp_count_.load(std::memory_order_relaxed);
    uint64_t udp = udp_count_.load(std::memory_order_relaxed);
    uint64_t other = other_count_.load(std::memory_order_relaxed);

    std::cout << "\n========== NetSpecter Nitro Summary ==========" << std::endl;
    std::cout << "Total Data Captured: " << total << " bytes" << std::endl;
    std::cout << "Protocol Breakdown:" << std::endl;
    std::cout << "  - TCP:   " << tcp << " packets" << std::endl;
    std::cout << "  - UDP:   " << udp << " packets" << std::endl;
    std::cout << "  - Other: " << other << " packets" << std::endl;
    std::cout << "================================================" << std::endl;
}

void StatsTracker::print_top_talkers(int limit) {
    std::lock_guard<std::mutex> lock(flow_mutex_);
    std::vector<std::pair<std::string, uint64_t>> talkers(flow_data_.begin(), flow_data_.end());
    
    std::sort(talkers.begin(), talkers.end(), [](auto& a, auto& b) {
        return a.second > b.second;
    });

    std::cout << "\n--- Top Talkers ---" << std::endl;
    for (int i = 0; i < std::min((int)talkers.size(), limit); ++i) {
        std::cout << talkers[i].first << ": " << talkers[i].second << " bytes" << std::endl;
    }
}