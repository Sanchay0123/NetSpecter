#include "analytics/StatsTracker.hpp"
#include <iostream>
#include <algorithm>

void StatsTracker::addPacket(const std::string& protocol, uint32_t size) {
    total_bytes_.fetch_add(size, std::memory_order_relaxed);
    if (protocol == "TCP") tcp_count_.fetch_add(1, std::memory_order_relaxed);
    else if (protocol == "UDP") udp_count_.fetch_add(1, std::memory_order_relaxed);
    else other_count_.fetch_add(1, std::memory_order_relaxed);
}

void StatsTracker::update(const std::string& ip_key, uint32_t size) {
    std::lock_guard<std::mutex> lock(flow_mutex_);
    auto& stats = flow_data_[ip_key];
    stats.total_bytes += size;
    stats.total_packets++;
}

void StatsTracker::calculate_metrics() {
    std::lock_guard<std::mutex> lock(flow_mutex_);
    for (auto& [ip, data] : flow_data_) {
        // Calculate PPS based on packets seen since the last check
        data.last_pps = data.total_packets - data.last_packet_count;
        data.last_packet_count = data.total_packets;
    }
}

std::map<std::string, IPFlowStats> StatsTracker::get_snapshot() {
    std::lock_guard<std::mutex> lock(flow_mutex_);
    return flow_data_;
}

std::vector<std::string> StatsTracker::detect_threats(uint32_t threshold) {
    std::lock_guard<std::mutex> lock(flow_mutex_);
    std::vector<std::string> threats;
    for (const auto& [ip, data] : flow_data_) {
        // Check if the current PPS exceeds the threshold
        if (!data.is_blocked && data.last_pps > threshold) {
            threats.push_back(ip);
        }
    }
    return threats;
}

void StatsTracker::mark_as_blocked(const std::string& ip) {
    std::lock_guard<std::mutex> lock(flow_mutex_);
    // Force set the blocked flag in the tracking map
    flow_data_[ip].is_blocked = true;
}

void StatsTracker::print_summary() const {
    std::cout << "\n========== NetSpecter Nitro Final Summary ==========" << std::endl;
    std::cout << "Total Data: " << total_bytes_.load() << " bytes" << std::endl;
    std::cout << "TCP: " << tcp_count_.load() << " | UDP: " << udp_count_.load() << std::endl;
    std::cout << "====================================================" << std::endl;
}