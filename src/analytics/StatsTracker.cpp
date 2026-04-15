#include "analytics/StatsTracker.hpp"
#include <iostream>
#include <algorithm>

void StatsTracker::addPacket(const std::string& protocol, uint32_t size) {
    total_bytes_.fetch_add(size, std::memory_order_relaxed);
    if (protocol == "TCP") tcp_count_.fetch_add(1, std::memory_order_relaxed);
    else if (protocol == "UDP") udp_count_.fetch_add(1, std::memory_order_relaxed);
    else other_count_.fetch_add(1, std::memory_order_relaxed);
}

void StatsTracker::update(const std::string& ip_key, uint32_t size, uint16_t dst_port, const unsigned char* payload, uint32_t payload_len) {
    std::lock_guard<std::mutex> lock(flow_mutex_);
    auto& stats = flow_data_[ip_key];
    stats.total_bytes += size;
    stats.total_packets++;

    if (dst_port != 0) {
        if (dst_port < stats.min_port) stats.min_port = dst_port;
        if (dst_port > stats.max_port) stats.max_port = dst_port;
        
        if (stats.unique_dst_ports.size() < 50) {
            if (std::find(stats.unique_dst_ports.begin(), stats.unique_dst_ports.end(), dst_port) == stats.unique_dst_ports.end()) {
                stats.unique_dst_ports.push_back(dst_port);
            }
        }
    }

    if (payload && payload_len >= 4) {
        for (uint32_t i = 0; i <= payload_len - 4; ++i) {
            // NOP sled \x90\x90\x90\x90
            if (payload[i] == 0x90 && payload[i+1] == 0x90 && payload[i+2] == 0x90 && payload[i+3] == 0x90) {
                stats.dpi_hits++;
                i += 3; // basic skip
            }
            // Basic SQLi UNION
            else if (i + 5 <= payload_len && payload[i] == 'U' && payload[i+1] == 'N' && payload[i+2] == 'I' && payload[i+3] == 'O' && payload[i+4] == 'N') {
                stats.dpi_hits++;
                i += 4; // basic skip
            }
        }
    }
}

void StatsTracker::calculate_metrics() {
    std::lock_guard<std::mutex> lock(flow_mutex_);
    for (auto& [ip, data] : flow_data_) {
        // Calculate PPS based on packets seen since the last check
        data.last_pps = data.total_packets - data.last_packet_count;
        data.last_packet_count = data.total_packets;
        
        if (data.unique_dst_ports.size() > 1) {
            data.entropy_score = static_cast<float>(data.max_port - data.min_port) / data.unique_dst_ports.size();
        } else {
            data.entropy_score = 0.0f;
        }
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

void StatsTracker::mark_as_blocked(const std::string& ip, const std::string& attack_type) {
    std::lock_guard<std::mutex> lock(flow_mutex_);
    // Force set the blocked flag in the tracking map
    flow_data_[ip].is_blocked = true;
    flow_data_[ip].attack_type = attack_type;
}

void StatsTracker::print_summary() const {
    std::cout << "\n========== NetSpecter Nitro Final Summary ==========" << std::endl;
    std::cout << "Total Data: " << total_bytes_.load() << " bytes" << std::endl;
    std::cout << "TCP: " << tcp_count_.load() << " | UDP: " << udp_count_.load() << std::endl;
    std::cout << "====================================================" << std::endl;
}