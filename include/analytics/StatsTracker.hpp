#ifndef STATS_TRACKER_HPP
#define STATS_TRACKER_HPP

#include <string>
#include <map>
#include <mutex>
#include <atomic>
#include <cstdint>
#include <vector>

struct IPFlowStats {
    uint64_t total_bytes;
    uint32_t total_packets;
    uint32_t last_packet_count;
    uint32_t last_pps;
    bool is_blocked;
};

class StatsTracker {
public:
    StatsTracker() = default;

    void addPacket(const std::string& protocol, uint32_t size);
    void update(const std::string& ip_key, uint32_t size);
    
    // Nitro Logic: Calculate PPS and find threats
    void calculate_metrics();
    std::map<std::string, IPFlowStats> get_snapshot();
    std::vector<std::string> detect_threats(uint32_t threshold_pps);
    void mark_as_blocked(const std::string& ip);

    void print_summary() const;

private:
    std::atomic<uint64_t> total_bytes_{0};
    std::atomic<uint64_t> tcp_count_{0};
    std::atomic<uint64_t> udp_count_{0};
    std::atomic<uint64_t> other_count_{0};

    std::map<std::string, IPFlowStats> flow_data_;
    mutable std::mutex flow_mutex_;
};

#endif