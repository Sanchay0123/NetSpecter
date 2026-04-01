#ifndef STATS_TRACKER_HPP
#define STATS_TRACKER_HPP

#include <string>
#include <map>
#include <mutex>
#include <atomic>
#include <cstdint>
#include <vector>

class StatsTracker {
public:
    StatsTracker() = default;

    // Fast path: No mutex, uses Atomic operations
    void addPacket(const std::string& protocol, uint32_t size);
    
    // Slow path: Still uses mutex (called less frequently for specific flows)
    void update(const std::string& flow_key, uint32_t size);
    
    void print_top_talkers(int limit = 10);
    void print_summary() const;

private:
    // Global counters using Lock-Free Atomics
    std::atomic<uint64_t> total_bytes_{0};
    std::atomic<uint64_t> tcp_count_{0};
    std::atomic<uint64_t> udp_count_{0};
    std::atomic<uint64_t> other_count_{0};

    // Flow data still needs a mutex because maps aren't thread-safe
    std::map<std::string, uint64_t> flow_data_;
    mutable std::mutex flow_mutex_;
};

#endif