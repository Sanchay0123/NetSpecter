#pragma once

#include <string>
#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>

struct TelemetryEvent {
    std::string timestamp;
    std::string ip;
    std::string attack_type;
    float entropy;
    std::vector<unsigned char> payload;
};

class TelemetryExporter {
public:
    TelemetryExporter(const std::string& filepath = "telemetry.json");
    ~TelemetryExporter();

    void log_event(const std::string& ip, const std::string& attack_type, 
                   float entropy, const unsigned char* payload_ptr, uint32_t payload_len);

private:
    void worker_loop();
    std::string base64_encode(const std::vector<unsigned char>& data);

    std::string filepath_;
    std::queue<TelemetryEvent> queue_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::thread worker_;
    std::atomic<bool> running_;
};
