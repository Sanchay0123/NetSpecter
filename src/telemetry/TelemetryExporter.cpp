#include "telemetry/TelemetryExporter.hpp"
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>

static const std::string base64_chars = 
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";

TelemetryExporter::TelemetryExporter(const std::string& filepath) 
    : filepath_(filepath), running_(true) {
    worker_ = std::thread(&TelemetryExporter::worker_loop, this);
}

TelemetryExporter::~TelemetryExporter() {
    running_ = false;
    cv_.notify_all();
    if (worker_.joinable()) {
        worker_.join();
    }
}

void TelemetryExporter::log_event(const std::string& ip, const std::string& attack_type, 
                                  float entropy, const unsigned char* payload_ptr, uint32_t payload_len) {
    TelemetryEvent event;

    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&now_c), "%Y-%m-%dT%H:%M:%S");
    event.timestamp = ss.str();

    event.ip = ip;
    event.attack_type = attack_type;
    event.entropy = entropy;
    
    if (payload_ptr != nullptr && payload_len > 0) {
        event.payload.assign(payload_ptr, payload_ptr + payload_len);
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push(std::move(event));
    }
    cv_.notify_one();
}

std::string TelemetryExporter::base64_encode(const std::vector<unsigned char>& data) {
    std::string ret;
    int i = 0, j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    
    for (unsigned char b : data) {
        char_array_3[i++] = b;
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            for(i = 0; i < 4; i++) ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for(j = i; j < 3; j++) char_array_3[j] = '\0';
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        for (j = 0; j < i + 1; j++) ret += base64_chars[char_array_4[j]];
        while(i++ < 3) ret += '=';
    }
    return ret;
}

void TelemetryExporter::worker_loop() {
    while (running_) {
        TelemetryEvent event;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [this]{ return !queue_.empty() || !running_; });
            
            if (!running_ && queue_.empty()) {
                return;
            }
            
            event = std::move(queue_.front());
            queue_.pop();
        }

        // Processing off the fast-path
        std::string payload_b64 = base64_encode(event.payload);

        // Very basic json constructor syntax
        std::stringstream json;
        json << "{";
        json << "\"timestamp\":\"" << event.timestamp << "\",";
        json << "\"ip\":\"" << event.ip << "\",";
        json << "\"attack_type\":\"" << event.attack_type << "\",";
        json << "\"entropy\":" << event.entropy << ",";
        json << "\"payload_base64\":\"" << payload_b64 << "\"";
        json << "}\n";

        // Write directly to file
        std::ofstream outfile(filepath_, std::ios_base::app);
        if (outfile.is_open()) {
            outfile << json.str();
            outfile.close();
        }
    }
}
