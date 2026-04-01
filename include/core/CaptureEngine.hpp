#ifndef CAPTURE_ENGINE_HPP
#define CAPTURE_ENGINE_HPP

#include <string>
#include <pcap.h>
#include <thread>
#include <atomic>
#include "analytics/StatsTracker.hpp"

class CaptureEngine {
public:
    CaptureEngine(const std::string& interface, StatsTracker& tracker);
    ~CaptureEngine();

    bool init();
    void start();
    void stop();

private:
    static void packet_handler(u_char* user, const struct pcap_pkthdr* h, const u_char* bytes);

    std::string interface_;
    pcap_t* handle_;
    char errbuf_[PCAP_ERRBUF_SIZE];
    std::atomic<bool> running_;
    std::thread capture_thread_;
    StatsTracker& tracker_; // Reference to our shared tracker
};

#endif