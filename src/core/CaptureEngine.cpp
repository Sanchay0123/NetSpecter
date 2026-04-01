#include "core/CaptureEngine.hpp"
#include "protocol/Dissector.hpp"
#include <iostream>

CaptureEngine::CaptureEngine(const std::string& interface, StatsTracker& tracker) 
    : interface_(interface), handle_(nullptr), running_(false), tracker_(tracker) {}

CaptureEngine::~CaptureEngine() { stop(); }

bool CaptureEngine::init() {
    handle_ = pcap_create(interface_.c_str(), errbuf_);
    if (!handle_) return false;

    pcap_set_snaplen(handle_, 65535);
    pcap_set_promisc(handle_, 1);
    pcap_set_buffer_size(handle_, 2 * 1024 * 1024);
    pcap_set_immediate_mode(handle_, 1);

    return pcap_activate(handle_) == 0;
}

void CaptureEngine::start() {
    if (running_) return;
    running_ = true;
    capture_thread_ = std::thread([this]() {
        pcap_loop(handle_, 0, CaptureEngine::packet_handler, reinterpret_cast<u_char*>(this));
    });
}

void CaptureEngine::stop() {
    if (running_) {
        running_ = false;
        if (handle_) pcap_breakloop(handle_);
        if (capture_thread_.joinable()) capture_thread_.join();
    }
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

void CaptureEngine::packet_handler(u_char* user, const struct pcap_pkthdr* h, const u_char* bytes) {
    auto* engine = reinterpret_cast<CaptureEngine*>(user);
    if (engine && engine->running_) {
        // Pass the tracker reference from the engine to the dissector
        Dissector::parse(h, bytes, engine->tracker_);
    }
}