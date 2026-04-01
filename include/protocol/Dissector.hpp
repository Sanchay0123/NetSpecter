#ifndef DISSECTOR_HPP
#define DISSECTOR_HPP

#include <pcap.h>

// Forward declaration
class StatsTracker;

class Dissector {
public:
    static void parse(const struct pcap_pkthdr* h, const u_char* bytes, StatsTracker& tracker);
};

#endif