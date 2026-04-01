#include "protocol/Dissector.hpp"
#include "analytics/StatsTracker.hpp"
#include <iostream>
#include <iomanip>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

// Helper to format MAC addresses
std::string mac_to_string(const u_char* addr) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    return std::string(buf);
}

void Dissector::parse(const struct pcap_pkthdr* h, const u_char* bytes, StatsTracker& tracker) {
    // 1. Extract Ethernet Header
    struct ethhdr* eth = (struct ethhdr*)bytes;
    
    std::string src_mac = mac_to_string(eth->h_source);
    std::string dst_mac = mac_to_string(eth->h_dest);

    // 2. Filter for IPv4 Packets
    if (ntohs(eth->h_proto) == ETH_P_IP) {
        struct iphdr* ip = (struct iphdr*)(bytes + sizeof(struct ethhdr));
        
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip->saddr), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip->daddr), dst_ip, INET_ADDRSTRLEN);

        std::string proto = "Unknown";
        uint16_t sp = 0, dp = 0;

        int ip_header_len = ip->ihl * 4;
        const u_char* l4_header = bytes + sizeof(struct ethhdr) + ip_header_len;

        if (ip->protocol == IPPROTO_TCP) {
            proto = "TCP";
            struct tcphdr* tcp = (struct tcphdr*)l4_header;
            sp = ntohs(tcp->source);
            dp = ntohs(tcp->dest);
        } else if (ip->protocol == IPPROTO_UDP) {
            proto = "UDP";
            struct udphdr* udp = (struct udphdr*)l4_header;
            sp = ntohs(udp->source);
            dp = ntohs(udp->dest);
        }

        tracker.addPacket(proto, h->len);

        // 3. New Detailed Output: [MAC] -> [IP:Port]
        printf("[%s] %s -> %s | %s:%d -> %s:%d (%d bytes)\n", 
               proto.c_str(), 
               src_mac.c_str(), dst_mac.c_str(),
               src_ip, sp, dst_ip, dp, h->len);
    }
}