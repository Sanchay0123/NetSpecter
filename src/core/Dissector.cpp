#include "protocol/Dissector.hpp"
#include "analytics/StatsTracker.hpp"
#include <iostream>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

void Dissector::parse(const struct pcap_pkthdr* h, const u_char* bytes, StatsTracker& tracker) {
    // 1. Extract Ethernet Header
    struct ethhdr* eth = (struct ethhdr*)bytes;

    // 2. Filter for IPv4 Packets
    if (ntohs(eth->h_proto) == ETH_P_IP) {
        struct iphdr* ip = (struct iphdr*)(bytes + sizeof(struct ethhdr));
        
        // Convert IP to string for the Tracker Key
        char src_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip->saddr), src_ip_str, INET_ADDRSTRLEN);
        std::string src_ip(src_ip_str);

        // Identify Protocol
        std::string proto = "Other";
        uint16_t dst_port = 0;
        const u_char* payload = nullptr;
        uint32_t payload_len = 0;

        if (ip->protocol == IPPROTO_TCP) {
            proto = "TCP";
            struct tcphdr* tcp = (struct tcphdr*)((u_char*)ip + (ip->ihl * 4));
            dst_port = ntohs(tcp->dest);
            uint32_t tcp_header_len = tcp->doff * 4;
            payload = (const u_char*)tcp + tcp_header_len;
        }
        else if (ip->protocol == IPPROTO_UDP) {
            proto = "UDP";
            struct udphdr* udp = (struct udphdr*)((u_char*)ip + (ip->ihl * 4));
            dst_port = ntohs(udp->dest);
            payload = (const u_char*)udp + 8;
        }

        if (payload != nullptr) {
            uint32_t offset = payload - bytes;
            if (offset < h->caplen) {
                payload_len = h->caplen - offset;
            } else {
                payload = nullptr;
                payload_len = 0;
            }
        }

        // --- THE NITRO ENGINE UPDATE ---
        
        // Update global atomic counters (Fast Path)
        tracker.addPacket(proto, h->len);

        // Update the per-IP Flow Map (This is what populates the Dashboard!)
        tracker.update(src_ip, h->len, dst_port, payload, payload_len);

        // --- SILENCE THE NOISE ---
        // We do NOT print to stdout here anymore. 
        // This prevents the dashboard from flickering or breaking.
    }
}