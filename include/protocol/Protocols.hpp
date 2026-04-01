#ifndef PROTOCOLS_HPP
#define PROTOCOLS_HPP

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string>

struct PacketInfo {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    std::string protocol;
    uint32_t length;
};

#endif