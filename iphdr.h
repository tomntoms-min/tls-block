#pragma once

#include <netinet/in.h>
#include "ip.h"

#pragma pack(push, 1)

struct IpHdr final {
    uint8_t version_and_ihl;
    uint8_t dscp_and_ecn;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_and_fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t sip_;
    uint32_t dip_;

    // const 키워드를 추가하여 const 객체에서도 호출 가능하도록 수정
    Ip sip() const { return Ip(ntohl(sip_)); }
    Ip dip() const { return Ip(ntohl(dip_)); }

    // Protocol(ip_protocol)
    enum: uint8_t {
        ICMP = 1,
        IGMP = 2,
        TCP = 6,
        IGRP = 9,
        UDP = 17,
        GRE = 47,
        ESP = 50,
        AH = 51,
        SKIP = 57,
        EIGRP = 88,
        OSPF = 89,
        L2TP = 115
    };
};

#pragma pack(pop)
