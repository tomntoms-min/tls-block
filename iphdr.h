#pragma once
#include <cstdint>
#include <arpa/inet.h>
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final {
    uint8_t ip_len:4;
    uint8_t ip_v:4;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint8_t frag_offset_1:5;
    uint8_t more_fragment:1;
    uint8_t dont_fragment:1;
    uint8_t reserved_zero:1;
    uint8_t frag_offset_2;
    uint8_t ttl;
    uint8_t proto;
    uint16_t check;
    Ip sip_; // 타입이 Ip 객체임
    Ip dip_; // 타입이 Ip 객체임

    // [수정 1] const 추가
    // [수정 2] Ip 객체이므로 ntohl 불필요, 그대로 반환
    Ip sip() const { return sip_; }
	Ip dip() const { return dip_; }

    // [추가] 헤더 길이를 반환하는 함수 (ip_len * 4)
    uint8_t ipHdrLen() const { return ip_len * 4; }

    // enum은 그대로 유지
    enum: uint8_t {
        ICMP = 1,
        TCP = 6,
        UDP = 17,
    };
};
#pragma pack(pop)
