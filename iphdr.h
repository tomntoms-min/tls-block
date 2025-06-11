#pragma once
#include <cstdint>
#include <arpa/inet.h>
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final {
    // 사용자가 제공한 비트필드 구조
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
    Ip sip_;
    Ip dip_;

    // [수정 1] const 추가: 이 함수는 멤버 변수를 변경하지 않음을 명시
    // [수정 2] ntohl 제거: sip_와 dip_는 이미 호스트 바이트 순서의 Ip 객체이므로 변환 불필요
    Ip sip() const { return sip_; }
	Ip dip() const { return dip_; }

    // [추가] 가독성을 위해 IP 헤더 길이를 반환하는 헬퍼 함수 추가
    uint8_t ipHdrLen() const { return ip_len * 4; }

    // enum은 그대로 유지
    enum: uint8_t {
        ICMP = 1,
        TCP = 6,
        UDP = 17,
    };
};
#pragma pack(pop)
