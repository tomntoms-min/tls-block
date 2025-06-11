#pragma once

#include <cstdint>
#include <arpa/inet.h>

#pragma pack(push, 1)
struct TcpHdr {
    uint16_t th_sport;
    uint16_t th_dport;
    uint32_t th_seq;
    uint32_t th_ack;
    uint8_t  th_offx2;
    uint8_t  th_flags;
    uint16_t th_win;
    uint16_t th_sum;
    uint16_t th_urp;

    uint8_t th_off() const { return (th_offx2 & 0xF0) >> 4; }

    enum: uint8_t {
        FIN = 0x01,
        SYN = 0x02,
        RST = 0x04,
        PSH = 0x08,
        ACK = 0x10,
        URG = 0x20,
    };
};
typedef TcpHdr *pTcpHdr;
#pragma pack(pop)
