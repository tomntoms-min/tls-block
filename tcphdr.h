#pragma once

#include <netinet/in.h>

#pragma pack(push, 1)

struct TcpHdr final
{
    uint16_t th_sport;       /* source port */
    uint16_t th_dport;       /* destination port */
    uint32_t th_seq;          /* sequence number */
    uint32_t th_ack;          /* acknowledgement number */

    uint8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */

    uint8_t  th_flags;       /* control flags */

    uint16_t th_win;         /* window */
    uint16_t th_sum;         /* checksum */
    uint16_t th_urp;         /* urgent pointer */

    enum: u_int8_t {
        FIN = 0x01,
        SYN = 0x02,
        RST = 0x04,
        PSH = 0x08,
        ACK = 0x10,
        URG = 0x20
    };
};

#pragma pack(pop)
