#pragma once

#include <cstdint>

#pragma pack(push, 1)

// TLS Record Protocol
struct TlsHdr {
    uint8_t  content_type_;
    uint16_t version_;
    uint16_t length_;

    enum : uint8_t {
        Handshake = 22,
    };
};

// TLS Handshake Protocol
struct HandshakeHdr {
    uint8_t  handshake_type_;
    uint8_t  length_[3]; // 24-bit length
};

#pragma pack(pop)
