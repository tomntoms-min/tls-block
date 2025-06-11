#pragma once
#include <cstdint>

// TLS 레코드의 필수적인 앞부분에 쉽게 접근하기 위한 구조체
#pragma pack(push, 1)
struct Tls {
    uint8_t tls_content;   // 22 (0x16) for Handshake
    uint16_t tls_version;  // e.g., 0x0303 for TLS 1.2
    uint16_t tls_length;   // 뒤따르는 데이터의 길이 (Network Byte Order)
    uint8_t handshake_type; // 1 (0x01) for Client Hello
};
#pragma pack(pop)
