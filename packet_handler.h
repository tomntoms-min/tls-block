#pragma once

#include <pcap.h>
#include <string>
#include <vector>
#include <cstdint>

// 시스템 표준 헤더를 사용합니다.
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

class PacketHandler {
public:
    // 생성자에서 더 이상 Ip 클래스를 받지 않습니다.
    PacketHandler(pcap_t* handle, uint8_t* my_mac, std::string server_name);
    void handlePacket(const struct pcap_pkthdr* header, const uint8_t* packet);

private:
    pcap_t* pcap_handle_;
    uint8_t my_mac_[6];
    std::string target_server_name_;
    
    // SNI 파싱 함수
    std::string parseSNI(const uint8_t* payload, int len);

    // 패킷 전송 함수
    void sendForwardRst(const uint8_t* orig_packet, const struct ip* ip_hdr, const struct tcphdr* tcp_hdr, int payload_len);
    void sendBackwardRst(const struct ip* ip_hdr, const struct tcphdr* tcp_hdr, int payload_len);

    // 체크섬 계산 함수
    uint16_t calculateChecksum(uint16_t *buf, int nbytes);
};
