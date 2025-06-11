#pragma once

#include <pcap.h>
#include <string>
#include <vector>
#include <cstdint>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

class PacketHandler {
public:
    PacketHandler(pcap_t* handle, uint8_t* my_mac, std::string server_name);
    void handlePacket(const struct pcap_pkthdr* header, const uint8_t* packet);

private:
    pcap_t* pcap_handle_;
    uint8_t my_mac_[6];
    std::string target_server_name_;
    
    // ================== 속도 최적화 2: 정적 전송 버퍼 ==================
    uint8_t send_buf_[1500];
    // ===============================================================

    std::string parseSNI(const uint8_t* payload, int len);
    void sendForwardRst(const uint8_t* orig_packet, const struct ip* ip_hdr, const struct tcphdr* tcp_hdr, int payload_len);
    void sendBackwardRst(const struct ip* ip_hdr, const struct tcphdr* tcp_hdr, int payload_len);
    uint16_t calculateChecksum(uint16_t *buf, int nbytes);
};
