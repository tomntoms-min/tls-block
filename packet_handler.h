#pragma once

#include <pcap.h>
#include <string>
#include <map>
#include <vector>
#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"
#include "mac.h"
#include "ip.h"

// TCP 흐름을 식별하기 위한 4-tuple 구조체
struct Flow {
    Ip src_ip;
    Ip dst_ip;
    uint16_t src_port;
    uint16_t dst_port;

    bool operator<(const Flow& other) const;
};

// 조각화된 TCP 스트림의 상태를 저장하는 구조체
struct Stream {
    std::vector<uint8_t> data;
    EthHdr eth_hdr;
    IpHdr ip_hdr;
    TcpHdr tcp_hdr;
};

class PacketHandler {
public:
    PacketHandler(pcap_t* handle, std::string iface, Mac my_mac, Ip my_ip, std::string server_name);
    void handlePacket(const struct pcap_pkthdr* header, const uint8_t* packet);

private:
    pcap_t* pcap_handle_;
    std::string interface_name_;
    Mac my_mac_;
    Ip my_ip_;
    std::string target_server_name_;
    std::map<Flow, Stream> active_streams_;

    // 함수 시그니처 수정
    bool findSNIAndBlock(const EthHdr& eth_hdr, const IpHdr& ip_hdr, const TcpHdr& tcp_hdr, const uint8_t* tls_data, size_t tls_len);
    void sendForwardRst(const EthHdr& eth_hdr, const IpHdr& ip_hdr, const TcpHdr& tcp_hdr, size_t payload_len);
    void sendBackwardRst(const IpHdr& ip_hdr, const TcpHdr& tcp_hdr, size_t payload_len);
    
    static uint16_t calculateIpChecksum(IpHdr* ip_hdr);
    static uint16_t calculateTcpChecksum(IpHdr* ip_hdr, TcpHdr* tcp_hdr, const uint8_t* data, size_t data_len);
};
