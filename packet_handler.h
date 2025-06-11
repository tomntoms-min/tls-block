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

// Represents a 4-tuple for a TCP flow
struct Flow {
    Ip src_ip;
    Ip dst_ip;
    uint16_t src_port;
    uint16_t dst_port;

    bool operator<(const Flow& other) const;
};

// Holds state for a segmented TCP stream
struct Stream {
    std::vector<uint8_t> data;
    uint32_t next_seq{0};
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

    void parse(const uint8_t* packet);
    bool findSNIAndBlock(const Flow& flow, const uint8_t* tls_data, size_t tls_len);
    void sendForwardRst(const EthHdr& eth_hdr, const IpHdr& ip_hdr, const TcpHdr& tcp_hdr, size_t payload_len);
    void sendBackwardRst(const IpHdr& ip_hdr, const TcpHdr& tcp_hdr, size_t payload_len);
    
    static uint16_t calculateIpChecksum(IpHdr* ip_hdr);
    static uint16_t calculateTcpChecksum(IpHdr* ip_hdr, TcpHdr* tcp_hdr, const uint8_t* data, size_t data_len);
};
