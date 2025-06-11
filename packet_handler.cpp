#include "packet_handler.h"
#include "tlshdr.h" // 사용자께서 제공해주신 tlshdr.h를 사용합니다
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

bool Flow::operator<(const Flow& other) const {
    if (src_ip != other.src_ip) return src_ip < other.src_ip;
    if (dst_ip != other.dst_ip) return dst_ip < other.dst_ip;
    if (src_port != other.src_port) return src_port < other.src_port;
    return dst_port < other.dst_port;
}

PacketHandler::PacketHandler(pcap_t* handle, std::string iface, Mac my_mac, Ip my_ip, std::string server_name)
    : pcap_handle_(handle), interface_name_(iface), my_mac_(my_mac), my_ip_(my_ip), target_server_name_(server_name) {}

void PacketHandler::handlePacket(const struct pcap_pkthdr* header, const uint8_t* packet) {
    (void)header;
    const EthHdr* eth_hdr = reinterpret_cast<const EthHdr*>(packet);
    if (eth_hdr->type() != EthHdr::Ip4) return;

    const IpHdr* ip_hdr = reinterpret_cast<const IpHdr*>(packet + sizeof(EthHdr));
    
    size_t ip_hdr_len = (*(reinterpret_cast<const uint8_t*>(ip_hdr)) & 0x0F) * 4;
    if (ip_hdr->protocol != IpHdr::TCP) return;

    const TcpHdr* tcp_hdr = reinterpret_cast<const TcpHdr*>(reinterpret_cast<const uint8_t*>(ip_hdr) + ip_hdr_len);
    size_t tcp_hdr_len = tcp_hdr->th_off * 4;

    const uint8_t* payload = reinterpret_cast<const uint8_t*>(tcp_hdr) + tcp_hdr_len;
    size_t payload_len = ntohs(ip_hdr->total_length) - ip_hdr_len - tcp_hdr_len;

    if (payload_len < (sizeof(TlsHdr) + sizeof(HandshakeHdr))) return;
    
    const TlsHdr* tls_hdr = reinterpret_cast<const TlsHdr*>(payload);
    const HandshakeHdr* handshake_hdr = reinterpret_cast<const HandshakeHdr*>(payload + sizeof(TlsHdr));

    if (tls_hdr->content_type_ != TlsHdr::Handshake || handshake_hdr->handshake_type_ != 0x01) {
        active_streams_.clear();
        return;
    }

    Flow flow = {ip_hdr->sip(), ip_hdr->dip(), ntohs(tcp_hdr->th_sport), ntohs(tcp_hdr->th_dport)};
    uint16_t expected_tls_len = ntohs(tls_hdr->length_) + sizeof(TlsHdr);

    if (payload_len < expected_tls_len) { 
        Stream& stream = active_streams_[flow];
        if (stream.data.empty()) { 
            stream.eth_hdr = *eth_hdr;
            stream.ip_hdr = *ip_hdr;
            stream.tcp_hdr = *tcp_hdr;
        }
        stream.data.insert(stream.data.end(), payload, payload + payload_len);

        if (stream.data.size() >= expected_tls_len) {
            if (findSNIAndBlock(stream.eth_hdr, stream.ip_hdr, stream.tcp_hdr, stream.data.data(), stream.data.size())) {
                std::cout << "Blocked segmented connection to: " << target_server_name_ << std::endl;
            }
            active_streams_.erase(flow);
        }
    } else {
        if (findSNIAndBlock(*eth_hdr, *ip_hdr, *tcp_hdr, payload, payload_len)) {
            std::cout << "Blocked single-packet connection to: " << target_server_name_ << std::endl;
        }
    }
}

bool PacketHandler::findSNIAndBlock(const EthHdr& eth_hdr, const IpHdr& ip_hdr, const TcpHdr& tcp_hdr, const uint8_t* tls_data, size_t tls_len) {
    const uint8_t* p = tls_data + sizeof(TlsHdr) + sizeof(HandshakeHdr);
    const uint8_t* end = tls_data + tls_len; 

    p += 34;

    if (p + 1 > end) return false;
    uint8_t session_id_len = *p;
    p += 1 + session_id_len;

    if (p + 2 > end) return false;
    uint16_t cipher_suites_len = ntohs(*(reinterpret_cast<const uint16_t*>(p)));
    p += 2 + cipher_suites_len;

    if (p + 1 > end) return false;
    uint8_t comp_methods_len = *p;
    p += 1 + comp_methods_len;
    
    if (p + 2 > end) return false;
    uint16_t extensions_total_len = ntohs(*(reinterpret_cast<const uint16_t*>(p)));
    p += 2;
    const uint8_t* extensions_end = p + extensions_total_len;
    if (extensions_end > end) extensions_end = end;

    while (p + 4 <= extensions_end) {
        uint16_t ext_type = ntohs(*(reinterpret_cast<const uint16_t*>(p)));
        uint16_t ext_len = ntohs(*(reinterpret_cast<const uint16_t*>(p + 2)));
        p += 4;
        
        if (ext_type == 0x0000) {
            const uint8_t* sni_ptr = p;
            if (sni_ptr + 5 > extensions_end) break;

            uint16_t server_name_len = ntohs(*(reinterpret_cast<const uint16_t*>(sni_ptr + 3)));
            if (sni_ptr + 5 + server_name_len > extensions_end) break; 

            std::string server_name(reinterpret_cast<const char*>(sni_ptr + 5), server_name_len);

            if (server_name.find(target_server_name_) != std::string::npos) {
                std::cout << "Target found in SNI: " << server_name << " -> Blocking!" << std::endl;
                sendForwardRst(eth_hdr, ip_hdr, tcp_hdr, tls_len);
                sendBackwardRst(ip_hdr, tcp_hdr, tls_len);
                return true;
            }
        }
        p += ext_len;
    }
    return false;
}

void PacketHandler::sendForwardRst(const EthHdr& eth_hdr_orig, const IpHdr& ip_hdr_orig, const TcpHdr& tcp_hdr_orig, size_t payload_len) {
    const size_t packet_len = sizeof(EthHdr) + sizeof(IpHdr) + sizeof(TcpHdr);
    std::vector<uint8_t> packet(packet_len);

    EthHdr* eth_hdr = reinterpret_cast<EthHdr*>(packet.data());
    eth_hdr->dmac_ = eth_hdr_orig.dmac();
    eth_hdr->smac_ = my_mac_;
    eth_hdr->type_ = htons(EthHdr::Ip4);

    IpHdr* ip_hdr = reinterpret_cast<IpHdr*>(packet.data() + sizeof(EthHdr));
    memcpy(ip_hdr, &ip_hdr_orig, sizeof(IpHdr));
    
    ip_hdr->total_length = htons(sizeof(IpHdr) + sizeof(TcpHdr));
    ip_hdr->checksum = 0;
    
    TcpHdr* tcp_hdr = reinterpret_cast<TcpHdr*>(packet.data() + sizeof(EthHdr) + sizeof(IpHdr));
    memcpy(tcp_hdr, &tcp_hdr_orig, sizeof(TcpHdr));
    tcp_hdr->th_flags = TcpHdr::RST | TcpHdr::ACK;
    tcp_hdr->th_seq = htonl(ntohl(tcp_hdr_orig.th_seq) + payload_len);
    tcp_hdr->th_off = (sizeof(TcpHdr) / 4);
    tcp_hdr->th_sum = 0;
    
    ip_hdr->checksum = calculateIpChecksum(ip_hdr);
    tcp_hdr->th_sum = calculateTcpChecksum(ip_hdr, tcp_hdr, nullptr, 0);

    if (pcap_sendpacket(pcap_handle_, packet.data(), packet.size()) != 0) {
        std::cerr << "pcap_sendpacket (forward) failed: " << pcap_geterr(pcap_handle_) << std::endl;
    }
}

void PacketHandler::sendBackwardRst(const IpHdr& ip_hdr_orig, const TcpHdr& tcp_hdr_orig, size_t payload_len) {
    const size_t packet_len = sizeof(IpHdr) + sizeof(TcpHdr);
    std::vector<uint8_t> packet(packet_len);

    IpHdr* ip_hdr = reinterpret_cast<IpHdr*>(packet.data());
    memcpy(ip_hdr, &ip_hdr_orig, sizeof(IpHdr));
    ip_hdr->sip_ = ip_hdr_orig.dip_;
    ip_hdr->dip_ = ip_hdr_orig.sip_;
    
    ip_hdr->total_length = htons(packet_len);
    ip_hdr->checksum = 0;
    
    TcpHdr* tcp_hdr = reinterpret_cast<TcpHdr*>(packet.data() + sizeof(IpHdr));
    memcpy(tcp_hdr, &tcp_hdr_orig, sizeof(TcpHdr));
    std::swap(tcp_hdr->th_sport, tcp_hdr->th_dport);
    tcp_hdr->th_flags = TcpHdr::RST | TcpHdr::ACK;
    tcp_hdr->th_seq = tcp_hdr_orig.th_ack;
    tcp_hdr->th_ack = htonl(ntohl(tcp_hdr_orig.th_seq) + payload_len);
    tcp_hdr->th_off = (sizeof(TcpHdr) / 4);
    tcp_hdr->th_sum = 0;

    ip_hdr->checksum = calculateIpChecksum(ip_hdr);
    tcp_hdr->th_sum = calculateTcpChecksum(ip_hdr, tcp_hdr, nullptr, 0);
    
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket");
        return;
    }
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        close(sock);
        return;
    }

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    // ========================== 최종 버그 수정 라인 ==========================
    sin.sin_port = tcp_hdr->th_dport; // 목적지 포트 번호를 명시적으로 지정
    // ====================================================================
    sin.sin_addr.s_addr = ip_hdr->dip_;

    if (sendto(sock, packet.data(), packet.size(), 0, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
        perror("sendto (backward)");
    }
    close(sock);
}

uint16_t PacketHandler::calculateIpChecksum(IpHdr* ip_hdr) {
    uint32_t sum = 0;
    uint16_t* ptr = reinterpret_cast<uint16_t*>(ip_hdr);
    for (size_t i = 0; i < sizeof(IpHdr) / 2; ++i) {
        sum += ntohs(ptr[i]);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return htons(~static_cast<uint16_t>(sum));
}

uint16_t PacketHandler::calculateTcpChecksum(IpHdr* ip_hdr, TcpHdr* tcp_hdr, const uint8_t* data, size_t data_len) {
    uint32_t sum = 0;
    sum += (ntohl(ip_hdr->sip_) >> 16) & 0xFFFF;
    sum += ntohl(ip_hdr->sip_) & 0xFFFF;
    sum += (ntohl(ip_hdr->dip_) >> 16) & 0xFFFF;
    sum += ntohl(ip_hdr->dip_) & 0xFFFF;
    
    sum += htons(ip_hdr->protocol);
    size_t tcp_len = sizeof(TcpHdr) + data_len;
    sum += htons(tcp_len);

    uint16_t* ptr = reinterpret_cast<uint16_t*>(tcp_hdr);
    for (size_t i = 0; i < sizeof(TcpHdr) / 2; ++i) {
        sum += ntohs(ptr[i]);
    }
    
    const uint16_t* const_ptr = reinterpret_cast<const uint16_t*>(data);
    for (size_t i = 0; i < data_len / 2; ++i) {
        sum += ntohs(const_ptr[i]);
    }
    if (data_len % 2 != 0) {
        sum += (data[data_len - 1] << 8);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return htons(~static_cast<uint16_t>(sum));
}
