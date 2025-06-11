#include "packet_handler.h"
#include <iostream>
#include <cstring>
#include <vector>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <algorithm>

// Flow 구조체의 비교 연산자 구현
bool Flow::operator<(const Flow& other) const {
    if (src_ip != other.src_ip) return src_ip < other.src_ip;
    if (dst_ip != other.dst_ip) return dst_ip < other.dst_ip;
    if (src_port != other.src_port) return src_port < other.src_port;
    return dst_port < other.dst_port;
}

// PacketHandler 생성자
PacketHandler::PacketHandler(pcap_t* handle, HostInfo my_host, std::string server_name)
    : pcap_handle_(handle), my_host_(my_host), target_server_name_(server_name) {}

// IP 헤더 체크섬 계산
uint16_t PacketHandler::calculateIpChecksum(IpHdr* ip_hdr) {
    uint32_t sum = 0;
    uint16_t* ptr = reinterpret_cast<uint16_t*>(ip_hdr);
    ip_hdr->checksum = 0; // 계산 전 체크섬 필드를 0으로 설정
    for (size_t i = 0; i < (sizeof(IpHdr) / 2); ++i) {
        sum += ntohs(ptr[i]);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return htons(~static_cast<uint16_t>(sum));
}

// TCP 헤더 체크섬 계산
uint16_t PacketHandler::calculateTcpChecksum(IpHdr* ip_hdr, TcpHdr* tcp_hdr, size_t tcp_len) {
    struct PseudoHdr {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint8_t zero = 0;
        uint8_t proto;
        uint16_t len;
    } psh;

    psh.src_ip = ip_hdr->sip_;
    psh.dst_ip = ip_hdr->dip_;
    psh.proto = IpHdr::TCP;
    psh.len = htons(tcp_len);
    
    uint32_t sum = 0;
    uint16_t* p = reinterpret_cast<uint16_t*>(&psh);
    for(size_t i=0; i<sizeof(PseudoHdr)/2; i++){
        sum += ntohs(*p++);
    }

    tcp_hdr->th_sum = 0; // 계산 전 체크섬 필드를 0으로 설정
    p = reinterpret_cast<uint16_t*>(tcp_hdr);
    for(size_t i=0; i<tcp_len/2; i++){
        sum += ntohs(*p++);
    }
    if (tcp_len % 2 != 0) {
        sum += (reinterpret_cast<uint8_t*>(tcp_hdr)[tcp_len - 1] << 8);
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return htons(~static_cast<uint16_t>(sum));
}

// 패킷 처리 메인 함수
void PacketHandler::handlePacket(const struct pcap_pkthdr* header, const uint8_t* packet) {
    (void)header;
    const EthHdr* eth_hdr = reinterpret_cast<const EthHdr*>(packet);
    if (eth_hdr->type() != EthHdr::Ip4) return;

    const IpHdr* ip_hdr = reinterpret_cast<const IpHdr*>(packet + sizeof(EthHdr));
    
    size_t ip_hdr_len = (ip_hdr->version_and_ihl & 0x0F) * 4;
    if (ip_hdr->protocol != IpHdr::TCP) return;

    const TcpHdr* tcp_hdr = reinterpret_cast<const TcpHdr*>(reinterpret_cast<const uint8_t*>(ip_hdr) + ip_hdr_len);
    size_t tcp_hdr_len = tcp_hdr->th_off * 4;

    const uint8_t* payload = reinterpret_cast<const uint8_t*>(tcp_hdr) + tcp_hdr_len;
    size_t payload_len = ntohs(ip_hdr->total_length) - ip_hdr_len - tcp_hdr_len;

    if (payload_len == 0) return;

    PacketInfo current_pkt_info;
    current_pkt_info.eth = *eth_hdr;
    current_pkt_info.ip = *ip_hdr;
    current_pkt_info.tcp = *tcp_hdr;
    current_pkt_info.ip_header_len = ip_hdr_len;
    current_pkt_info.tcp_header_len = tcp_hdr_len;

    if (payload_len < (sizeof(TlsHdr) + sizeof(HandshakeHdr))) return;
    const TlsHdr* tls_hdr = reinterpret_cast<const TlsHdr*>(payload);
    const HandshakeHdr* handshake_hdr = reinterpret_cast<const HandshakeHdr*>(payload + sizeof(TlsHdr));
    
    if (tls_hdr->content_type_ != TlsHdr::Handshake || handshake_hdr->handshake_type_ != 0x01) {
        return;
    }
    
    std::string hostname = parseSNI(payload, payload_len);

    if (!hostname.empty() && hostname.find(target_server_name_) != std::string::npos) {
        std::cout << "Target found in SNI: " << hostname << " -> Blocking!" << std::endl;
        sendRstPacket(current_pkt_info, payload_len);
    }
}

// SNI 파싱 함수
std::string PacketHandler::parseSNI(const uint8_t* tls_data, size_t tls_len) {
    const uint8_t* p = tls_data + sizeof(TlsHdr) + sizeof(HandshakeHdr);
    const uint8_t* end = tls_data + tls_len;

    p += 34; 

    if (p + 1 > end) return "";
    uint8_t session_id_len = *p;
    p += 1 + session_id_len;

    if (p + 2 > end) return "";
    uint16_t cipher_suites_len = ntohs(*(reinterpret_cast<const uint16_t*>(p)));
    p += 2 + cipher_suites_len;

    if (p + 1 > end) return "";
    uint8_t comp_methods_len = *p;
    p += 1 + comp_methods_len;
    
    if (p + 2 > end) return "";
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

            return std::string(reinterpret_cast<const char*>(sni_ptr + 5), server_name_len);
        }
        p += ext_len;
    }
    return "";
}

// 양방향 RST 패킷 전송 함수
void PacketHandler::sendRstPacket(const PacketInfo& pkt_info, size_t payload_len) {
    // 1. 서버로 보내는 정방향(Forward) RST
    {
        size_t tcp_hdr_len = sizeof(TcpHdr);
        size_t ip_hdr_len = sizeof(IpHdr);
        size_t eth_hdr_len = sizeof(EthHdr);
        size_t packet_len = eth_hdr_len + ip_hdr_len + tcp_hdr_len;
        
        std::vector<uint8_t> fwd_packet(packet_len);

        EthHdr* eth = reinterpret_cast<EthHdr*>(fwd_packet.data());
        *eth = pkt_info.eth;
        eth->smac_ = my_host_.mac;

        IpHdr* ip = reinterpret_cast<IpHdr*>(fwd_packet.data() + eth_hdr_len);
        *ip = pkt_info.ip;
        ip->total_length = htons(ip_hdr_len + tcp_hdr_len);
        
        TcpHdr* tcp = reinterpret_cast<TcpHdr*>(fwd_packet.data() + eth_hdr_len + ip_hdr_len);
        *tcp = pkt_info.tcp;
        tcp->th_flags = TcpHdr::RST | TcpHdr::ACK;
        tcp->th_seq = htonl(ntohl(pkt_info.tcp.th_seq) + payload_len);
        tcp->th_off = tcp_hdr_len / 4;

        ip->checksum = calculateIpChecksum(ip);
        tcp->th_sum = calculateTcpChecksum(ip, tcp, tcp_hdr_len);

        if (pcap_sendpacket(pcap_handle_, fwd_packet.data(), packet_len) != 0) {
            fprintf(stderr, "pcap_sendpacket (forward) failed: %s\n", pcap_geterr(pcap_handle_));
        }
    }

    // 2. 클라이언트로 보내는 역방향(Backward) RST
    {
        size_t tcp_hdr_len = sizeof(TcpHdr);
        size_t ip_hdr_len = sizeof(IpHdr);
        size_t packet_len = ip_hdr_len + tcp_hdr_len;

        std::vector<uint8_t> bwd_packet(packet_len);

        IpHdr* ip = reinterpret_cast<IpHdr*>(bwd_packet.data());
        *ip = pkt_info.ip;
        std::swap(ip->sip_, ip->dip_);
        ip->total_length = htons(packet_len);
        
        TcpHdr* tcp = reinterpret_cast<TcpHdr*>(bwd_packet.data() + ip_hdr_len);
        *tcp = pkt_info.tcp;
        std::swap(tcp->th_sport, tcp->th_dport);
        tcp->th_flags = TcpHdr::RST | TcpHdr::ACK;
        tcp->th_seq = htonl(ntohl(pkt_info.tcp.th_ack));
        tcp->th_ack = htonl(ntohl(pkt_info.tcp.th_seq) + payload_len);
        tcp->th_off = tcp_hdr_len / 4;

        ip->checksum = calculateIpChecksum(ip);
        tcp->th_sum = calculateTcpChecksum(ip, tcp, tcp_hdr_len);

        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sock < 0) {
            perror("socket() failed");
            return;
        }
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        
        struct sockaddr_in dst_addr{};
        dst_addr.sin_family = AF_INET;
        dst_addr.sin_port = tcp->th_dport;
        dst_addr.sin_addr.s_addr = ip->dip_;

        if (sendto(sock, bwd_packet.data(), packet_len, 0, (struct sockaddr*)&dst_addr, sizeof(dst_addr)) < 0) {
            perror("sendto (backward) failed");
        }
        close(sock);
    }
}
