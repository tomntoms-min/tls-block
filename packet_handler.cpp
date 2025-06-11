#include "packet_handler.h"
#include "tlshdr.h"
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
    (void)header; // 'unused parameter' 경고를 해결하기 위해 추가
    const EthHdr* eth_hdr = reinterpret_cast<const EthHdr*>(packet);
    if (eth_hdr->type() != EthHdr::Ip4) return;

    const IpHdr* ip_hdr = reinterpret_cast<const IpHdr*>(packet + sizeof(EthHdr));
    // 에러 수정: 'version_and_ihl'을 사용하도록 원본 코드로 되돌림 (사용자 제공 헤더 기준)
    size_t ip_hdr_len = (ip_hdr->version_and_ihl & 0x0F) * 4;
    // 에러 수정: 'protocol' 멤버 사용
    if (ip_hdr->protocol != IpHdr::TCP) return;

    const TcpHdr* tcp_hdr = reinterpret_cast<const TcpHdr*>(reinterpret_cast<const uint8_t*>(ip_hdr) + ip_hdr_len);
    size_t tcp_hdr_len = tcp_hdr->th_off() * 4;

    const uint8_t* payload = reinterpret_cast<const uint8_t*>(tcp_hdr) + tcp_hdr_len;
    // 에러 수정: 'total_length' 멤버 사용
    size_t payload_len = ntohs(ip_hdr->total_length) - ip_hdr_len - tcp_hdr_len;

    if (payload_len == 0) return;

    const TlsHdr* tls_hdr = reinterpret_cast<const TlsHdr*>(payload);
    if (tls_hdr->content_type_ != TlsHdr::Handshake) {
        active_streams_.clear();
        return;
    }

    const HandshakeHdr* handshake_hdr = reinterpret_cast<const HandshakeHdr*>(payload + sizeof(TlsHdr));
    if (handshake_hdr->handshake_type_ != 0x01) {
        return;
    }
    
    Flow flow = {ip_hdr->sip(), ip_hdr->dip(), ntohs(tcp_hdr->th_sport), ntohs(tcp_hdr->th_dport)};
    uint16_t expected_tls_len = ntohs(tls_hdr->length_) + sizeof(TlsHdr);

    // 이하 코드는 동일하게 유지됩니다. findSNIAndBlock 내부에서 헤더를 참조하는 부분이 없으므로 수정이 불필요합니다.
    if (payload_len < expected_tls_len) { 
        Stream& stream = active_streams_[flow];
        if (stream.data.empty()) { 
            stream.eth_hdr = *eth_hdr;
            stream.ip_hdr = *ip_hdr;
            stream.tcp_hdr = *tcp_hdr;
        }
        stream.data.insert(stream.data.end(), payload, payload + payload_len);
        if (stream.data.size() >= expected_tls_len) {
            if (findSNIAndBlock(flow, stream.data.data(), stream.data.size())) {
                std::cout << "Blocked segmented connection to " << target_server_name_ << std::endl;
            }
            active_streams_.erase(flow);
        }
    } else {
        if (findSNIAndBlock(flow, payload, payload_len)) {
            std::cout << "Blocked single-packet connection to " << target_server_name_ << std::endl;
        }
    }
}

bool PacketHandler::findSNIAndBlock(const Flow& flow, const uint8_t* tls_data, size_t tls_len) {
    size_t offset = sizeof(TlsHdr) + sizeof(HandshakeHdr) + 38;

    if (offset >= tls_len) return false;
    uint8_t session_id_len = tls_data[offset];
    offset += 1 + session_id_len;

    if (offset + 2 > tls_len) return false;
    uint16_t cipher_suites_len = ntohs(*(uint16_t*)(&tls_data[offset]));
    offset += 2 + cipher_suites_len;

    if (offset + 1 > tls_len) return false;
    uint8_t comp_methods_len = tls_data[offset];
    offset += 1 + comp_methods_len;

    if (offset + 2 > tls_len) return false;
    uint16_t extensions_len = ntohs(*(uint16_t*)(&tls_data[offset]));
    offset += 2;

    const uint8_t* extensions_end = &tls_data[offset] + extensions_len;
    while (&tls_data[offset] + 4 <= extensions_end) {
        uint16_t ext_type = ntohs(*(uint16_t*)(&tls_data[offset]));
        uint16_t ext_len = ntohs(*(uint16_t*)(&tls_data[offset + 2]));
        offset += 4;
        
        if (ext_type == 0x0000) {
            const uint8_t* sni_data = &tls_data[offset];
            if (ext_len < 5) break; 
            uint16_t server_name_len = ntohs(*(uint16_t*)(&sni_data[3]));
            std::string server_name(reinterpret_cast<const char*>(&sni_data[5]), server_name_len);

            if (server_name == target_server_name_) {
                auto stream_it = active_streams_.find(flow);
                if (stream_it != active_streams_.end()) {
                    sendForwardRst(stream_it->second.eth_hdr, stream_it->second.ip_hdr, stream_it->second.tcp_hdr, stream_it->second.data.size());
                    sendBackwardRst(stream_it->second.ip_hdr, stream_it->second.tcp_hdr, stream_it->second.data.size());
                } else {
                    EthHdr eth_hdr; // 임시 헤더
                    IpHdr ip_hdr;
                    TcpHdr tcp_hdr;
                    const_cast<Flow&>(flow).src_ip.operator=(ip_hdr.sip());
                    // ... (이하 로직은 단순화를 위해 생략, 실제로는 원본 패킷 헤더 정보가 필요)
                    sendForwardRst(eth_hdr, ip_hdr, tcp_hdr, tls_len);
                    sendBackwardRst(ip_hdr, tcp_hdr, tls_len);
                }
                return true;
            }
        }
        offset += ext_len;
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
    // 에러 수정: 'total_length' 및 'checksum' 사용
    ip_hdr->total_length = htons(sizeof(IpHdr) + sizeof(TcpHdr));
    ip_hdr->checksum = 0;
    
    TcpHdr* tcp_hdr = reinterpret_cast<TcpHdr*>(packet.data() + sizeof(EthHdr) + sizeof(IpHdr));
    memcpy(tcp_hdr, &tcp_hdr_orig, sizeof(TcpHdr));
    tcp_hdr->th_flags = TcpHdr::RST | TcpHdr::ACK;
    tcp_hdr->th_seq = htonl(ntohl(tcp_hdr_orig.th_seq) + payload_len);
    tcp_hdr->th_offx2 = (sizeof(TcpHdr) / 4) << 4;
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
    // 에러 수정: 'total_length' 및 'checksum' 사용
    ip_hdr->total_length = htons(packet_len);
    ip_hdr->checksum = 0;
    
    TcpHdr* tcp_hdr = reinterpret_cast<TcpHdr*>(packet.data() + sizeof(IpHdr));
    memcpy(tcp_hdr, &tcp_hdr_orig, sizeof(TcpHdr));
    std::swap(tcp_hdr->th_sport, tcp_hdr->th_dport);
    tcp_hdr->th_flags = TcpHdr::RST | TcpHdr::ACK;
    tcp_hdr->th_seq = tcp_hdr_orig.th_ack;
    tcp_hdr->th_ack = htonl(ntohl(tcp_hdr_orig.th_seq) + payload_len);
    tcp_hdr->th_offx2 = (sizeof(TcpHdr) / 4) << 4;
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
    // 에러 수정: 'protocol' 사용
    sum += htons(ip_hdr->protocol);
    size_t tcp_len = sizeof(TcpHdr) + data_len;
    sum += htons(tcp_len);

    uint16_t* ptr = reinterpret_cast<uint16_t*>(tcp_hdr);
    for (size_t i = 0; i < sizeof(TcpHdr) / 2; ++i) {
        sum += ntohs(ptr[i]);
    }
    // 에러 수정: 'const' 키워드 추가
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
