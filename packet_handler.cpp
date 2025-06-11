#include "packet_handler.h"
#include <iostream>
#include <cstring>
#include <vector>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

// '새로운 정답 코드'의 강력한 체크섬 계산 방식을 도입합니다.
uint16_t PacketHandler::calculateChecksum(uint16_t *buf, int nbytes) {
    unsigned long sum = 0;
    while (nbytes > 1) {
        sum += *buf++;
        nbytes -= 2;
    }
    if (nbytes) {
        sum += *(uint8_t*)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

PacketHandler::PacketHandler(pcap_t* handle, uint8_t* my_mac, std::string server_name)
    : pcap_handle_(handle), target_server_name_(server_name) {
    memcpy(my_mac_, my_mac, 6);
}

void PacketHandler::handlePacket(const struct pcap_pkthdr* header, const uint8_t* packet) {
    (void)header;
    const struct ether_header* eth_hdr = reinterpret_cast<const struct ether_header*>(packet);
    if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) return;

    const struct ip* ip_hdr = reinterpret_cast<const struct ip*>(packet + sizeof(struct ether_header));
    if (ip_hdr->ip_p != IPPROTO_TCP) return;

    int ip_hdr_len = ip_hdr->ip_hl * 4;
    const struct tcphdr* tcp_hdr = reinterpret_cast<const struct tcphdr*>(reinterpret_cast<const uint8_t*>(ip_hdr) + ip_hdr_len);
    int tcp_hdr_len = tcp_hdr->th_off * 4;

    const uint8_t* payload = reinterpret_cast<const uint8_t*>(tcp_hdr) + tcp_hdr_len;
    int payload_len = ntohs(ip_hdr->ip_len) - ip_hdr_len - tcp_hdr_len;

    if (payload_len <= 5 || payload[0] != 0x16) return;

    std::string hostname = parseSNI(payload, payload_len);

    if (!hostname.empty() && hostname.find(target_server_name_) != std::string::npos) {
         std::cout << "Target found in SNI: " << hostname << " -> Blocking!" << std::endl;
        sendForwardRst(packet, ip_hdr, tcp_hdr, payload_len);
        sendBackwardRst(ip_hdr, tcp_hdr, payload_len);
    }
}

std::string PacketHandler::parseSNI(const uint8_t* payload, int len) {
    if (len < 9 || payload[5] != 0x01) return ""; 
    
    int offset = 5 + 4; 
    offset += 2 + 32;
    
    if (offset >= len) return "";
    uint8_t session_id_len = payload[offset];
    offset += 1 + session_id_len;

    if (offset + 2 > len) return "";
    uint16_t cipher_suites_len = ntohs(*(uint16_t*)(payload + offset));
    offset += 2 + cipher_suites_len;

    if (offset + 1 > len) return "";
    uint8_t comp_len = payload[offset];
    offset += 1 + comp_len;

    if (offset + 2 > len) return "";
    uint16_t ext_total_len = ntohs(*(uint16_t*)(payload + offset));
    offset += 2;

    const uint8_t* p = payload + offset;
    const uint8_t* end = p + ext_total_len;
    if (end > payload + len) end = payload + len;

    while (p + 4 <= end) {
        uint16_t ext_type = ntohs(*(uint16_t*)p);
        uint16_t ext_len = ntohs(*(uint16_t*)(p + 2));
        p += 4;
        if (p + ext_len > end) break;
        
        if (ext_type == 0x0000) { 
            if (ext_len < 5) break;
            uint16_t name_len = ntohs(*(uint16_t*)(p + 3));
            if (p + 5 + name_len > end) break;
            return std::string((char*)(p + 5), name_len);
        }
        p += ext_len;
    }
    return "";
}

void PacketHandler::sendForwardRst(const uint8_t* orig_packet, const struct ip* ip_hdr, const struct tcphdr* tcp_hdr, int payload_len) {
    int eth_sz = sizeof(struct ether_header);
    int ip_sz = ip_hdr->ip_hl * 4;
    int tcp_sz = tcp_hdr->th_off * 4;
    int total_hdr_sz = eth_sz + ip_sz + tcp_sz;
    
    std::vector<uint8_t> packet(total_hdr_sz);
    memcpy(packet.data(), orig_packet, total_hdr_sz);

    struct ether_header* eth = reinterpret_cast<struct ether_header*>(packet.data());
    memcpy(eth->ether_shost, my_mac_, 6);

    struct ip* new_ip = reinterpret_cast<struct ip*>(packet.data() + eth_sz);
    new_ip->ip_len = htons(ip_sz + tcp_sz);
    new_ip->ip_sum = 0;
    new_ip->ip_sum = htons(calculateChecksum(reinterpret_cast<uint16_t*>(new_ip), ip_sz));

    struct tcphdr* new_tcp = reinterpret_cast<struct tcphdr*>(packet.data() + eth_sz + ip_sz);
    new_tcp->th_seq = htonl(ntohl(tcp_hdr->th_seq) + payload_len);
    new_tcp->th_flags = TH_RST | TH_ACK;
    new_tcp->th_sum = 0;

    int pseudo_hdr_sz = 12 + tcp_sz;
    std::vector<uint8_t> pseudo_packet(pseudo_hdr_sz);
    memcpy(pseudo_packet.data(), &new_ip->ip_src, 8);
    pseudo_packet[8] = 0;
    pseudo_packet[9] = IPPROTO_TCP;
    uint16_t tcp_len_n = htons(tcp_sz);
    memcpy(pseudo_packet.data() + 10, &tcp_len_n, 2);
    memcpy(pseudo_packet.data() + 12, new_tcp, tcp_sz);
    new_tcp->th_sum = htons(calculateChecksum(reinterpret_cast<uint16_t*>(pseudo_packet.data()), pseudo_hdr_sz));
    
    if (pcap_sendpacket(pcap_handle_, packet.data(), total_hdr_sz) != 0) {
        fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(pcap_handle_));
    }
}

void PacketHandler::sendBackwardRst(const struct ip* ip_hdr, const struct tcphdr* tcp_hdr, int payload_len) {
    int ip_sz = sizeof(struct ip);
    int tcp_sz = sizeof(struct tcphdr);
    int total_sz = ip_sz + tcp_sz;

    std::vector<uint8_t> packet(total_sz, 0);

    struct ip* new_ip = reinterpret_cast<struct ip*>(packet.data());
    new_ip->ip_v = 4;
    new_ip->ip_hl = ip_sz / 4;
    new_ip->ip_len = htons(total_sz);
    new_ip->ip_ttl = 128;
    new_ip->ip_p = IPPROTO_TCP;
    new_ip->ip_src = ip_hdr->ip_dst;
    new_ip->ip_dst = ip_hdr->ip_src;
    new_ip->ip_sum = 0;
    new_ip->ip_sum = htons(calculateChecksum(reinterpret_cast<uint16_t*>(new_ip), ip_sz));

    struct tcphdr* new_tcp = reinterpret_cast<struct tcphdr*>(packet.data() + ip_sz);
    new_tcp->th_sport = tcp_hdr->th_dport;
    new_tcp->th_dport = tcp_hdr->th_sport;
    new_tcp->th_seq = tcp_hdr->th_ack;
    new_tcp->th_ack = htonl(ntohl(tcp_hdr->th_seq) + payload_len);
    new_tcp->th_off = tcp_sz / 4;
    new_tcp->th_flags = TH_RST | TH_ACK;
    new_tcp->th_win = htons(60000);
    new_tcp->th_sum = 0;

    int pseudo_hdr_sz = 12 + tcp_sz;
    std::vector<uint8_t> pseudo_packet(pseudo_hdr_sz);
    memcpy(pseudo_packet.data(), &new_ip->ip_src, 8);
    pseudo_packet[8] = 0;
    pseudo_packet[9] = IPPROTO_TCP;
    uint16_t tcp_len_n = htons(tcp_sz);
    memcpy(pseudo_packet.data() + 10, &tcp_len_n, 2);
    memcpy(pseudo_packet.data() + 12, new_tcp, tcp_sz);
    new_tcp->th_sum = htons(calculateChecksum(reinterpret_cast<uint16_t*>(pseudo_packet.data()), pseudo_hdr_sz));

    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sd < 0) {
        perror("socket");
        return;
    }
    int on = 1;
    setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = new_tcp->th_dport;
    addr.sin_addr = new_ip->ip_dst;

    if (sendto(sd, packet.data(), total_sz, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("sendto");
    }
    close(sd);
}
