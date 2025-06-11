#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <iostream>

using namespace std;

const int BUF_SIZE = 4096;

void usage() {
    cout << "Usage: ./tls-block <interface> <server name>\n";
}

uint16_t checksum(uint16_t* buf, int len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1)
        sum += *(uint8_t*)buf;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

struct PseudoHeader {
    uint32_t src;
    uint32_t dst;
    uint8_t zero = 0;
    uint8_t proto = IPPROTO_TCP;
    uint16_t len;
};

// --- TLS Client Hello 내 SNI 파싱 --- //
string get_sni_from_packet(const u_char* packet, int len) {
    const ip* ip_hdr = (ip*)(packet + sizeof(ether_header));
    int ip_hdr_len = ip_hdr->ip_hl * 4;
    const tcphdr* tcp_hdr = (tcphdr*)((u_char*)ip_hdr + ip_hdr_len);
    int tcp_hdr_len = tcp_hdr->th_off * 4;
    const u_char* payload = (u_char*)tcp_hdr + tcp_hdr_len;
    int payload_len = ntohs(ip_hdr->ip_len) - ip_hdr_len - tcp_hdr_len;

    if (payload_len < 5 || payload[0] != 0x16) return ""; // TLS Handshake
    int tls_len = (payload[3] << 8) | payload[4];
    if (tls_len + 5 > payload_len) return "";

    const u_char* handshake = payload + 5;
    if (handshake[0] != 0x01) return ""; // Client Hello
    int session_id_len_offset = 43;
    if (handshake + session_id_len_offset >= payload + payload_len) return "";

    int session_id_len = handshake[session_id_len_offset];
    int cipher_len = (handshake[session_id_len_offset + 1 + session_id_len] << 8) |
                     handshake[session_id_len_offset + 2 + session_id_len];
    int comp_method_len = handshake[session_id_len_offset + 3 + session_id_len + cipher_len];
    int ext_len_offset = session_id_len_offset + 4 + session_id_len + cipher_len + comp_method_len;
    int ext_len = (handshake[ext_len_offset] << 8) | handshake[ext_len_offset + 1];

    const u_char* ext_ptr = handshake + ext_len_offset + 2;
    const u_char* ext_end = ext_ptr + ext_len;
    while (ext_ptr + 4 <= ext_end) {
        uint16_t ext_type = (ext_ptr[0] << 8) | ext_ptr[1];
        uint16_t ext_size = (ext_ptr[2] << 8) | ext_ptr[3];
        if (ext_type == 0x00) { // server_name
            int sni_len = (ext_ptr[7] << 8) | ext_ptr[8];
            string sni((char*)(ext_ptr + 9), sni_len);
            return sni;
        }
        ext_ptr += 4 + ext_size;
    }
    return "";
}

// --- TCP 패킷 전송 함수 --- //
void inject_tcp(const ip* ip_src, const tcphdr* tcp_src, const char* data, int data_len, uint8_t flags) {
    char buf[BUF_SIZE] = {};
    ip* iph = (ip*)buf;
    tcphdr* tcph = (tcphdr*)(buf + sizeof(ip));
    char* payload = buf + sizeof(ip) + sizeof(tcphdr);

    if (data && data_len > 0)
        memcpy(payload, data, data_len);

    iph->ip_v = 4;
    iph->ip_hl = 5;
    iph->ip_ttl = 64;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_len = htons(sizeof(ip) + sizeof(tcphdr) + data_len);
    iph->ip_off = 0;
    iph->ip_id = htons(12345);

    iph->ip_src = (flags & TH_RST) ? ip_src->ip_src : ip_src->ip_dst;
    iph->ip_dst = (flags & TH_RST) ? ip_src->ip_dst : ip_src->ip_src;
    iph->ip_sum = 0;
    iph->ip_sum = checksum((uint16_t*)iph, sizeof(ip));

    tcph->th_sport = (flags & TH_RST) ? tcp_src->th_sport : tcp_src->th_dport;
    tcph->th_dport = (flags & TH_RST) ? tcp_src->th_dport : tcp_src->th_sport;

    int ip_len = ip_src->ip_hl * 4;
    int tcp_len = tcp_src->th_off * 4;
    int orig_data_len = ntohs(ip_src->ip_len) - ip_len - tcp_len;

    tcph->th_seq = htonl((flags & TH_RST) ? ntohl(tcp_src->th_seq) + orig_data_len : ntohl(tcp_src->th_ack));
    tcph->th_ack = (flags & TH_RST) ? 0 : htonl(ntohl(tcp_src->th_seq) + orig_data_len);
    tcph->th_off = 5;
    tcph->th_flags = flags;
    tcph->th_win = htons(65535);
    tcph->th_sum = 0;

    PseudoHeader pseudo;
    pseudo.src = iph->ip_src.s_addr;
    pseudo.dst = iph->ip_dst.s_addr;
    pseudo.len = htons(sizeof(tcphdr) + data_len);

    char pseudo_buf[BUF_SIZE] = {};
    memcpy(pseudo_buf, &pseudo, sizeof(pseudo));
    memcpy(pseudo_buf + sizeof(pseudo), tcph, sizeof(tcphdr) + data_len);
    tcph->th_sum = checksum((uint16_t*)pseudo_buf, sizeof(pseudo) + sizeof(tcphdr) + data_len);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("raw socket");
        return;
    }

    int on = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));

    sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_addr = iph->ip_dst;

    sendto(sock, buf, sizeof(ip) + sizeof(tcphdr) + data_len, 0, (sockaddr*)&to, sizeof(to));
    close(sock);
}

// --- Main --- //
int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return 1;
    }

    string block_name = argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 10, errbuf);
    if (!handle) {
        cerr << "pcap_open_live failed: " << errbuf << endl;
        return 1;
    }

    cout << "[*] Monitoring interface: " << argv[1] << " for SNI: " << block_name << endl;

    while (true) {
        pcap_pkthdr* hdr;
        const u_char* packet;
        int res = pcap_next_ex(handle, &hdr, &packet);
        if (res != 1) continue;

        const ip* ip_hdr = (ip*)(packet + sizeof(ether_header));
        if (ip_hdr->ip_p != IPPROTO_TCP) continue;

        const tcphdr* tcp_hdr = (tcphdr*)((u_char*)ip_hdr + ip_hdr->ip_hl * 4);
        if (ntohs(tcp_hdr->th_dport) != 443) continue;

        string sni = get_sni_from_packet(packet, hdr->len);
        if (!sni.empty() && sni == block_name) {
            cout << "[!] Match: " << sni << ". Sending RSTs." << endl;
            inject_tcp(ip_hdr, tcp_hdr, nullptr, 0, TH_RST);               // Forward
            inject_tcp(ip_hdr, tcp_hdr, nullptr, 0, TH_RST | TH_ACK);     // Backward
        }
    }

    pcap_close(handle);
    return 0;
}
