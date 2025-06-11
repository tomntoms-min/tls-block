#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <pcap.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <cstring>

// 사용자가 제공한 신뢰성 높은 헤더 파일들
#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"
#include "tlshdr.h"
#include "mac.h"
#include "ip.h"

using namespace std;

// --- 모든 로직이 이 파일 안에 통합됩니다 ---

// 1. 상태 관리를 위한 구조체 및 전역 변수
// ==============================================

// TCP 연결을 식별하는 키
struct ConnectionKey {
    Ip src_ip;
    Ip dst_ip;
    uint16_t src_port;
    uint16_t dst_port;

    bool operator<(const ConnectionKey& other) const {
        if (src_ip != other.src_ip) return src_ip < other.src_ip;
        if (dst_ip != other.dst_ip) return dst_ip < other.dst_ip;
        if (src_port != other.src_port) return src_port < other.src_port;
        return dst_port < other.dst_port;
    }
};

// 각 연결의 재조합 상태를 관리하는 구조체
struct ReassemblyContext {
    vector<uint8_t> buffer;
    uint16_t expected_length{0};
    EthHdr eth_hdr;
    IpHdr ip_hdr;
    TcpHdr tcp_hdr;
};

// 모든 세션의 상태를 관리하는 전역 맵
static map<ConnectionKey, ReassemblyContext> session_manager;

// 2. 헬퍼 함수들 (패킷 생성 및 파싱)
// ==============================================

// 체크섬 계산 헬퍼
static uint16_t calculate_checksum(const void* buf, size_t len) {
    auto p = static_cast<const uint16_t*>(buf);
    uint32_t sum = 0;
    while (len > 1) { sum += ntohs(*p++); len -= 2; }
    if (len) sum += (*reinterpret_cast<const uint8_t*>(p)) << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return htons(~(uint16_t)sum);
}

// TCP 체크섬 계산을 위한 가상 헤더
#pragma pack(push, 1)
struct PseudoHdr {
    uint32_t src_ip; uint32_t dst_ip; uint8_t reserved; uint8_t protocol; uint16_t tcp_len;
};
#pragma pack(pop)

// 서버로 RST 전송
static void send_forward_rst(pcap_t* handle, const ReassemblyContext& ctx, const Mac& my_mac) {
    vector<uint8_t> packet(sizeof(EthHdr) + sizeof(IpHdr) + sizeof(TcpHdr));
    EthHdr* eth = reinterpret_cast<EthHdr*>(packet.data());
    IpHdr* ip = reinterpret_cast<IpHdr*>(eth + 1);
    TcpHdr* tcp = reinterpret_cast<TcpHdr*>(ip + 1);
    eth->dmac_ = ctx.eth_hdr.smac(); eth->smac_ = my_mac; eth->type_ = htons(EthHdr::Ip4);
    memcpy(ip, &ctx.ip_hdr, sizeof(IpHdr));
    ip->total_len = htons(sizeof(IpHdr) + sizeof(TcpHdr)); ip->check = 0;
    memcpy(tcp, &ctx.tcp_hdr, sizeof(TcpHdr));
    tcp->th_seq = htonl(ntohl(ctx.tcp_hdr.th_seq) + ctx.buffer.size());
    tcp->th_flags = TcpHdr::RST | TcpHdr::ACK; tcp->th_sum = 0;
    PseudoHdr psh; psh.src_ip = ip->sip_; psh.dst_ip = ip->dip_; psh.reserved = 0; psh.protocol = IpHdr::TCP; psh.tcp_len = htons(sizeof(TcpHdr));
    vector<uint8_t> checksum_buf(sizeof(PseudoHdr) + sizeof(TcpHdr));
    memcpy(checksum_buf.data(), &psh, sizeof(PseudoHdr)); memcpy(checksum_buf.data() + sizeof(PseudoHdr), tcp, sizeof(TcpHdr));
    tcp->th_sum = calculate_checksum(checksum_buf.data(), checksum_buf.size());
    ip->check = calculate_checksum(ip, sizeof(IpHdr));
    pcap_sendpacket(handle, packet.data(), packet.size());
}

// 클라이언트로 FIN 전송
static void send_backward_fin(const ReassemblyContext& ctx) {
    vector<uint8_t> packet(sizeof(IpHdr) + sizeof(TcpHdr));
    IpHdr* ip = reinterpret_cast<IpHdr*>(packet.data());
    TcpHdr* tcp = reinterpret_cast<TcpHdr*>(ip + 1);
    memcpy(ip, &ctx.ip_hdr, sizeof(IpHdr));
    swap(ip->sip_, ip->dip_);
    ip->total_len = htons(sizeof(IpHdr) + sizeof(TcpHdr)); ip->check = 0;
    memcpy(tcp, &ctx.tcp_hdr, sizeof(TcpHdr));
    swap(tcp->th_sport, tcp->th_dport);
    tcp->th_seq = ctx.tcp_hdr.th_ack; tcp->th_ack = htonl(ntohl(ctx.tcp_hdr.th_seq) + ctx.buffer.size());
    tcp->th_flags = TcpHdr::FIN | TcpHdr::ACK; tcp->th_sum = 0;
    PseudoHdr psh; psh.src_ip = ip->sip_; psh.dst_ip = ip->dip_; psh.reserved = 0; psh.protocol = IpHdr::TCP; psh.tcp_len = htons(sizeof(TcpHdr));
    vector<uint8_t> checksum_buf(sizeof(PseudoHdr) + sizeof(TcpHdr));
    memcpy(checksum_buf.data(), &psh, sizeof(PseudoHdr)); memcpy(checksum_buf.data() + sizeof(PseudoHdr), tcp, sizeof(TcpHdr));
    tcp->th_sum = calculate_checksum(checksum_buf.data(), checksum_buf.size());
    ip->check = calculate_checksum(ip, sizeof(IpHdr));
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int one = 1; setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    sockaddr_in sin{}; sin.sin_family = AF_INET; sin.sin_addr.s_addr = ip->dip_;
    sendto(sock, packet.data(), packet.size(), 0, (sockaddr*)&sin, sizeof(sin)); close(sock);
}

// SNI 파싱
static string find_sni(const vector<uint8_t>& buffer) {
    const uint8_t* data = buffer.data(); size_t len = buffer.size();
    size_t pos = sizeof(Tls);
    if (len <= pos) return "";
    pos += 1 + data[pos]; if (len <= pos) return "";
    pos += 2 + ntohs(*(uint16_t*)(data + pos)); if (len <= pos) return "";
    pos += 1 + data[pos]; if (len <= pos) return "";
    pos += 2;
    while (pos + 4 < len) {
        uint16_t ext_type = ntohs(*(uint16_t*)(data + pos));
        uint16_t ext_len = ntohs(*(uint16_t*)(data + pos + 2));
        pos += 4;
        if (ext_type == 0) {
            if (pos + 5 > len) return "";
            uint16_t name_len = ntohs(*(uint16_t*)(data + pos + 3));
            if (pos + 5 + name_len > len) return "";
            return string((char*)(data + pos + 5), name_len);
        }
        pos += ext_len;
    }
    return "";
}

// 3. 메인 로직 및 프로그램 진입점
// ==============================================

void usage() {
    cout << "syntax : ./tls-block <interface> <server name>\nsample : tls-block wlan0 naver.com\n";
}

bool getMacIpAddr(const string &iface_name, Mac& mac_addr, Ip& ip_addr) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return false;
    }
    struct ifreq ifr {};
    strncpy(ifr.ifr_name, iface_name.c_str(), IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl(failed to get mac addr)");
        close(fd);
        return false;
    }
    mac_addr = Mac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));

    ifr.ifr_addr.sa_family = AF_INET;
    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        perror("ioctl(failed to get ip addr)");
        close(fd);
        return false;
    }
    ip_addr = Ip(ntohl(reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr)->sin_addr.s_addr));

    close(fd);
    return true;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        usage();
        return 1;
    }

    string iface(argv[1]);
    string server(argv[2]);
    Mac my_mac;
    Ip my_ip;
    if (!getMacIpAddr(iface, my_mac, my_ip)) {
        return EXIT_FAILURE;
    }
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(iface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", iface.c_str(), errbuf);
        return EXIT_FAILURE;
    }

    cout << "[*] Monitoring interface " << iface << " for server: " << server << endl;
    cout << "[*] My MAC: " << string(my_mac) << ", My IP: " << string(my_ip) << endl;

    while (true){
        struct pcap_pkthdr *header;
        const uint8_t* pkt;
        int res = pcap_next_ex(pcap, &header, &pkt);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
            cerr << "[pcap] error or break: " << res << endl;
            break;
        }

        // --- 패킷 처리 로직이 main 루프 안으로 통합 ---
        const EthHdr* eth = (const EthHdr*)pkt;
        if (eth->type() != EthHdr::Ip4) continue;
        const IpHdr* ip = (const IpHdr*)(eth + 1);
        if (ip->proto != IpHdr::TCP) continue;
        size_t ip_hdr_len = ip->ipHdrLen();
        const TcpHdr* tcp = (const TcpHdr*)((u_char*)ip + ip_hdr_len);
        size_t tcp_hdr_len = tcp->th_off * 4;
        size_t payload_len = ntohs(ip->total_len) - ip_hdr_len - tcp_hdr_len;
        const uint8_t* payload = (const uint8_t*)tcp + tcp_hdr_len;
        
        ConnectionKey key{ip->sip(), ip->dip(), ntohs(tcp->th_sport), ntohs(tcp->th_dport)};
        
        if (tcp->th_flags & (TcpHdr::RST | TcpHdr::FIN)) { session_manager.erase(key); continue; }
        if (payload_len == 0) continue;
        
        if (session_manager.find(key) == session_manager.end()) {
            const Tls* tls = (const Tls*)payload;
            if (payload_len < sizeof(Tls) || tls->tls_content != 22 || tls->handshake_type != 1) continue;
            ReassemblyContext ctx;
            ctx.expected_length = ntohs(tls->tls_length) + 5;
            ctx.buffer.assign(payload, payload + payload_len);
            ctx.eth_hdr = *eth; ctx.ip_hdr = *ip; ctx.tcp_hdr = *tcp;
            session_manager[key] = ctx;
        } else {
            session_manager[key].buffer.insert(session_manager[key].buffer.end(), payload, payload + payload_len);
        }
        
        if (session_manager.count(key) && session_manager[key].buffer.size() >= session_manager[key].expected_length) {
            auto& ctx = session_manager[key];
            string sni = find_sni(ctx.buffer);
            if (!sni.empty()) {
                cout << "[*] Detected SNI: " << sni << endl;
                if (sni.find(server) != string::npos) {
                    cout << "[!] Match found! Interrupting handshake..." << endl;
                    send_forward_rst(pcap, ctx, my_mac);
                    send_backward_fin(ctx);
                }
            }
            session_manager.erase(key);
        }
        // --- 패킷 처리 로직 끝 ---
    }

    pcap_close(pcap);
    return 0;
}
