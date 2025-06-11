#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <pcap.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"
#include "tlshdr.h"

using namespace std;

struct ConnectionKey {
    Ip src_ip, dst_ip;
    uint16_t src_port, dst_port;
    bool operator<(const ConnectionKey& o) const {
        return tie(src_ip, dst_ip, src_port, dst_port) < tie(o.src_ip, o.dst_ip, o.src_port, o.dst_port);
    }
};

struct ReassemblyContext {
    vector<uint8_t> buffer;
    uint16_t expected_length = 0;
    EthHdr eth_hdr;
    IpHdr ip_hdr;
    TcpHdr tcp_hdr;
};

map<ConnectionKey, ReassemblyContext> session_manager;

uint16_t calculate_checksum(const void* buf, size_t len) {
    auto* p = static_cast<const uint16_t*>(buf);
    uint32_t sum = 0;
    while (len > 1) { sum += ntohs(*p++); len -= 2; }
    if (len) sum += (*(const uint8_t*)p) << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return htons(~sum);
}

#pragma pack(push, 1)
struct PseudoHdr {
    uint32_t src_ip, dst_ip;
    uint8_t reserved, protocol;
    uint16_t tcp_len;
};
#pragma pack(pop)

void send_rst_both(pcap_t* handle, const ReassemblyContext& ctx, const Mac& my_mac) {
    auto send_one = [&](IpHdr ip, TcpHdr tcp, Mac dmac, Mac smac) {
        vector<uint8_t> packet(sizeof(EthHdr) + sizeof(IpHdr) + sizeof(TcpHdr));
        auto* eth = (EthHdr*)packet.data();
        auto* iphdr = (IpHdr*)(eth + 1);
        auto* tcphdr = (TcpHdr*)(iphdr + 1);

        eth->dmac_ = dmac;
        eth->smac_ = smac;
        eth->type_ = htons(EthHdr::Ip4);

        *iphdr = ip;
        iphdr->total_len = htons(sizeof(IpHdr) + sizeof(TcpHdr));
        iphdr->check = 0;

        *tcphdr = tcp;
        tcphdr->th_flags = TcpHdr::RST | TcpHdr::ACK;
        tcphdr->th_sum = 0;

        PseudoHdr psh = { iphdr->sip_, iphdr->dip_, 0, IpHdr::TCP, htons(sizeof(TcpHdr)) };
        vector<uint8_t> buf(sizeof(PseudoHdr) + sizeof(TcpHdr));
        memcpy(buf.data(), &psh, sizeof(psh));
        memcpy(buf.data() + sizeof(psh), tcphdr, sizeof(TcpHdr));
        tcphdr->th_sum = calculate_checksum(buf.data(), buf.size());
        iphdr->check = calculate_checksum(iphdr, sizeof(IpHdr));

        pcap_sendpacket(handle, packet.data(), packet.size());
    };

    IpHdr ip_fwd = ctx.ip_hdr;
    TcpHdr tcp_fwd = ctx.tcp_hdr;
    tcp_fwd.th_seq = htonl(ntohl(tcp_fwd.th_seq) + ctx.buffer.size());
    send_one(ip_fwd, tcp_fwd, ctx.eth_hdr.smac(), my_mac);

    IpHdr ip_back = ctx.ip_hdr;
    TcpHdr tcp_back = ctx.tcp_hdr;
    swap(ip_back.sip_, ip_back.dip_);
    swap(tcp_back.th_sport, tcp_back.th_dport);
    tcp_back.th_seq = ctx.tcp_hdr.th_ack;
    tcp_back.th_ack = htonl(ntohl(ctx.tcp_hdr.th_seq) + ctx.buffer.size());
    send_one(ip_back, tcp_back, ctx.eth_hdr.dmac(), ctx.eth_hdr.smac());
}

string find_sni_from_tls(const vector<uint8_t>& data) {
    size_t pos = 0;
    if (data.size() < 5) return "";
    pos = 5 + 1 + data[5]; // Session ID
    if (pos + 2 > data.size()) return "";
    uint16_t cipher_len = ntohs(*(uint16_t*)(&data[pos]));
    pos += 2 + cipher_len;
    if (pos + 1 > data.size()) return "";
    uint8_t comp_len = data[pos];
    pos += 1 + comp_len;
    if (pos + 2 > data.size()) return "";
    uint16_t ext_total_len = ntohs(*(uint16_t*)(&data[pos]));
    pos += 2;

    size_t ext_end = pos + ext_total_len;
    while (pos + 4 <= data.size() && pos + 4 <= ext_end) {
        uint16_t ext_type = ntohs(*(uint16_t*)(&data[pos]));
        uint16_t ext_len = ntohs(*(uint16_t*)(&data[pos + 2]));
        pos += 4;
        if (ext_type == 0x0000 && pos + 5 <= data.size()) {
            pos += 2;
            pos++; // name_type
            uint16_t name_len = ntohs(*(uint16_t*)(&data[pos]));
            pos += 2;
            if (pos + name_len <= data.size())
                return string((char*)(&data[pos]), name_len);
        }
        pos += ext_len;
    }
    return "";
}

void usage() {
    cout << "syntax: ./tls-block <interface> <host>\n";
    cout << "sample: ./tls-block eth0 naver.com\n";
}

int main(int argc, char* argv[]) {
    if (argc != 3) { usage(); return -1; }
    string iface = argv[1], target_host = argv[2];

    Mac my_mac;
    ifreq ifr{};
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ-1);
    ioctl(sock, SIOCGIFHWADDR, &ifr); close(sock);
    my_mac = Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(iface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        cerr << "pcap_open_live error: " << errbuf << endl;
        return -1;
    }

    while (true) {
        pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res < 0) break;

        const EthHdr* eth = (const EthHdr*)packet;
        if (eth->type() != EthHdr::Ip4) continue;
        const IpHdr* ip = (const IpHdr*)(eth + 1);
        if (ip->proto != IpHdr::TCP) continue;

        size_t ip_len = ip->ipHdrLen();
        const TcpHdr* tcp = (const TcpHdr*)((u_char*)ip + ip_len);
        size_t tcp_len = tcp->th_off * 4;
        size_t payload_len = ntohs(ip->total_len) - ip_len - tcp_len;
        const uint8_t* payload = (const uint8_t*)tcp + tcp_len;

        if (tcp->th_flags & (TcpHdr::RST | TcpHdr::FIN) || payload_len == 0) continue;

        ConnectionKey key{ip->sip(), ip->dip(), ntohs(tcp->th_sport), ntohs(tcp->th_dport)};
        auto& ctx = session_manager[key];

        if (ctx.buffer.empty()) {
            if (payload_len < sizeof(Tls)) continue;
            const Tls* tls = (const Tls*)payload;
            if (tls->tls_content != 22 || tls->handshake_type != 1) continue;
            ctx.expected_length = ntohs(tls->tls_length) + 5;
            ctx.buffer.assign(payload, payload + payload_len);
            ctx.eth_hdr = *eth; ctx.ip_hdr = *ip; ctx.tcp_hdr = *tcp;
        } else {
            ctx.buffer.insert(ctx.buffer.end(), payload, payload + payload_len);
        }

        if (ctx.buffer.size() >= ctx.expected_length) {
            string sni = find_sni_from_tls(ctx.buffer);
            if (!sni.empty()) {
                cout << "[*] SNI detected: " << sni << endl;
                if (sni == target_host ||
                    (sni.size() > target_host.size() &&
                     sni.compare(sni.size() - target_host.size(), target_host.size(), target_host) == 0)) {
                    cout << "[!] Match found. Sending RST packets..." << endl;
                    send_rst_both(handle, ctx, my_mac);
                }
            }
            session_manager.erase(key);
        }
    }

    pcap_close(handle);
    return 0;
}
