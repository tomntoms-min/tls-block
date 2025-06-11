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

#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"
#include "tlshdr.h"
#include "mac.h"
#include "ip.h"

using namespace std;

// --- 상태 관리 구조체 및 전역 변수 (이전과 동일) ---
struct ConnectionKey { /* ... */ };
struct ReassemblyContext { /* ... */ };
static map<ConnectionKey, ReassemblyContext> session_manager;

// --- 헬퍼 함수 (체크섬, 패킷 주입 - 이전과 동일) ---
static uint16_t calculate_checksum(const void* buf, size_t len) { /* ... */ }
#pragma pack(push, 1)
struct PseudoHdr { /* ... */ };
#pragma pack(pop)
static void send_forward_rst(pcap_t* handle, const ReassemblyContext& ctx, const Mac& my_mac) { /* ... */ }
static void send_backward_fin(const ReassemblyContext& ctx) { /* ... */ }


// [핵심 수정] 방어 코드가 추가된 SNI 파싱 함수
static string find_sni(const vector<uint8_t>& buffer) {
    const uint8_t* data = buffer.data();
    size_t len = buffer.size();
    size_t pos = sizeof(Tls);

    // [방어 코드] 각 단계를 진행하기 전에 남은 길이를 철저히 검사
    if (len <= pos) return "";
    pos += 1 + data[pos];
    if (len <= pos + 2) return "";
    pos += 2 + ntohs(*(uint16_t*)(data + pos));
    if (len <= pos + 1) return "";
    pos += 1 + data[pos];
    if (len <= pos + 2) return "";
    
    uint16_t extensions_len = ntohs(*(uint16_t*)(data + pos));
    pos += 2;
    size_t extensions_end = pos + extensions_len;
    if (len < extensions_end) return ""; // 실제 버퍼 길이보다 확장 필드가 길다면 잘못된 패킷

    while (pos + 4 <= extensions_end) {
        uint16_t ext_type = ntohs(*(uint16_t*)(data + pos));
        uint16_t ext_len = ntohs(*(uint16_t*)(data + pos + 2));
        pos += 4;
        
        if (pos + ext_len > extensions_end) return ""; // 현재 확장이 전체 확장 길이를 넘어서면 안됨

        if (ext_type == 0) {
            if (pos + 5 > extensions_end) return "";
            uint16_t name_len = ntohs(*(uint16_t*)(data + pos + 3));
            if (pos + 5 + name_len > extensions_end) return "";
            return string((char*)(data + pos + 5), name_len);
        }
        pos += ext_len;
    }
    return "";
}

// --- 메인 로직 및 프로그램 진입점 ---
void usage() { /* ... */ }
bool getMacIpAddr(const string &iface_name, Mac& mac_addr, Ip& ip_addr) { /* ... */ }

int main(int argc, char *argv[]) {
    if (argc != 3) { usage(); return 1; }

    string iface(argv[1]);
    string server(argv[2]);
    Mac my_mac;
    Ip my_ip;
    if (!getMacIpAddr(iface, my_mac, my_ip)) return EXIT_FAILURE;
    
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
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            cerr << "[pcap] error or break: " << res << endl;
            break;
        }

        // [핵심 수정] 패킷 파싱 전체에 방어 코드 적용
        // =======================================================
        
        // [방어 코드 1] 이더넷 헤더를 읽을 만큼 패킷이 충분히 긴가?
        if (header->caplen < sizeof(EthHdr)) continue;
        const EthHdr* eth = (const EthHdr*)pkt;
        if (eth->type() != EthHdr::Ip4) continue;

        // [방어 코드 2] IP 헤더의 최소 길이를 포함하는가?
        size_t ip_offset = sizeof(EthHdr);
        if (header->caplen < ip_offset + sizeof(IpHdr)) continue;
        const IpHdr* ip = (const IpHdr*)(pkt + ip_offset);
        if (ip->proto != IpHdr::TCP) continue;

        // [방어 코드 3] IP 헤더에 명시된 길이가 실제 패킷 길이를 넘지 않는가?
        size_t ip_hdr_len = ip->ipHdrLen();
        if (header->caplen < ip_offset + ip_hdr_len) continue;

        // [방어 코드 4] TCP 헤더의 최소 길이를 포함하는가?
        size_t tcp_offset = ip_offset + ip_hdr_len;
        if (header->caplen < tcp_offset + sizeof(TcpHdr)) continue;
        const TcpHdr* tcp = (const TcpHdr*)((u_char*)ip + ip_hdr_len);

        // [방어 코드 5] TCP 헤더에 명시된 길이가 실제 패킷 길이를 넘지 않는가?
        size_t tcp_hdr_len = tcp->th_off * 4;
        if (header->caplen < tcp_offset + tcp_hdr_len) continue;

        size_t payload_len = ntohs(ip->total_len) - ip_hdr_len - tcp_hdr_len;
        const uint8_t* payload = (const uint8_t*)tcp + tcp_hdr_len;
        
        // =======================================================

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
    }

    pcap_close(pcap);
    return 0;
}
