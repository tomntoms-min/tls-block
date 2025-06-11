#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <atomic>

using namespace std;

#define ETHERNET_SIZE 14

void usage() {
    cout << "syntax : tls-block <interface> <server name>\n";
    cout << "sample : tls-block wlan0 naver.com\n";
}

// IP 및 TCP 헤더의 체크섬을 계산하는 함수
uint16_t checksum(uint16_t *buf, int len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) sum += *(uint8_t *)buf;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

// TCP 체크섬 계산을 위한 가상 헤더 구조체
struct PseudoHeader {
    uint32_t src;
    uint32_t dst;
    uint8_t zero = 0;
    uint8_t proto = IPPROTO_TCP;
    uint16_t len;
};

// TLS 페이로드에서 SNI(Server Name Indication)를 파싱하는 함수
string parse_sni(const u_char *data, int data_len) {
    if (data_len < 42 || data[0] != 0x16 || data[5] != 0x01) {
        return ""; // Not a Client Hello
    }

    int pos = 5; // TLS Record Header
    pos += 4; // Handshake Header
    pos += 2 + 32; // Version + Random

    if (pos >= data_len) return "";
    uint8_t session_id_len = data[pos];
    pos += 1 + session_id_len;

    if (pos + 2 > data_len) return "";
    uint16_t cipher_len;
    memcpy(&cipher_len, data + pos, sizeof(uint16_t));
    cipher_len = ntohs(cipher_len);
    pos += 2 + cipher_len;

    if (pos + 1 > data_len) return "";
    uint8_t comp_len = data[pos];
    pos += 1 + comp_len;

    if (pos + 2 > data_len) return "";
    uint16_t ext_total_len;
    memcpy(&ext_total_len, data + pos, sizeof(uint16_t));
    ext_total_len = ntohs(ext_total_len);
    pos += 2;

    int ext_end = pos + ext_total_len;
    while (pos + 4 <= ext_end && pos + 4 <= data_len) {
        uint16_t ext_type, ext_len;
        memcpy(&ext_type, data + pos, sizeof(uint16_t));
        memcpy(&ext_len, data + pos + 2, sizeof(uint16_t));
        ext_type = ntohs(ext_type);
        ext_len = ntohs(ext_len);
        pos += 4;

        if (ext_type == 0x0000) { // SNI
            if (pos + 5 > data_len) return "";
            uint16_t sni_len;
            memcpy(&sni_len, data + pos + 3, sizeof(uint16_t));
            sni_len = ntohs(sni_len);
            pos += 5;
            if (pos + sni_len > data_len) return "";
            return string((const char *)(data + pos), sni_len);
        }
        pos += ext_len;
    }
    return "";
}

// Raw 소켓을 이용해 RST 패킷을 주입하는 함수 (RST Blasting을 위해 seq_offset 추가)
void inject_rst(const ip *ip_hdr, const tcphdr *tcp_hdr, bool forward, int seq_offset) {
    char buf[1500] = {};
    ip *iph = (ip *)buf;
    tcphdr *tcph = (tcphdr *)(buf + sizeof(ip));
    int tcp_hdr_size = sizeof(tcphdr);
    int ip_hdr_size = sizeof(ip);

    // IP Header 구성
    iph->ip_v = 4;
    iph->ip_hl = 5;
    iph->ip_len = htons(ip_hdr_size + tcp_hdr_size);
    iph->ip_id = htons(54321);
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_src = forward ? ip_hdr->ip_src : ip_hdr->ip_dst;
    iph->ip_dst = forward ? ip_hdr->ip_dst : ip_hdr->ip_src;
    iph->ip_sum = 0;
    iph->ip_sum = checksum((uint16_t *)iph, ip_hdr_size);

    // TCP Header 구성
    tcph->th_sport = forward ? tcp_hdr->th_sport : tcp_hdr->th_dport;
    tcph->th_dport = forward ? tcp_hdr->th_dport : tcp_hdr->th_sport;

    int original_ip_hl = ip_hdr->ip_hl * 4;
    int original_tcp_hl = tcp_hdr->th_off * 4;
    int payload_len = ntohs(ip_hdr->ip_len) - original_ip_hl - original_tcp_hl;

    if (forward) {
        tcph->th_seq = htonl(ntohl(tcp_hdr->th_seq) + payload_len + seq_offset);
        tcph->th_ack = tcp_hdr->th_ack;
        tcph->th_flags = TH_RST | TH_ACK;
    } else {
        tcph->th_seq = tcp_hdr->th_ack;
        tcph->th_ack = 0;
        tcph->th_flags = TH_RST;
    }
    
    tcph->th_off = 5;
    tcph->th_win = 0;
    tcph->th_sum = 0;

    // TCP Pseudo Header 체크섬 계산
    PseudoHeader pseudo;
    pseudo.src = iph->ip_src.s_addr;
    pseudo.dst = iph->ip_dst.s_addr;
    pseudo.len = htons(tcp_hdr_size);
    char pseudo_buf[sizeof(PseudoHeader) + tcp_hdr_size];
    memcpy(pseudo_buf, &pseudo, sizeof(PseudoHeader));
    memcpy(pseudo_buf + sizeof(PseudoHeader), tcph, tcp_hdr_size);
    tcph->th_sum = checksum((uint16_t *)pseudo_buf, sizeof(PseudoHeader) + tcp_hdr_size);

    // Raw 소켓 생성 및 패킷 전송
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) { perror("socket"); return; }
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    sockaddr_in to = {};
    to.sin_family = AF_INET;
    to.sin_addr = iph->ip_dst;
    sendto(sock, buf, ntohs(iph->ip_len), 0, (sockaddr *)&to, sizeof(to));
    close(sock);
}

// 패킷 정보를 담는 구조체
struct Packet {
    pcap_pkthdr hdr;
    u_char *data;
};

// 스레드 간 통신을 위한 전역 변수
queue<Packet> packet_queue;
mutex queue_mutex;
condition_variable queue_cv;
atomic<bool> running(true);

// 개선된 패킷 처리 스레드 함수
void packet_processor(const string &target_name) {
    while (running) {
        unique_lock<mutex> lock(queue_mutex);
        queue_cv.wait(lock, [] { return !packet_queue.empty() || !running; });

        if (!running && packet_queue.empty()) break;

        Packet pkt = packet_queue.front();
        packet_queue.pop();
        lock.unlock();

        const ip *ip_hdr = (ip *)(pkt.data + ETHERNET_SIZE);
        if (ip_hdr->ip_p != IPPROTO_TCP) {
            delete[] pkt.data;
            continue;
        }

        int ip_hdr_len = ip_hdr->ip_hl * 4;
        const tcphdr *tcp_hdr = (tcphdr *)((u_char *)ip_hdr + ip_hdr_len);
        int tcp_hdr_len = tcp_hdr->th_off * 4;
        int payload_len = ntohs(ip_hdr->ip_len) - ip_hdr_len - tcp_hdr_len;
        if (payload_len <= 0) {
            delete[] pkt.data;
            continue;
        }

        const u_char *payload = (u_char *)tcp_hdr + tcp_hdr_len;
        string server_name = parse_sni(payload, payload_len);

        if (!server_name.empty()) {
            cout << "[*] Detected SNI: " << server_name << endl;
            
            // [개선 1] 부분 문자열 매칭으로 서브도메인 및 리디렉션 대응
            if (server_name.find(target_name) != string::npos) {
                cout << "[!] Match found! Blocking " << server_name << "..." << endl;
                
                // [개선 2] RST Blasting으로 경쟁 상태 문제 해결
                for (int i = 0; i < 5; ++i) {
                    inject_rst(ip_hdr, tcp_hdr, true, i * 1460);  // Forward RST Blasting
                    inject_rst(ip_hdr, tcp_hdr, false, 0);       // Backward RST
                }
            }
        }
        delete[] pkt.data;
    }
}

// 메인 함수
int main(int argc, char *argv[]) {
    if (argc != 3) {
        usage();
        return 1;
    }

    string iface = argv[1];
    string target_name = argv[2];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(iface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        cerr << "pcap_open_live error: " << errbuf << endl;
        return 1;
    }

    cout << "[*] Monitoring interface: " << iface << " for SNI: " << target_name << endl;

    thread worker(packet_processor, target_name);

    while (running) {
        pcap_pkthdr *hdr;
        const u_char *packet;
        int res = pcap_next_ex(handle, &hdr, &packet);
        if (res == 0) continue;
        if (res < 0) {
            running = false; // 루프 종료 신호
            break;
        }

        u_char *copy = new u_char[hdr->caplen];
        memcpy(copy, packet, hdr->caplen);
        
        {
            lock_guard<mutex> lock(queue_mutex);
            packet_queue.push({*hdr, copy});
        }
        queue_cv.notify_one();
    }

    running = false;
    queue_cv.notify_all();
    if(worker.joinable()) {
        worker.join();
    }

    pcap_close(handle);
    cout << "[*] Capture finished." << endl;
    return 0;
}
