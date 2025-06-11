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

struct PseudoHeader {
    uint32_t src;
    uint32_t dst;
    uint8_t zero = 0;
    uint8_t proto = IPPROTO_TCP;
    uint16_t len;
};

string parse_sni(const u_char *data, int data_len) {
    int pos = 0;
    pos += 5;  // TLS record header
    if (pos >= data_len) return "";

    pos += 4;  // handshake header
    if (pos >= data_len) return "";

    pos += 2 + 32;  // version + random
    if (pos >= data_len) return "";

    uint8_t session_id_len = data[pos];
    pos += 1 + session_id_len;
    if (pos >= data_len) return "";

    uint16_t cipher_len = (data[pos] << 8) | data[pos + 1];
    pos += 2 + cipher_len;
    if (pos >= data_len) return "";

    uint8_t comp_len = data[pos];
    pos += 1 + comp_len;
    if (pos >= data_len) return "";

    uint16_t ext_len = (data[pos] << 8) | data[pos + 1];
    pos += 2;
    if (pos >= data_len) return "";

    int ext_end = pos + ext_len;
    while (pos + 4 <= ext_end) {
        uint16_t ext_type = (data[pos] << 8) | data[pos + 1];
        uint16_t ext_len = (data[pos + 2] << 8) | data[pos + 3];
        pos += 4;
        if (ext_type == 0x00) {  // SNI
            if (pos + 5 >= data_len) return "";
            uint16_t sni_list_len = (data[pos] << 8) | data[pos + 1];
            uint8_t sni_type = data[pos + 2];
            uint16_t sni_len = (data[pos + 3] << 8) | data[pos + 4];
            pos += 5;
            if (pos + sni_len > data_len) return "";
            return string((const char *)(data + pos), sni_len);
        }
        pos += ext_len;
    }
    return "";
}

void inject_rst(const ip *ip_hdr, const tcphdr *tcp_hdr, bool forward) {
    char buf[1500] = {};
    ip *iph = (ip *)buf;
    tcphdr *tcph = (tcphdr *)(buf + sizeof(ip));

    iph->ip_v = 4;
    iph->ip_hl = 5;
    iph->ip_ttl = 64;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_len = htons(sizeof(ip) + sizeof(tcphdr));
    iph->ip_off = 0;
    iph->ip_id = htons(1234);

    iph->ip_src = forward ? ip_hdr->ip_src : ip_hdr->ip_dst;
    iph->ip_dst = forward ? ip_hdr->ip_dst : ip_hdr->ip_src;
    iph->ip_sum = 0;
    iph->ip_sum = checksum((uint16_t *)iph, sizeof(ip));

    tcph->th_sport = forward ? tcp_hdr->th_sport : tcp_hdr->th_dport;
    tcph->th_dport = forward ? tcp_hdr->th_dport : tcp_hdr->th_sport;

    uint32_t seq = ntohl(tcp_hdr->th_seq);
    uint32_t ack = ntohl(tcp_hdr->th_ack);
    int ip_hl = ip_hdr->ip_hl * 4;
    int tcp_hl = tcp_hdr->th_off * 4;
    int payload_len = ntohs(ip_hdr->ip_len) - ip_hl - tcp_hl;

    tcph->th_seq = htonl(forward ? seq + payload_len : ack);
    tcph->th_ack = forward ? 0 : htonl(seq + payload_len);
    tcph->th_off = 5;
    tcph->th_flags = TH_RST | (forward ? 0 : TH_ACK);
    tcph->th_win = htons(65535);

    PseudoHeader pseudo;
    pseudo.src = iph->ip_src.s_addr;
    pseudo.dst = iph->ip_dst.s_addr;
    pseudo.len = htons(sizeof(tcphdr));

    char pseudo_buf[1500] = {};
    memcpy(pseudo_buf, &pseudo, sizeof(pseudo));
    memcpy(pseudo_buf + sizeof(pseudo), tcph, sizeof(tcphdr));
    tcph->th_sum = checksum((uint16_t *)pseudo_buf, sizeof(pseudo) + sizeof(tcphdr));

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket"); return;
    }
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    sockaddr_in to = {};
    to.sin_family = AF_INET;
    to.sin_addr = iph->ip_dst;
    sendto(sock, buf, sizeof(ip) + sizeof(tcphdr), 0, (sockaddr *)&to, sizeof(to));
    close(sock);
}

// --------------------- Thread-safe Queue Section --------------------------

struct Packet {
    pcap_pkthdr *hdr;
    const u_char *data;
};

queue<Packet> packet_queue;
mutex queue_mutex;
condition_variable queue_cv;
atomic<bool> running(true);

// --------------------- Packet Processing Thread ---------------------------

void packet_processor(const string &target_name) {
    while (running) {
        unique_lock<mutex> lock(queue_mutex);
        queue_cv.wait(lock, [] { return !packet_queue.empty() || !running; });

        if (!running && packet_queue.empty()) break;

        Packet pkt = packet_queue.front();
        packet_queue.pop();
        lock.unlock();

        const ip *ip_hdr = (ip *)(pkt.data + ETHERNET_SIZE);
        if (ip_hdr->ip_p != IPPROTO_TCP) continue;

        int ip_hdr_len = ip_hdr->ip_hl * 4;
        const tcphdr *tcp_hdr = (tcphdr *)((u_char *)ip_hdr + ip_hdr_len);
        int tcp_hdr_len = tcp_hdr->th_off * 4;
        int payload_len = ntohs(ip_hdr->ip_len) - ip_hdr_len - tcp_hdr_len;
        if (payload_len <= 0) continue;

        const u_char *payload = (u_char *)tcp_hdr + tcp_hdr_len;
        string server_name = parse_sni(payload, payload_len);

        if (!server_name.empty()) {
            cout << "[*] Detected SNI: " << server_name << endl;
            if (server_name == target_name) {
                cout << "[!] Match found! Blocking..." << endl;
                inject_rst(ip_hdr, tcp_hdr, true);
                inject_rst(ip_hdr, tcp_hdr, false);
            }
        }
    }
}

// --------------------- Main Function --------------------------------------

int main(int argc, char *argv[]) {
    if (argc != 3) {
        usage();
        return 1;
    }

    string iface = argv[1];
    string target_name = argv[2];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(iface.c_str(), BUFSIZ, 1, 10, errbuf);
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
        if (res == -1 || res == -2) break;

        u_char *copy = new u_char[hdr->caplen];
        memcpy(copy, packet, hdr->caplen);

        {
            lock_guard<mutex> lock(queue_mutex);
            packet_queue.push({hdr, copy});
        }
        queue_cv.notify_one();
    }

    running = false;
    queue_cv.notify_all();
    worker.join();

    pcap_close(handle);
    return 0;
}
