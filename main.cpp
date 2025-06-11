#include <iostream>
#include <pcap.h>
#include <string>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <cstring>
#include "packet_handler.h"

void usage() {
    std::cout << "syntax : tls-block <interface> <server name>\n";
    std::cout << "sample : tls-block wlan0 naver.com\n";
}

bool getMyMacAddress(const std::string& iface, uint8_t* mac_addr) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return false;
    }
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl(mac)");
        close(sock);
        return false;
    }
    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);
    return true;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return -1;
    }

    std::string interface_name = argv[1];
    std::string server_name = argv[2];
    uint8_t my_mac[6];

    if (!getMyMacAddress(interface_name, my_mac)) {
        std::cerr << "Failed to get MAC address for " << interface_name << std::endl;
        return -1;
    }
    
    char mac_str[18];
    sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);
    std::cout << "Interface: " << interface_name << " | MAC: " << mac_str << std::endl;
    std::cout << "Blocking server pattern: " << server_name << std::endl;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(interface_name.c_str(), BUFSIZ, 1, 1, errbuf);
    if (pcap == nullptr) {
        std::cerr << "pcap_open_live failed: " << errbuf << std::endl;
        return -1;
    }

    // ================== 속도 최적화 1: 즉시 모드 활성화 ==================
    if (pcap_set_immediate_mode(pcap, 1) != 0) {
        std::cerr << "pcap_set_immediate_mode error: " << pcap_geterr(pcap) << std::endl;
    }
    // =================================================================

    PacketHandler handler(pcap, my_mac, server_name);

    while (true) {
        struct pcap_pkthdr* header;
        const uint8_t* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res < 0) {
            std::cerr << "pcap_next_ex error: " << pcap_geterr(pcap) << std::endl;
            break;
        }
        handler.handlePacket(header, packet);
    }

    pcap_close(pcap);
    return 0;
}
