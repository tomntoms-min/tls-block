#include <iostream>
#include <pcap.h>
#include <string>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "mac.h"
#include "ip.h"
#include "packet_handler.h"

void usage() {
    std::cout << "syntax : tls-block <interface> <server name>\n";
    std::cout << "sample : tls-block wlan0 test.gilgil.net\n";
}

bool getMyInfo(const std::string& iface, Mac& mac, Ip& ip) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;

    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl(mac)");
        close(sock);
        return false;
    }
    mac = Mac(reinterpret_cast<const uint8_t*>(ifr.ifr_hwaddr.sa_data));

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl(ip)");
        close(sock);
        return false;
    }
    ip = Ip(ntohl(reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr)->sin_addr.s_addr));

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
    Mac my_mac;
    Ip my_ip;

    if (!getMyInfo(interface_name, my_mac, my_ip)) {
        std::cerr << "Failed to get MAC/IP for interface " << interface_name << std::endl;
        return -1;
    }
    std::cout << "Interface: " << interface_name << " | MAC: " << std::string(my_mac) << " | IP: " << std::string(my_ip) << std::endl;
    std::cout << "Blocking server: " << server_name << std::endl;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(interface_name.c_str(), BUFSIZ, 1, 1, errbuf);
    if (pcap == nullptr) {
        std::cerr << "pcap_open_live failed: " << errbuf << std::endl;
        return -1;
    }

    PacketHandler handler(pcap, interface_name, my_mac, my_ip, server_name);

    while (true) {
        struct pcap_pkthdr* header;
        const uint8_t* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            std::cerr << "pcap_next_ex error: " << pcap_geterr(pcap) << std::endl;
            break;
        }
        handler.handlePacket(header, packet);
    }

    pcap_close(pcap);
    return 0;
}
