#include "network_utils.h"

#include <arpa/inet.h>
#include <linux/filter.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <iostream>

// Get current time in milliseconds
uint64_t get_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

// Get MAC address of an interface
bool get_mac_address(const char* ifname, unsigned char* mac) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return false;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        close(sock);
        return false;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);
    return true;
}

// Get interface index
int get_interface_index(const char* ifname) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return -1;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        close(sock);
        return -1;
    }
    close(sock);
    return ifr.ifr_ifindex;
}

// Enable hardware timestamping on interface
bool enable_hw_timestamping(const char* ifname) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "[TSTAMP] Failed to create socket for timestamping config" << std::endl;
        return false;
    }

    struct ifreq ifr;
    struct hwtstamp_config hwconfig;

    memset(&ifr, 0, sizeof(ifr));
    memset(&hwconfig, 0, sizeof(hwconfig));

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    // Request all RX packets to be timestamped
    hwconfig.tx_type = HWTSTAMP_TX_ON;
    hwconfig.rx_filter = HWTSTAMP_FILTER_ALL;

    ifr.ifr_data = (char*)&hwconfig;

    if (ioctl(sock, SIOCSHWTSTAMP, &ifr) < 0) {
        std::cerr << "[TSTAMP] Failed to enable hardware timestamping on " << ifname << ": " << strerror(errno)
                  << std::endl;
        std::cerr << "[TSTAMP] This may mean the NIC driver doesn't support hardware timestamping" << std::endl;
        close(sock);
        return false;
    }

    std::cout << "[TSTAMP] Hardware timestamping enabled on " << ifname << std::endl;
    std::cout << "[TSTAMP]   tx_type=" << hwconfig.tx_type << ", rx_filter=" << hwconfig.rx_filter << std::endl;

    close(sock);
    return true;
}

// Attach BPF filter to drop packets with matching source MAC
bool attach_bpf_filter_exclude_mac(int sock, const unsigned char* mac) {
    // BPF program to drop packets where source MAC (offset 6-11) matches the given MAC
    // The Ethernet frame format is: dst_mac(6) src_mac(6) ...
    // We check src_mac at offset 6
    struct sock_filter filter[] = {
        // Load halfword (2 bytes) from offset 6 (first 2 bytes of source MAC)
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 6),
        // Compare with first 2 bytes of our MAC (network byte order)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (__u32)((mac[0] << 8) | mac[1]), 0, 4),

        // Load halfword from offset 8 (next 2 bytes of source MAC)
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 8),
        // Compare with next 2 bytes of our MAC
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (__u32)((mac[2] << 8) | mac[3]), 0, 2),

        // Load halfword from offset 10 (last 2 bytes of source MAC)
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 10),
        // Compare with last 2 bytes of our MAC
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (__u32)((mac[4] << 8) | mac[5]), 0, 1),

        // All 6 bytes matched - drop packet (return 0)
        BPF_STMT(BPF_RET | BPF_K, 0),

        // Did not match - accept packet (return -1 means accept all)
        BPF_STMT(BPF_RET | BPF_K, 0xFFFFFFFF),
    };

    struct sock_fprog bpf = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };

    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0) {
        std::cerr << "[FILTER] Warning: Failed to attach BPF filter: " << strerror(errno) << std::endl;
        return false;
    }

    std::cout << "[FILTER] BPF filter attached to drop packets from own MAC" << std::endl;
    return true;
}
