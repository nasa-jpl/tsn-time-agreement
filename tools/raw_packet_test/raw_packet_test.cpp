#include <iostream>
#include <cstring>
#include <ctime>
#include <thread>
#include <atomic>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#ifdef __APPLE__
#include <net/if_dl.h>
#include <ifaddrs.h>
#include <net/bpf.h>
#include <fcntl.h>
#include <machine/endian.h>
#include <libkern/OSByteOrder.h>
#define htobe64(x) OSSwapHostToBigInt64(x)
#endif

#ifdef __linux__
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <endian.h>
#endif

// VLAN header structure (802.1Q)
struct VlanHeader {
    uint16_t tpid;  // Tag Protocol Identifier (0x8100)
    uint16_t tci;   // Tag Control Information (PCP + DEI + VID)
} __attribute__((packed));

// Test packet structure without VLAN
struct TestPacket {
    struct ether_header eth_header;
    uint32_t sequence_number;
    uint64_t timestamp;
    char payload[64];
} __attribute__((packed));

// Test packet structure with VLAN tag
struct VlanTestPacket {
    unsigned char ether_dhost[6];
    unsigned char ether_shost[6];
    struct VlanHeader vlan;
    uint16_t ether_type;
    uint32_t sequence_number;
    uint64_t timestamp;
    char payload[64];
} __attribute__((packed));

std::atomic<bool> running(true);

// Get current time in milliseconds
uint64_t get_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

// Get MAC address of an interface
bool get_mac_address(const char* ifname, unsigned char* mac) {
#ifdef __APPLE__
    struct ifaddrs *ifap, *ifaptr;
    if (getifaddrs(&ifap) != 0) {
        std::cerr << "getifaddrs failed" << std::endl;
        return false;
    }

    for (ifaptr = ifap; ifaptr != nullptr; ifaptr = ifaptr->ifa_next) {
        if (strcmp(ifaptr->ifa_name, ifname) == 0 &&
            ifaptr->ifa_addr->sa_family == AF_LINK) {
            struct sockaddr_dl* sdl = (struct sockaddr_dl*)ifaptr->ifa_addr;
            memcpy(mac, LLADDR(sdl), 6);
            freeifaddrs(ifap);
            return true;
        }
    }
    freeifaddrs(ifap);
    return false;
#else
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        close(sock);
        return false;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);
    return true;
#endif
}

// Get interface index
int get_interface_index(const char* ifname) {
#ifdef __APPLE__
    return if_nametoindex(ifname);
#else
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        close(sock);
        return -1;
    }
    close(sock);
    return ifr.ifr_ifindex;
#endif
}

// Sender thread function
void sender_thread(const char* ifname, const unsigned char* dest_mac, uint16_t ethertype, uint16_t vlan_id, int count, int interval_ms) {
    unsigned char src_mac[6];
    if (!get_mac_address(ifname, src_mac)) {
        std::cerr << "[SEND] Failed to get MAC address for " << ifname << std::endl;
        return;
    }

    std::cout << "[SEND] Source MAC: " << std::hex;
    for (int i = 0; i < 6; i++) {
        std::cout << (int)src_mac[i];
        if (i < 5) std::cout << ":";
    }
    std::cout << std::dec << std::endl;

#ifdef __APPLE__
    // On macOS, use BPF
    int sock = -1;
    char bpf_device[32];
    for (int i = 0; i < 99; i++) {
        snprintf(bpf_device, sizeof(bpf_device), "/dev/bpf%d", i);
        sock = open(bpf_device, O_RDWR);
        if (sock != -1) break;
    }

    if (sock < 0) {
        std::cerr << "[SEND] Failed to open BPF device" << std::endl;
        return;
    }

    // Bind to interface
    struct ifreq ifr;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(sock, BIOCSETIF, &ifr) < 0) {
        std::cerr << "[SEND] Failed to bind to interface" << std::endl;
        close(sock);
        return;
    }

    // Enable immediate mode
    unsigned int enable = 1;
    ioctl(sock, BIOCIMMEDIATE, &enable);
#else
    // On Linux, use AF_PACKET
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        std::cerr << "[SEND] Failed to create socket. Run with sudo?" << std::endl;
        return;
    }

    // Bind to interface
    struct sockaddr_ll saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_ALL);
    saddr.sll_ifindex = get_interface_index(ifname);

    if (bind(sock, (struct sockaddr*)&saddr, sizeof(saddr)) < 0) {
        std::cerr << "[SEND] Failed to bind socket" << std::endl;
        close(sock);
        return;
    }
#endif

    std::cout << "[SEND] Starting to send " << count << " packets on " << ifname;
    if (vlan_id > 0) {
        std::cout << " (VLAN " << vlan_id << ")";
    }
    std::cout << std::endl;

    // Send packets
    for (int i = 0; i < count && running; i++) {
        ssize_t sent;

        if (vlan_id > 0) {
            // Send VLAN-tagged packet
            VlanTestPacket packet;
            memset(&packet, 0, sizeof(packet));

            // Fill ethernet header
            memcpy(packet.ether_dhost, dest_mac, 6);
            memcpy(packet.ether_shost, src_mac, 6);

            // Fill VLAN header (802.1Q)
            packet.vlan.tpid = htons(0x8100);  // VLAN tag identifier
            packet.vlan.tci = htons(vlan_id & 0x0FFF);  // VLAN ID (12 bits), PCP=0, DEI=0

            // EtherType comes after VLAN tag
            packet.ether_type = htons(ethertype);

            // Fill test data
            packet.sequence_number = htonl(i);
            packet.timestamp = htobe64(time(nullptr));
            snprintf(packet.payload, sizeof(packet.payload), "Test packet #%d", i);

            sent = write(sock, &packet, sizeof(packet));
        } else {
            // Send regular packet without VLAN tag
            TestPacket packet;
            memset(&packet, 0, sizeof(packet));

            // Fill ethernet header
            memcpy(packet.eth_header.ether_dhost, dest_mac, 6);
            memcpy(packet.eth_header.ether_shost, src_mac, 6);
            packet.eth_header.ether_type = htons(ethertype);

            // Fill test data
            packet.sequence_number = htonl(i);
            packet.timestamp = htobe64(time(nullptr));
            snprintf(packet.payload, sizeof(packet.payload), "Test packet #%d", i);

            sent = write(sock, &packet, sizeof(packet));
        }

        if (sent < 0) {
            std::cerr << "[SEND] Failed to send packet " << i << std::endl;
        } else {
            std::cout << "[SEND] Sent packet #" << i << " (" << sent << " bytes)" << std::endl;
        }

        usleep(interval_ms * 1000);
    }

    close(sock);
    std::cout << "[SEND] Sender thread finished" << std::endl;
}

// Receiver thread function
void receiver_thread(const char* ifname, uint16_t ethertype, uint16_t vlan_id, int total_recv_time_ms) {
#ifdef __APPLE__
    // On macOS, use BPF
    int sock = -1;
    char bpf_device[32];
    for (int i = 0; i < 99; i++) {
        snprintf(bpf_device, sizeof(bpf_device), "/dev/bpf%d", i);
        sock = open(bpf_device, O_RDONLY);
        if (sock != -1) break;
    }

    if (sock < 0) {
        std::cerr << "[RECV] Failed to open BPF device" << std::endl;
        return;
    }

    // Set buffer size
    unsigned int bufsize = 32768;
    if (ioctl(sock, BIOCSBLEN, &bufsize) < 0) {
        std::cerr << "[RECV] Failed to set buffer size" << std::endl;
        close(sock);
        return;
    }

    // Bind to interface
    struct ifreq ifr;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(sock, BIOCSETIF, &ifr) < 0) {
        std::cerr << "[RECV] Failed to bind to interface" << std::endl;
        close(sock);
        return;
    }

    // Enable immediate mode
    unsigned int enable = 1;
    ioctl(sock, BIOCIMMEDIATE, &enable);

    // Set up filter for the specified ethertype (handles both VLAN and non-VLAN)
    struct bpf_program filter;
    if (vlan_id > 0) {
        // Filter for VLAN-tagged packets with matching ethertype at offset 16
        struct bpf_insn insns[] = {
            BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),             // Load bytes at offset 12 (should be 0x8100 for VLAN)
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x8100, 0, 3),  // Check if VLAN tag present
            BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 16),             // Load ethertype at offset 16 (after VLAN tag)
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ethertype, 0, 1), // Check if matches our ethertype
            BPF_STMT(BPF_RET + BPF_K, (u_int)-1),               // Accept
            BPF_STMT(BPF_RET + BPF_K, 0)                        // Reject
        };
        filter.bf_len = sizeof(insns) / sizeof(insns[0]);
        filter.bf_insns = insns;
    } else {
        // Filter for non-VLAN packets with matching ethertype at offset 12
        struct bpf_insn insns[] = {
            BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),             // Load ethertype at offset 12
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ethertype, 0, 1), // Check if matches
            BPF_STMT(BPF_RET + BPF_K, (u_int)-1),               // Accept
            BPF_STMT(BPF_RET + BPF_K, 0)                        // Reject
        };
        filter.bf_len = sizeof(insns) / sizeof(insns[0]);
        filter.bf_insns = insns;
    }

    if (ioctl(sock, BIOCSETF, &filter) < 0) {
        std::cerr << "[RECV] Failed to set filter" << std::endl;
        close(sock);
        return;
    }

    char buffer[32768];
    int received = 0;
    uint64_t start_time_ms = get_time_ms();

    std::cout << "[RECV] Listening on " << ifname << " for test packets";
    if (vlan_id > 0) {
        std::cout << " (VLAN " << vlan_id << ")";
    }
    std::cout << " for " << total_recv_time_ms << "ms..." << std::endl;

    // Set read timeout to 100ms for more responsive timeout checking
    // For BPF, we need to use BIOCSRTIMEOUT instead of SO_RCVTIMEO
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000;  // 100ms
    if (ioctl(sock, BIOCSRTIMEOUT, &tv) < 0) {
        std::cerr << "[RECV] Warning: Failed to set BPF read timeout" << std::endl;
    }

    while (running) {
        // Check if total receive time has elapsed
        uint64_t elapsed = get_time_ms() - start_time_ms;
        if (elapsed >= (uint64_t)total_recv_time_ms) {
            std::cout << "[RECV] Receive time expired (elapsed=" << elapsed
                      << "ms) after receiving " << received
                      << " packets" << std::endl;
            break;
        }

        ssize_t n = read(sock, buffer, sizeof(buffer));
        if (n > 0) {
            // BPF can batch multiple packets in a single read
            // We need to iterate through all packets in the buffer
            char* ptr = buffer;
            char* end = buffer + n;

            while (ptr < end) {
                struct bpf_hdr* bpf_packet = (struct bpf_hdr*)ptr;

                // Check if we have a complete BPF header
                if (ptr + sizeof(struct bpf_hdr) > end) {
                    break;
                }

                unsigned char* packet_data = (unsigned char*)(ptr + bpf_packet->bh_hdrlen);

                if (vlan_id > 0) {
                    // Parse VLAN-tagged packet
                    VlanTestPacket* packet = (VlanTestPacket*)packet_data;
                    uint16_t received_vlan = ntohs(packet->vlan.tci) & 0x0FFF;

                    std::cout << "[RECV] Received VLAN packet #" << ntohl(packet->sequence_number) << std::endl;
                    std::cout << "       From MAC: " << std::hex;
                    for (int i = 0; i < 6; i++) {
                        std::cout << (int)packet->ether_shost[i];
                        if (i < 5) std::cout << ":";
                    }
                    std::cout << std::dec << std::endl;
                    std::cout << "       VLAN ID: " << received_vlan << std::endl;
                    std::cout << "       Payload: " << packet->payload << std::endl;
                } else {
                    // Parse non-VLAN packet
                    TestPacket* packet = (TestPacket*)packet_data;

                    std::cout << "[RECV] Received packet #" << ntohl(packet->sequence_number) << std::endl;
                    std::cout << "       From MAC: " << std::hex;
                    for (int i = 0; i < 6; i++) {
                        std::cout << (int)packet->eth_header.ether_shost[i];
                        if (i < 5) std::cout << ":";
                    }
                    std::cout << std::dec << std::endl;
                    std::cout << "       Payload: " << packet->payload << std::endl;
                }

                received++;

                // Move to next packet in buffer using BPF alignment
                ptr += BPF_WORDALIGN(bpf_packet->bh_hdrlen + bpf_packet->bh_caplen);
            }
        }
    }

    close(sock);
#else
    // On Linux, use AF_PACKET
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        std::cerr << "[RECV] Failed to create socket. Run with sudo?" << std::endl;
        return;
    }

    // Bind to interface
    struct sockaddr_ll saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_ALL);
    saddr.sll_ifindex = get_interface_index(ifname);

    if (bind(sock, (struct sockaddr*)&saddr, sizeof(saddr)) < 0) {
        std::cerr << "[RECV] Failed to bind socket" << std::endl;
        close(sock);
        return;
    }

    char buffer[2048];
    int received = 0;
    uint64_t start_time_ms = get_time_ms();

    std::cout << "[RECV] Listening on " << ifname << " for test packets";
    if (vlan_id > 0) {
        std::cout << " (VLAN " << vlan_id << ")";
    }
    std::cout << " for " << total_recv_time_ms << "ms..." << std::endl;

    // Set read timeout to 100ms for more responsive timeout checking
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000;  // 100ms
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (running) {
        // Check if total receive time has elapsed
        uint64_t elapsed = get_time_ms() - start_time_ms;
        if (elapsed >= (uint64_t)total_recv_time_ms) {
            std::cout << "[RECV] Receive time expired (elapsed=" << elapsed
                      << "ms) after receiving " << received
                      << " packets" << std::endl;
            break;
        }
        ssize_t n = recvfrom(sock, buffer, sizeof(buffer), 0, nullptr, nullptr);
        if (n > 0) {
            unsigned char* packet_data = (unsigned char*)buffer;

            if (vlan_id > 0) {
                // Check for VLAN-tagged packet
                VlanTestPacket* packet = (VlanTestPacket*)packet_data;

                // Verify VLAN tag and ethertype
                if (ntohs(packet->vlan.tpid) == 0x8100 && ntohs(packet->ether_type) == ethertype) {
                    uint16_t received_vlan = ntohs(packet->vlan.tci) & 0x0FFF;

                    std::cout << "[RECV] Received VLAN packet #" << ntohl(packet->sequence_number) << std::endl;
                    std::cout << "       From MAC: " << std::hex;
                    for (int i = 0; i < 6; i++) {
                        std::cout << (int)packet->ether_shost[i];
                        if (i < 5) std::cout << ":";
                    }
                    std::cout << std::dec << std::endl;
                    std::cout << "       VLAN ID: " << received_vlan << std::endl;
                    std::cout << "       Payload: " << packet->payload << std::endl;

                    received++;
                }
            } else {
                // Parse non-VLAN packet
                TestPacket* packet = (TestPacket*)packet_data;

                // Filter for the specified ethertype
                if (ntohs(packet->eth_header.ether_type) == ethertype) {
                    std::cout << "[RECV] Received packet #" << ntohl(packet->sequence_number) << std::endl;
                    std::cout << "       From MAC: " << std::hex;
                    for (int i = 0; i < 6; i++) {
                        std::cout << (int)packet->eth_header.ether_shost[i];
                        if (i < 5) std::cout << ":";
                    }
                    std::cout << std::dec << std::endl;
                    std::cout << "       Payload: " << packet->payload << std::endl;

                    received++;
                }
            }
        }
    }

    close(sock);
#endif
    std::cout << "[RECV] Receiver thread finished" << std::endl;
}

void print_usage(const char* prog) {
    std::cout << "Usage:" << std::endl;
    std::cout << "  " << prog << " <send_interface> <recv_interface> <dest_mac> [ethertype] [vlan_id] [count] [interval_ms] [recv_timeout_ms]" << std::endl;
    std::cout << std::endl;
    std::cout << "Parameters:" << std::endl;
    std::cout << "  send_interface  - Interface to send packets from" << std::endl;
    std::cout << "  recv_interface  - Interface to receive packets on" << std::endl;
    std::cout << "  dest_mac        - Destination MAC address (use broadcast ff:ff:ff:ff:ff:ff for testing)" << std::endl;
    std::cout << "  ethertype       - Ethernet type field in hex (default: 0x88BF)" << std::endl;
    std::cout << "  vlan_id         - VLAN ID (0-4095, 0 = no VLAN tagging, default: 0)" << std::endl;
    std::cout << "  count           - Number of packets to send (default: 10)" << std::endl;
    std::cout << "  interval_ms     - Delay between sent packets in milliseconds (default: 500)" << std::endl;
    std::cout << "  recv_timeout_ms - Extra time to keep receiving after expected send completion (default: 2000)" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << prog << " en0 en1 ff:ff:ff:ff:ff:ff" << std::endl;
    std::cout << "  " << prog << " en0 en1 ff:ff:ff:ff:ff:ff 0x88BF" << std::endl;
    std::cout << "  " << prog << " en0 en1 ff:ff:ff:ff:ff:ff 0x88BF 100" << std::endl;
    std::cout << "  " << prog << " en0 en1 ff:ff:ff:ff:ff:ff 0x88BF 100 20 1000" << std::endl;
    std::cout << "  " << prog << " en0 en1 ff:ff:ff:ff:ff:ff 0x88BF 100 20 1000 3000" << std::endl;
    std::cout << "  " << prog << " eth0 eth1 aa:bb:cc:dd:ee:ff 0x9999 0 50 100 5000" << std::endl;
    std::cout << std::endl;
    std::cout << "Note: This program requires root privileges (run with sudo)" << std::endl;
    std::cout << "Note: Receiver runs for startup_delay + (count * interval_ms) + recv_timeout_ms" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        print_usage(argv[0]);
        return 1;
    }

    const char* send_interface = argv[1];
    const char* recv_interface = argv[2];

    // Parse destination MAC address
    unsigned char dest_mac[6];
    if (sscanf(argv[3], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &dest_mac[0], &dest_mac[1], &dest_mac[2],
               &dest_mac[3], &dest_mac[4], &dest_mac[5]) != 6) {
        std::cerr << "Invalid MAC address format. Use: xx:xx:xx:xx:xx:xx" << std::endl;
        return 1;
    }

    // Parse ethertype (default 0x88BF)
    uint16_t ethertype = 0x88BF;
    int next_arg = 4;
    if (argc > 4) {
        // Try to parse as hex ethertype
        unsigned int temp;
        if (sscanf(argv[4], "0x%x", &temp) == 1 || sscanf(argv[4], "%x", &temp) == 1) {
            ethertype = (uint16_t)temp;
            next_arg = 5;
        }
    }

    // Parse VLAN ID (default 0 = no VLAN)
    uint16_t vlan_id = 0;
    if (argc > next_arg) {
        int temp = atoi(argv[next_arg]);
        if (temp >= 0 && temp <= 4095) {
            vlan_id = (uint16_t)temp;
            next_arg++;
        }
    }

    int count = (argc > next_arg) ? atoi(argv[next_arg]) : 10;
    int interval_ms = (argc > next_arg + 1) ? atoi(argv[next_arg + 1]) : 500;
    int recv_timeout_ms = (argc > next_arg + 2) ? atoi(argv[next_arg + 2]) : 2000;

    std::cout << "=== Raw Packet Tester ===" << std::endl;
    std::cout << "Send Interface: " << send_interface << std::endl;
    std::cout << "Recv Interface: " << recv_interface << std::endl;
    std::cout << "Dest MAC: " << std::hex;
    for (int i = 0; i < 6; i++) {
        std::cout << (int)dest_mac[i];
        if (i < 5) std::cout << ":";
    }
    std::cout << std::dec << std::endl;
    std::cout << "EtherType: 0x" << std::hex << ethertype << std::dec << std::endl;
    if (vlan_id > 0) {
        std::cout << "VLAN ID: " << vlan_id << std::endl;
    } else {
        std::cout << "VLAN: disabled" << std::endl;
    }
    std::cout << "Packet count: " << count << std::endl;
    std::cout << "Send interval: " << interval_ms << "ms" << std::endl;
    std::cout << "Recv timeout: " << recv_timeout_ms << "ms after send complete" << std::endl;

    // Calculate total receive time: startup delay + send time + extra timeout
    int startup_delay_ms = 500;
    int total_recv_time_ms = startup_delay_ms + (count * interval_ms) + recv_timeout_ms;
    std::cout << "Total recv time: " << total_recv_time_ms << "ms" << std::endl;
    std::cout << "=========================" << std::endl << std::endl;

    // Start receiver thread first
    std::thread recv_thread(receiver_thread, recv_interface, ethertype, vlan_id, total_recv_time_ms);

    // Give receiver time to set up
    usleep(startup_delay_ms * 1000);

    // Start sender thread
    std::thread send_thread(sender_thread, send_interface, dest_mac, ethertype, vlan_id, count, interval_ms);

    // Wait for both threads to complete
    send_thread.join();
    recv_thread.join();

    std::cout << "\n=== Test Complete ===" << std::endl;

    return 0;
}
