#include <arpa/inet.h>
#include <endian.h>
#include <linux/errqueue.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <thread>
#include <vector>

#include <cxxopts.hpp>

// Fixed ethertype for all packets
#define TEST_ETHERTYPE 0x88BF

// Fixed receive timeout after send completion (ms)
#define RECV_TIMEOUT_MS 2000

// VLAN header structure (802.1Q)
struct VlanHeader {
    uint16_t tpid;  // Tag Protocol Identifier (0x8100)
    uint16_t tci;   // Tag Control Information (PCP + DEI + VID)
} __attribute__((packed));

// Test packet structure with VLAN tag (VLAN is always used)
struct VlanTestPacket {
    unsigned char ether_dhost[6];
    unsigned char ether_shost[6];
    struct VlanHeader vlan;
    uint16_t ether_type;
    uint32_t sequence_number;
    uint32_t source_id;
    uint64_t timestamp;
    char payload[60];
} __attribute__((packed));

std::atomic<bool> running(true);

// Structure to hold a timestamped packet
struct PacketTimestamp {
    uint32_t sequence_number;
    uint32_t source_id;
    struct timespec timestamp;
    bool is_hardware;
};

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
        std::cerr << "[TSTAMP] Failed to enable hardware timestamping on " << ifname
                  << ": " << strerror(errno) << std::endl;
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
        std::cerr << "[RECV] Warning: Failed to attach BPF filter: " << strerror(errno) << std::endl;
        return false;
    }

    std::cout << "[RECV] BPF filter attached to drop packets from own MAC" << std::endl;
    return true;
}

// Retrieve TX timestamp from error queue
bool get_tx_timestamp(int sock, std::map<uint32_t, PacketTimestamp>& tx_timestamps, int timeout_ms) {
    // Poll for error queue with specified timeout
    struct pollfd pfd;
    pfd.fd = sock;
    pfd.events = POLLERR;
    pfd.revents = 0;

    int ret = poll(&pfd, 1, timeout_ms);
    if (ret <= 0) {
        return false;  // Timeout or error
    }

    char control[512];
    char data[2048];
    struct msghdr msg;
    struct iovec iov;

    memset(&msg, 0, sizeof(msg));
    iov.iov_base = data;
    iov.iov_len = sizeof(data);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    // Read from error queue
    ssize_t len = recvmsg(sock, &msg, MSG_ERRQUEUE);
    if (len < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            std::cerr << "[SEND] Error reading error queue: " << strerror(errno) << std::endl;
        }
        return false;
    }

    // Extract sequence number and source ID from the returned packet data
    uint32_t seq_num = 0;
    uint32_t src_id = 0;
    if (len >= (ssize_t)(sizeof(struct ether_header) + sizeof(uint32_t) + sizeof(uint32_t))) {
        // The packet data starts after the ethernet header
        // For VLAN packets: eth_header (18 bytes) + sequence_number (4 bytes) + source_id (4 bytes)
        unsigned char* packet_data = (unsigned char*)data;
        uint16_t ether_type = ntohs(*(uint16_t*)(packet_data + 12));

        if (ether_type == 0x8100) {
            // VLAN tagged - sequence number is at offset 18, source_id at offset 22
            seq_num = ntohl(*(uint32_t*)(packet_data + 18));
            src_id = ntohl(*(uint32_t*)(packet_data + 22));
        }
    }

    // Parse control messages for timestamps
    for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMPING) {
            struct timespec* ts_array = (struct timespec*)CMSG_DATA(cmsg);
            // ts_array[0] = software timestamp
            // ts_array[1] = hardware timestamp (deprecated)
            // ts_array[2] = hardware timestamp (raw)

            bool has_hw = (ts_array[2].tv_sec != 0 || ts_array[2].tv_nsec != 0);
            bool has_sw = (ts_array[0].tv_sec != 0 || ts_array[0].tv_nsec != 0);

            PacketTimestamp ts;
            ts.sequence_number = seq_num;
            ts.source_id = src_id;

            if (has_hw) {
                ts.timestamp = ts_array[2];
                ts.is_hardware = true;
                std::cout << "[TSTAMP] Packet #" << seq_num << " (src=" << src_id << ") TX timestamp (HW): " << ts_array[2].tv_sec << "."
                          << ts_array[2].tv_nsec << std::endl;
            } else if (has_sw) {
                ts.timestamp = ts_array[0];
                ts.is_hardware = false;
                std::cout << "[TSTAMP] Packet #" << seq_num << " (src=" << src_id << ") TX timestamp (SW): " << ts_array[0].tv_sec << "."
                          << ts_array[0].tv_nsec << std::endl;
            } else {
                return false;
            }

            tx_timestamps[seq_num] = ts;
            return true;
        }
    }

    return false;
}

// Thread to continuously drain TX timestamps from error queue
void tx_timestamp_thread(int sock, int expected_count, std::map<uint32_t, PacketTimestamp>& tx_timestamps) {
    std::cout << "[TSTAMP] TX timestamp collection thread started" << std::endl;

    int no_timestamp_count = 0;
    const int max_no_timestamp = 2000;  // Exit after 2000 * 1ms = 2 seconds with no timestamps

    while (running && no_timestamp_count < max_no_timestamp) {
        // Check if we've collected all expected timestamps
        if ((int)tx_timestamps.size() >= expected_count) {
            std::cout << "[TSTAMP] Collected all " << expected_count << " TX timestamps" << std::endl;
            break;
        }

        // Try to get a timestamp with 1ms timeout for fast polling
        if (get_tx_timestamp(sock, tx_timestamps, 1)) {
            no_timestamp_count = 0;  // Reset counter on success
        } else {
            no_timestamp_count++;
            // Don't sleep - loop immediately to poll as fast as possible
        }
    }

    if (no_timestamp_count >= max_no_timestamp) {
        std::cout << "[TSTAMP] TX timestamp collection timed out. Collected " << tx_timestamps.size() << "/" << expected_count << std::endl;
    }

    std::cout << "[TSTAMP] TX timestamp collection thread finished" << std::endl;
}

// Sender thread function
void sender_thread(const char* ifname,
                   const unsigned char* dest_mac,
                   uint16_t vlan_id,
                   uint32_t source_id,
                   int count,
                   int interval_ms,
                   std::map<uint32_t, PacketTimestamp>& tx_timestamps) {
    unsigned char src_mac[6];
    if (!get_mac_address(ifname, src_mac)) {
        std::cerr << "[SEND] Failed to get MAC address for " << ifname << std::endl;
        return;
    }

    std::cout << "[SEND] Source MAC: " << std::hex;
    for (int i = 0; i < 6; i++) {
        std::cout << (int)src_mac[i];
        if (i < 5) {
            std::cout << ":";
        }
    }
    std::cout << std::dec << std::endl;

    // Enable hardware timestamping on the interface first (via ioctl)
    enable_hw_timestamping(ifname);

    // Use Linux AF_PACKET
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

    // Increase socket error queue size to prevent timestamp drops at high rates
    int sndbuf = 1024 * 1024;  // 1MB send buffer
    if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0) {
        std::cerr << "[SEND] Warning: Failed to increase send buffer: " << strerror(errno) << std::endl;
    }

    // Enable transmit timestamping (both hardware and software)
    // The kernel will use hardware if available, otherwise fall back to software
    int timestamping_flags = SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_SOFTWARE |
                             SOF_TIMESTAMPING_RAW_HARDWARE;
    if (setsockopt(sock, SOL_SOCKET, SO_TIMESTAMPING, &timestamping_flags, sizeof(timestamping_flags)) < 0) {
        std::cerr << "[SEND] Warning: Failed to enable TX timestamping: " << strerror(errno) << std::endl;
    } else {
        std::cout << "[SEND] TX timestamping enabled (HW+SW)" << std::endl;
    }

    std::cout << "[SEND] Starting to send " << count << " packets on " << ifname << " (VLAN " << vlan_id << ")"
              << std::endl;

    // Start TX timestamp collection thread
    std::thread tx_ts_thread(tx_timestamp_thread, sock, count, std::ref(tx_timestamps));

    // Send packets (always VLAN-tagged)
    for (int i = 0; i < count && running; i++) {
        VlanTestPacket packet;
        memset(&packet, 0, sizeof(packet));

        // Fill ethernet header
        memcpy(packet.ether_dhost, dest_mac, 6);
        memcpy(packet.ether_shost, src_mac, 6);

        // Fill VLAN header (802.1Q)
        packet.vlan.tpid = htons(0x8100);           // VLAN tag identifier
        packet.vlan.tci = htons(vlan_id & 0x0FFF);  // VLAN ID (12 bits), PCP=0, DEI=0

        // EtherType comes after VLAN tag
        packet.ether_type = htons(TEST_ETHERTYPE);

        // Fill test data
        packet.sequence_number = htonl(i);
        packet.source_id = htonl(source_id);
        packet.timestamp = htobe64(time(nullptr));
        snprintf(packet.payload, sizeof(packet.payload), "Test packet #%d from source %u", i, source_id);

        // Use sendmsg to enable timestamp retrieval
        struct iovec iov;
        iov.iov_base = &packet;
        iov.iov_len = sizeof(packet);

        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        ssize_t sent = sendmsg(sock, &msg, 0);

        if (sent < 0) {
            std::cerr << "[SEND] Failed to send packet " << i << std::endl;
        } else {
            std::cout << "[SEND] Sent packet #" << i << " (" << sent << " bytes)" << std::endl;
        }

        usleep(interval_ms * 1000);
    }

    std::cout << "[SEND] All packets sent, waiting for TX timestamp collection to complete..." << std::endl;

    // Wait for TX timestamp thread to finish collecting timestamps
    tx_ts_thread.join();

    std::cout << "[SEND] Collected " << tx_timestamps.size() << "/" << count << " TX timestamps" << std::endl;

    close(sock);
    std::cout << "[SEND] Sender thread finished" << std::endl;
}

// Receiver thread function
void receiver_thread(const char* ifname,
                     uint16_t vlan_id,
                     int total_recv_time_ms,
                     std::vector<PacketTimestamp>& rx_timestamps) {
    // Use Linux AF_PACKET
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

    // Enable hardware timestamping on the interface first (via ioctl)
    enable_hw_timestamping(ifname);

    // Enable auxiliary data to receive VLAN information
    int val = 1;
    if (setsockopt(sock, SOL_PACKET, PACKET_AUXDATA, &val, sizeof(val)) < 0) {
        std::cerr << "[RECV] Warning: Failed to enable PACKET_AUXDATA" << std::endl;
    }

    // Enable receive timestamping (both hardware and software)
    int timestamping_flags = SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_SOFTWARE |
                             SOF_TIMESTAMPING_RAW_HARDWARE;
    if (setsockopt(sock, SOL_SOCKET, SO_TIMESTAMPING, &timestamping_flags, sizeof(timestamping_flags)) < 0) {
        std::cerr << "[RECV] Warning: Failed to enable RX timestamping: " << strerror(errno) << std::endl;
    } else {
        std::cout << "[RECV] RX timestamping enabled (HW+SW)" << std::endl;
    }

    // Attach BPF filter to drop packets from our own MAC (prevents local echo)
    unsigned char recv_mac[6];
    if (get_mac_address(ifname, recv_mac)) {
        attach_bpf_filter_exclude_mac(sock, recv_mac);
    } else {
        std::cerr << "[RECV] Warning: Could not get interface MAC for BPF filter" << std::endl;
    }

    char buffer[2048];
    // Increase control buffer to hold both VLAN auxdata and timestamps
    char control[CMSG_SPACE(sizeof(struct tpacket_auxdata)) + CMSG_SPACE(3 * sizeof(struct timespec))];
    int received = 0;
    uint64_t start_time_ms = get_time_ms();

    std::cout << "[RECV] Listening on " << ifname << " for test packets" << " (VLAN " << vlan_id << ")" << " for "
              << total_recv_time_ms << "ms..." << std::endl;

    // Set read timeout to 100ms for more responsive timeout checking
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000;  // 100ms
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (running) {
        // Check if total receive time has elapsed
        uint64_t elapsed = get_time_ms() - start_time_ms;
        if (elapsed >= (uint64_t)total_recv_time_ms) {
            std::cout << "[RECV] Receive time expired (elapsed=" << elapsed << "ms) after receiving " << received
                      << " packets" << std::endl;
            break;
        }

        // Use recvmsg to get auxiliary data (VLAN info)
        struct iovec iov;
        iov.iov_base = buffer;
        iov.iov_len = sizeof(buffer);

        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control;
        msg.msg_controllen = sizeof(control);

        ssize_t n = recvmsg(sock, &msg, 0);
        if (n > 0) {
            unsigned char* packet_data = (unsigned char*)buffer;

            // Extract VLAN info and timestamps from auxiliary data
            bool vlan_stripped = false;
            bool has_rx_timestamp = false;
            struct timespec rx_timestamp_sw = {0, 0};
            struct timespec rx_timestamp_hw = {0, 0};

            for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                if (cmsg->cmsg_level == SOL_PACKET && cmsg->cmsg_type == PACKET_AUXDATA) {
                    struct tpacket_auxdata* aux = (struct tpacket_auxdata*)CMSG_DATA(cmsg);
                    if (aux->tp_vlan_tci != 0 || aux->tp_status & TP_STATUS_VLAN_VALID) {
                        vlan_stripped = true;
                    }
                } else if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMPING) {
                    struct timespec* ts_array = (struct timespec*)CMSG_DATA(cmsg);
                    // ts_array[0] = software timestamp
                    // ts_array[1] = hardware timestamp (deprecated)
                    // ts_array[2] = hardware timestamp (raw)

                    if (ts_array[2].tv_sec != 0 || ts_array[2].tv_nsec != 0) {
                        rx_timestamp_hw = ts_array[2];
                        has_rx_timestamp = true;
                    } else if (ts_array[0].tv_sec != 0 || ts_array[0].tv_nsec != 0) {
                        rx_timestamp_sw = ts_array[0];
                        has_rx_timestamp = true;
                    }
                }
            }

            // Always expecting VLAN-tagged packets
            uint32_t seq_num = 0;
            uint32_t src_id = 0;
            bool valid_packet = false;

            // Check if kernel stripped the VLAN tag
            if (vlan_stripped) {
                // VLAN was stripped, ethertype is now at offset 12
                uint16_t ether_type = ntohs(*(uint16_t*)(packet_data + 12));

                if (ether_type == TEST_ETHERTYPE) {
                    seq_num = ntohl(*(uint32_t*)(packet_data + 14));  // Sequence number after ethertype
                    src_id = ntohl(*(uint32_t*)(packet_data + 18));   // Source ID after sequence number
                    valid_packet = true;
                    std::cout << "[RECV] Received VLAN packet #" << seq_num << " (src=" << src_id << ") (kernel-stripped)" << std::endl;
                }
            } else {
                // VLAN still in packet (not stripped)
                VlanTestPacket* vlan_packet = (VlanTestPacket*)packet_data;
                if (ntohs(vlan_packet->vlan.tpid) == 0x8100 && ntohs(vlan_packet->ether_type) == TEST_ETHERTYPE) {
                    seq_num = ntohl(vlan_packet->sequence_number);
                    src_id = ntohl(vlan_packet->source_id);
                    valid_packet = true;
                    std::cout << "[RECV] Received VLAN packet #" << seq_num << " (src=" << src_id << ") (in-packet)" << std::endl;
                }
            }

            if (valid_packet) {
                // Store RX timestamp
                if (has_rx_timestamp) {
                    PacketTimestamp ts;
                    ts.sequence_number = seq_num;
                    ts.source_id = src_id;

                    if (rx_timestamp_hw.tv_sec != 0 || rx_timestamp_hw.tv_nsec != 0) {
                        ts.timestamp = rx_timestamp_hw;
                        ts.is_hardware = true;
                        std::cout << "       RX timestamp (HW): " << rx_timestamp_hw.tv_sec << "."
                                  << rx_timestamp_hw.tv_nsec << std::endl;
                    } else {
                        ts.timestamp = rx_timestamp_sw;
                        ts.is_hardware = false;
                        std::cout << "       RX timestamp (SW): " << rx_timestamp_sw.tv_sec << "."
                                  << rx_timestamp_sw.tv_nsec << std::endl;
                    }

                    rx_timestamps.push_back(ts);
                }

                received++;
            }
        }
    }

    close(sock);
    std::cout << "[RECV] Receiver thread finished" << std::endl;
}

int main(int argc, char* argv[]) {
    try {
        cxxopts::Options options("packet_latency_measurement", "Packet latency measurement tool with hardware timestamping support");

        options.add_options()("s,send-interface", "Interface to send packets from", cxxopts::value<std::string>())(
            "r,recv-interface", "Interface to receive packets on", cxxopts::value<std::string>())(
            "d,dest-mac", "Destination MAC address", cxxopts::value<std::string>()->default_value("ff:ff:ff:ff:ff:ff"))(
            "v,vlan-id", "VLAN ID (1-4095)", cxxopts::value<int>()->default_value("10"))(
            "source-id", "Source ID to include in packet payload (required)", cxxopts::value<uint32_t>())(
            "c,count", "Number of packets to send", cxxopts::value<int>()->default_value("10"))(
            "i,interval", "Delay between sent packets in milliseconds", cxxopts::value<int>()->default_value("500"))(
            "o,output", "CSV file to write timestamp data", cxxopts::value<std::string>())("h,help", "Print usage");

        options.parse_positional({"send-interface", "recv-interface"});
        options.positional_help("<send_interface> <recv_interface>");

        auto result = options.parse(argc, argv);

        if (result.count("help")) {
            std::cout << options.help() << std::endl;
            std::cout << "\nNote: EtherType is fixed at 0x88BF" << std::endl;
            std::cout << "Note: All packets are VLAN-tagged" << std::endl;
            std::cout << "Note: Receive timeout is fixed at 2000ms after send completion" << std::endl;
            std::cout << "Note: This program requires root privileges (run with sudo)" << std::endl;
            std::cout << "\nExamples:" << std::endl;
            std::cout << "  " << argv[0] << " eth0 eth1 --source-id 1" << std::endl;
            std::cout << "  " << argv[0] << " -s eth0 -r eth1 --source-id 1 -v 100 -c 20 -i 1000" << std::endl;
            std::cout << "  " << argv[0] << " eth0 eth1 --source-id 1 -o timestamps.csv" << std::endl;
            return 0;
        }

        // Check required arguments
        if (!result.count("send-interface") || !result.count("recv-interface") || !result.count("source-id")) {
            std::cerr << "Error: Missing required arguments (send-interface, recv-interface, and source-id)" << std::endl;
            std::cerr << "Run with --help for usage information" << std::endl;
            return 1;
        }

        std::string send_interface_str = result["send-interface"].as<std::string>();
        std::string recv_interface_str = result["recv-interface"].as<std::string>();
        std::string dest_mac_str = result["dest-mac"].as<std::string>();
        int vlan_id_int = result["vlan-id"].as<int>();
        uint32_t source_id = result["source-id"].as<uint32_t>();
        int count = result["count"].as<int>();
        int interval_ms = result["interval"].as<int>();

        // Store CSV file path if provided
        std::string csv_file_str;
        const char* csv_file = nullptr;
        if (result.count("output")) {
            csv_file_str = result["output"].as<std::string>();
            csv_file = csv_file_str.c_str();
        }

        // Convert interfaces to const char* for thread compatibility
        const char* send_interface = send_interface_str.c_str();
        const char* recv_interface = recv_interface_str.c_str();

        // Validate VLAN ID
        if (vlan_id_int < 1 || vlan_id_int > 4095) {
            std::cerr << "Invalid VLAN ID. Must be between 1 and 4095." << std::endl;
            return 1;
        }
        uint16_t vlan_id = (uint16_t)vlan_id_int;

        // Parse destination MAC address
        unsigned char dest_mac[6];
        if (sscanf(dest_mac_str.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dest_mac[0], &dest_mac[1], &dest_mac[2],
                   &dest_mac[3], &dest_mac[4], &dest_mac[5]) != 6) {
            std::cerr << "Invalid MAC address format. Use: xx:xx:xx:xx:xx:xx" << std::endl;
            return 1;
        }

        std::cout << "=== Raw Packet Tester ===" << std::endl;
        std::cout << "Send Interface: " << send_interface << std::endl;
        std::cout << "Recv Interface: " << recv_interface << std::endl;
        std::cout << "Dest MAC: " << std::hex;
        for (int i = 0; i < 6; i++) {
            std::cout << (int)dest_mac[i];
            if (i < 5) {
                std::cout << ":";
            }
        }
        std::cout << std::dec << std::endl;
        std::cout << "EtherType: 0x" << std::hex << TEST_ETHERTYPE << std::dec << std::endl;
        std::cout << "VLAN ID: " << vlan_id << std::endl;
        std::cout << "Source ID: " << source_id << std::endl;
        std::cout << "Packet count: " << count << std::endl;
        std::cout << "Send interval: " << interval_ms << "ms" << std::endl;
        std::cout << "Recv timeout: " << RECV_TIMEOUT_MS << "ms after send complete" << std::endl;

        // Calculate total receive time: startup delay + send time + extra timeout
        int startup_delay_ms = 500;
        int total_recv_time_ms = startup_delay_ms + (count * interval_ms) + RECV_TIMEOUT_MS;
        std::cout << "Total recv time: " << total_recv_time_ms << "ms" << std::endl;
        std::cout << "=========================" << std::endl << std::endl;

        // Timestamp storage
        std::map<uint32_t, PacketTimestamp> tx_timestamps;
        std::vector<PacketTimestamp> rx_timestamps;

        // Start receiver thread first
        std::thread recv_thread(receiver_thread, recv_interface, vlan_id, total_recv_time_ms, std::ref(rx_timestamps));

        // Give receiver time to set up
        usleep(startup_delay_ms * 1000);

        // Start sender thread
        std::thread send_thread(sender_thread, send_interface, dest_mac, vlan_id, source_id, count, interval_ms,
                                std::ref(tx_timestamps));

        // Wait for both threads to complete
        send_thread.join();
        recv_thread.join();

        std::cout << "\n=== Test Complete ===" << std::endl;
        std::cout << "TX timestamps collected: " << tx_timestamps.size() << std::endl;
        std::cout << "RX timestamps collected: " << rx_timestamps.size() << std::endl;

        // Calculate and print deltas
        std::cout << "\n=== Timestamp Deltas (TX -> RX) ===" << std::endl;
        for (const auto& rx_ts : rx_timestamps) {
            auto tx_it = tx_timestamps.find(rx_ts.sequence_number);
            if (tx_it != tx_timestamps.end() && tx_it->second.source_id == rx_ts.source_id) {
                const PacketTimestamp& tx_ts = tx_it->second;

                // Calculate delta in nanoseconds
                int64_t delta_sec = rx_ts.timestamp.tv_sec - tx_ts.timestamp.tv_sec;
                int64_t delta_nsec = rx_ts.timestamp.tv_nsec - tx_ts.timestamp.tv_nsec;
                int64_t delta_ns = (delta_sec * 1000000000LL) + delta_nsec;

                std::cout << "Packet #" << rx_ts.sequence_number << " (src=" << rx_ts.source_id << "): " << delta_ns << " ns"
                          << " [TX=" << (tx_ts.is_hardware ? "HW" : "SW")
                          << ", RX=" << (rx_ts.is_hardware ? "HW" : "SW") << "]" << std::endl;
            } else {
                std::cout << "Packet #" << rx_ts.sequence_number << " (src=" << rx_ts.source_id << "): No matching TX timestamp found" << std::endl;
            }
        }

        // Write to CSV file if specified
        if (csv_file != nullptr) {
            std::ofstream csv(csv_file);
            if (csv.is_open()) {
                // Write CSV header with direction and interface columns
                csv << "direction,interface,sequence_number,source_id,timestamp_sec,timestamp_nsec,type" << std::endl;

                // Write TX timestamps
                for (const auto& tx_pair : tx_timestamps) {
                    const PacketTimestamp& tx_ts = tx_pair.second;
                    csv << "TX," << send_interface << "," << tx_ts.sequence_number << "," << tx_ts.source_id << ","
                        << tx_ts.timestamp.tv_sec << "," << std::setw(9) << std::setfill('0') << tx_ts.timestamp.tv_nsec << ","
                        << (tx_ts.is_hardware ? "HW" : "SW") << std::endl;
                }

                // Write RX timestamps
                for (const auto& rx_ts : rx_timestamps) {
                    csv << "RX," << recv_interface << "," << rx_ts.sequence_number << "," << rx_ts.source_id << ","
                        << rx_ts.timestamp.tv_sec << "," << std::setw(9) << std::setfill('0') << rx_ts.timestamp.tv_nsec << ","
                        << (rx_ts.is_hardware ? "HW" : "SW") << std::endl;
                }

                csv.close();
                std::cout << "\nTimestamp data written to: " << csv_file << std::endl;
            } else {
                std::cerr << "Error: Failed to open CSV file for writing: " << csv_file << std::endl;
            }
        }

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error parsing options: " << e.what() << std::endl;
        return 1;
    }
}
