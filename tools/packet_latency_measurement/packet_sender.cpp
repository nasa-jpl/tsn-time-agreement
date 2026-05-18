#include "packet_sender.h"

#include <arpa/inet.h>
#include <endian.h>
#include <linux/errqueue.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <linux/net_tstamp.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>

#include "network_utils.h"

PacketSender::PacketSender(const std::string& interface, const unsigned char* dest_mac, uint16_t vlan_id,
                           uint32_t source_id)
    : interface_(interface), vlan_id_(vlan_id), source_id_(source_id), sock_(-1), should_stop_(false) {
    memcpy(dest_mac_, dest_mac, 6);
}

PacketSender::~PacketSender() {
    if (sock_ >= 0) {
        close(sock_);
    }
}

bool PacketSender::createSocket() {
    // Use Linux AF_PACKET
    sock_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_ < 0) {
        std::cerr << "[SEND] Failed to create socket. Run with sudo?" << std::endl;
        return false;
    }

    // Bind to interface
    struct sockaddr_ll saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_ALL);
    saddr.sll_ifindex = get_interface_index(interface_.c_str());

    if (bind(sock_, (struct sockaddr*)&saddr, sizeof(saddr)) < 0) {
        std::cerr << "[SEND] Failed to bind socket" << std::endl;
        close(sock_);
        sock_ = -1;
        return false;
    }

    // Enable hardware timestamping on the interface (non-fatal if it fails)
    if (!enable_hw_timestamping(interface_.c_str())) {
        std::cout << "[SEND] Hardware timestamping not available, will use software timestamps" << std::endl;
    }

    // Attach BPF filter to DROP all incoming packets on sender socket
    // This prevents the receive buffer from filling up and blocking the error queue
    struct sock_filter drop_all_filter[] = {
        BPF_STMT(BPF_RET | BPF_K, 0),  // Return 0 = drop all packets
    };
    struct sock_fprog drop_all_bpf = {
        .len = sizeof(drop_all_filter) / sizeof(drop_all_filter[0]),
        .filter = drop_all_filter,
    };
    if (setsockopt(sock_, SOL_SOCKET, SO_ATTACH_FILTER, &drop_all_bpf, sizeof(drop_all_bpf)) < 0) {
        std::cerr << "[SEND] Warning: Failed to attach BPF filter to drop incoming packets: " << strerror(errno)
                  << std::endl;
    } else {
        std::cout << "[SEND] BPF filter attached to drop all incoming packets (TX-only mode)" << std::endl;
    }

    // Increase socket buffers to handle high packet rates
    int sndbuf = 8 * 1024 * 1024;  // 8MB send buffer
    if (setsockopt(sock_, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0) {
        std::cerr << "[SEND] Warning: Failed to increase send buffer: " << strerror(errno) << std::endl;
    }

    int rcvbuf = 8 * 1024 * 1024;  // 8MB receive buffer
    if (setsockopt(sock_, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
        std::cerr << "[SEND] Warning: Failed to increase receive buffer: " << strerror(errno) << std::endl;
    } else {
        std::cout << "[SEND] Socket buffers increased (8MB each) to handle high packet rates" << std::endl;
    }

    // Enable transmit timestamping (both hardware and software)
    int timestamping_flags = SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_TX_HARDWARE |
                             SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RAW_HARDWARE;
    if (setsockopt(sock_, SOL_SOCKET, SO_TIMESTAMPING, &timestamping_flags, sizeof(timestamping_flags)) < 0) {
        std::cerr << "[SEND] Warning: Failed to enable HW timestamping: " << strerror(errno) << std::endl;
        // Try software-only as fallback
        timestamping_flags = SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE;
        if (setsockopt(sock_, SOL_SOCKET, SO_TIMESTAMPING, &timestamping_flags, sizeof(timestamping_flags)) < 0) {
            std::cerr << "[SEND] Warning: Failed to enable SW timestamping: " << strerror(errno) << std::endl;
        } else {
            std::cout << "[SEND] TX timestamping enabled (SW only)" << std::endl;
        }
    } else {
        std::cout << "[SEND] TX timestamping enabled (HW+SW)" << std::endl;
    }

    return true;
}

void PacketSender::txTimestampCollectionThread(int expected_count) {
    std::cout << "[TSTAMP] TX timestamp collection thread started" << std::endl;

    int consecutive_failures = 0;
    const int max_consecutive_failures = 2000;  // Exit after 2000 consecutive failures
    int drain_counter = 0;

    while (!should_stop_ && consecutive_failures < max_consecutive_failures) {
        // Check if we've collected all expected timestamps
        if ((int)tx_timestamps_.size() >= expected_count) {
            std::cout << "[TSTAMP] Collected all " << expected_count << " TX timestamps" << std::endl;
            break;
        }

        // Drain the regular receive buffer to prevent it from filling up
        // (sender socket may receive packets if send_interface == recv_interface)
        char discard[2048];
        while (recv(sock_, discard, sizeof(discard), MSG_DONTWAIT) > 0) {
            drain_counter++;
        }

        // Try to drain error queue
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

        // Read from error queue (non-blocking)
        ssize_t len = recvmsg(sock_, &msg, MSG_ERRQUEUE | MSG_DONTWAIT);

        if (len > 0) {
            consecutive_failures = 0;  // Reset on success

            // Extract sequence number and source ID
            uint32_t seq_num = 0;
            uint32_t src_id = 0;
            if (len >= (ssize_t)(sizeof(struct ether_header) + sizeof(uint32_t) + sizeof(uint32_t))) {
                unsigned char* packet_data = (unsigned char*)data;
                uint16_t ether_type = ntohs(*(uint16_t*)(packet_data + 12));

                if (ether_type == 0x8100) {
                    seq_num = ntohl(*(uint32_t*)(packet_data + 18));
                    src_id = ntohl(*(uint32_t*)(packet_data + 22));
                }
            }

            // Parse control messages for timestamps
            for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMPING) {
                    struct timespec* ts_array = (struct timespec*)CMSG_DATA(cmsg);
                    bool has_hw = (ts_array[2].tv_sec != 0 || ts_array[2].tv_nsec != 0);
                    bool has_sw = (ts_array[0].tv_sec != 0 || ts_array[0].tv_nsec != 0);

                    PacketTimestamp ts;
                    ts.sequence_number = seq_num;
                    ts.source_id = src_id;

                    if (has_hw) {
                        ts.timestamp = ts_array[2];
                        ts.is_hardware = true;
                        std::cout << "[TSTAMP] Packet #" << seq_num << " (src=" << src_id << ") TX timestamp (HW): "
                                  << ts_array[2].tv_sec << "." << ts_array[2].tv_nsec << std::endl;
                    } else if (has_sw) {
                        ts.timestamp = ts_array[0];
                        ts.is_hardware = false;
                        std::cout << "[TSTAMP] Packet #" << seq_num << " (src=" << src_id << ") TX timestamp (SW): "
                                  << ts_array[0].tv_sec << "." << ts_array[0].tv_nsec << std::endl;
                    }

                    if (has_hw || has_sw) {
                        tx_timestamps_[seq_num] = ts;
                    }
                }
            }
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                consecutive_failures++;
                usleep(1000);  // 1ms sleep when no data
            } else {
                std::cerr << "[TSTAMP] Error reading error queue: " << strerror(errno) << std::endl;
                consecutive_failures++;
                usleep(1000);
            }
        }
    }

    if (consecutive_failures >= max_consecutive_failures) {
        std::cout << "[TSTAMP] TX timestamp collection timed out. Collected " << tx_timestamps_.size() << "/"
                  << expected_count << std::endl;
    }

    if (drain_counter > 0) {
        std::cout << "[TSTAMP] Drained " << drain_counter << " packets from sender socket receive buffer"
                  << std::endl;
    }

    std::cout << "[TSTAMP] TX timestamp collection thread finished" << std::endl;
}

int PacketSender::send(int count, int interval_ms) {
    if (!createSocket()) {
        return 0;
    }

    unsigned char src_mac[6];
    if (!get_mac_address(interface_.c_str(), src_mac)) {
        std::cerr << "[SEND] Failed to get MAC address for " << interface_ << std::endl;
        return 0;
    }

    std::cout << "[SEND] Source MAC: " << std::hex;
    for (int i = 0; i < 6; i++) {
        std::cout << (int)src_mac[i];
        if (i < 5) {
            std::cout << ":";
        }
    }
    std::cout << std::dec << std::endl;

    std::cout << "[SEND] Starting to send " << count << " packets on " << interface_ << " (VLAN " << vlan_id_ << ")"
              << std::endl;

    // Start TX timestamp collection thread
    should_stop_ = false;
    tx_timestamp_thread_ = std::thread(&PacketSender::txTimestampCollectionThread, this, count);

    int sent_count = 0;

    // Send packets (always VLAN-tagged)
    for (int i = 0; i < count && !should_stop_; i++) {
        VlanTestPacket packet;
        memset(&packet, 0, sizeof(packet));

        // Fill ethernet header
        memcpy(packet.ether_dhost, dest_mac_, 6);
        memcpy(packet.ether_shost, src_mac, 6);

        // Fill VLAN header (802.1Q)
        packet.vlan.tpid = htons(0x8100);           // VLAN tag identifier
        packet.vlan.tci = htons(vlan_id_ & 0x0FFF);  // VLAN ID (12 bits), PCP=0, DEI=0

        // EtherType comes after VLAN tag
        packet.ether_type = htons(TEST_ETHERTYPE);

        // Fill test data
        packet.sequence_number = htonl(i);
        packet.source_id = htonl(source_id_);
        packet.timestamp = htobe64(time(nullptr));
        snprintf(packet.payload, sizeof(packet.payload), "Test packet #%d from source %u", i, source_id_);

        // Use sendmsg to enable timestamp retrieval
        struct iovec iov;
        iov.iov_base = &packet;
        iov.iov_len = sizeof(packet);

        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        ssize_t sent = sendmsg(sock_, &msg, 0);

        if (sent < 0) {
            std::cerr << "[SEND] Failed to send packet " << i << std::endl;
        } else {
            std::cout << "[SEND] Sent packet #" << i << " (" << sent << " bytes)" << std::endl;
            sent_count++;
        }

        usleep(interval_ms * 1000);
    }

    std::cout << "[SEND] All packets sent, waiting for TX timestamp collection to complete..." << std::endl;

    // Wait for TX timestamp thread to finish collecting timestamps
    if (tx_timestamp_thread_.joinable()) {
        tx_timestamp_thread_.join();
    }

    std::cout << "[SEND] Collected " << tx_timestamps_.size() << "/" << count << " TX timestamps" << std::endl;

    return sent_count;
}

void PacketSender::stop() {
    should_stop_ = true;
}
