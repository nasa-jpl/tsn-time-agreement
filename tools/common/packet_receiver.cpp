#include "packet_receiver.h"

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/net_tstamp.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <iostream>

#include "network_utils.h"

PacketReceiver::PacketReceiver(const std::string& interface, uint16_t vlan_id, bool enable_timestamps)
    : interface_(interface), vlan_id_(vlan_id), enable_timestamps_(enable_timestamps), sock_(-1), should_stop_(false) {}

PacketReceiver::~PacketReceiver() {
    if (sock_ >= 0) {
        close(sock_);
    }
}

bool PacketReceiver::createSocket() {
    // Use Linux AF_PACKET
    sock_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_ < 0) {
        std::cerr << "[RECV] Failed to create socket. Run with sudo?" << std::endl;
        return false;
    }

    // Bind to interface
    struct sockaddr_ll saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_ALL);
    saddr.sll_ifindex = get_interface_index(interface_.c_str());

    if (bind(sock_, (struct sockaddr*)&saddr, sizeof(saddr)) < 0) {
        std::cerr << "[RECV] Failed to bind socket" << std::endl;
        close(sock_);
        sock_ = -1;
        return false;
    }

    if (enable_timestamps_) {
        // Enable hardware timestamping on the interface (non-fatal if it fails)
        if (!enable_hw_timestamping(interface_.c_str())) {
            std::cout << "[RECV] Hardware timestamping not available, will use software timestamps" << std::endl;
        }

        // Increase receive buffer to handle high packet rates
        int rcvbuf = 8 * 1024 * 1024;  // 8MB
        if (setsockopt(sock_, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
            std::cerr << "[RECV] Warning: Failed to increase receive buffer: " << strerror(errno) << std::endl;
        }

        // Enable auxiliary data to receive VLAN information
        int val = 1;
        if (setsockopt(sock_, SOL_PACKET, PACKET_AUXDATA, &val, sizeof(val)) < 0) {
            std::cerr << "[RECV] Warning: Failed to enable PACKET_AUXDATA: " << strerror(errno) << std::endl;
        }

        // Enable receive timestamping (both hardware and software)
        int timestamping_flags = SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_RX_HARDWARE |
                                 SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RAW_HARDWARE;
        if (setsockopt(sock_, SOL_SOCKET, SO_TIMESTAMPING, &timestamping_flags, sizeof(timestamping_flags)) < 0) {
            std::cerr << "[RECV] Warning: Failed to enable HW timestamping: " << strerror(errno) << std::endl;
            // Try software-only as fallback
            timestamping_flags = SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE;
            if (setsockopt(sock_, SOL_SOCKET, SO_TIMESTAMPING, &timestamping_flags, sizeof(timestamping_flags)) < 0) {
                std::cerr << "[RECV] Warning: Failed to enable SW timestamping: " << strerror(errno) << std::endl;
            } else {
                std::cout << "[RECV] RX timestamping enabled (SW only)" << std::endl;
            }
        } else {
            std::cout << "[RECV] RX timestamping enabled (HW+SW)" << std::endl;
        }

        // Note: BPF filter disabled on this platform due to compatibility issues
        // Packets are filtered by source_id in post-processing instead
        std::cout << "[RECV] Note: BPF MAC filtering disabled (filter by source_id in CSV output)" << std::endl;
    } else {
        std::cout << "[RECV] RX timestamping disabled" << std::endl;
    }

    // Set read timeout to 100ms for more responsive timeout checking
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000;  // 100ms
    setsockopt(sock_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    return true;
}

int PacketReceiver::receive(int duration_ms) {
    if (!createSocket()) {
        return 0;
    }

    char buffer[2048];
    // Increase control buffer to hold both VLAN auxdata and timestamps
    char control[CMSG_SPACE(sizeof(struct tpacket_auxdata)) + CMSG_SPACE(3 * sizeof(struct timespec))];
    int received = 0;
    uint64_t start_time_ms = get_time_ms();

    std::cout << "[RECV] Listening on " << interface_ << " for test packets" << " (VLAN " << vlan_id_ << ")" << " for "
              << duration_ms << "ms..." << std::endl;

    should_stop_ = false;

    while (!should_stop_) {
        // Check if total receive time has elapsed
        uint64_t elapsed = get_time_ms() - start_time_ms;
        if (elapsed >= (uint64_t)duration_ms) {
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

        ssize_t n = recvmsg(sock_, &msg, 0);

        if (n > 0) {
            unsigned char* packet_data = (unsigned char*)buffer;

            // Extract VLAN info and timestamps from auxiliary data
            bool vlan_stripped = false;
            bool has_rx_timestamp = false;
            struct timespec rx_timestamp_sw = {0, 0};
            struct timespec rx_timestamp_hw = {0, 0};

            if (enable_timestamps_) {
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
            } else {
                // Even with timestamps disabled, we still need to check for VLAN stripping
                for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                    if (cmsg->cmsg_level == SOL_PACKET && cmsg->cmsg_type == PACKET_AUXDATA) {
                        struct tpacket_auxdata* aux = (struct tpacket_auxdata*)CMSG_DATA(cmsg);
                        if (aux->tp_vlan_tci != 0 || aux->tp_status & TP_STATUS_VLAN_VALID) {
                            vlan_stripped = true;
                        }
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
#ifdef _DEBUG
                    std::cout << "[RECV] Received VLAN packet #" << seq_num << " (src=" << src_id
                              << ") (kernel-stripped)" << std::endl;
#endif
                }
            } else {
                // VLAN still in packet (not stripped)
                VlanTestPacket* vlan_packet = (VlanTestPacket*)packet_data;
                if (ntohs(vlan_packet->vlan.tpid) == 0x8100 && ntohs(vlan_packet->ether_type) == TEST_ETHERTYPE) {
                    seq_num = ntohl(vlan_packet->sequence_number);
                    src_id = ntohl(vlan_packet->source_id);
                    valid_packet = true;
#ifdef _DEBUG
                    std::cout << "[RECV] Received VLAN packet #" << seq_num << " (src=" << src_id << ") (in-packet)"
                              << std::endl;
#endif
                }
            }

            if (valid_packet) {
                // Store RX timestamp if enabled
                if (enable_timestamps_ && has_rx_timestamp) {
                    PacketTimestamp ts;
                    ts.sequence_number = seq_num;
                    ts.source_id = src_id;

                    if (rx_timestamp_hw.tv_sec != 0 || rx_timestamp_hw.tv_nsec != 0) {
                        ts.timestamp = rx_timestamp_hw;
                        ts.is_hardware = true;
#ifdef _DEBUG
                        std::cout << "       RX timestamp (HW): " << rx_timestamp_hw.tv_sec << "."
                                  << rx_timestamp_hw.tv_nsec << std::endl;
#endif
                    } else {
                        ts.timestamp = rx_timestamp_sw;
                        ts.is_hardware = false;
#ifdef _DEBUG
                        std::cout << "       RX timestamp (SW): " << rx_timestamp_sw.tv_sec << "."
                                  << rx_timestamp_sw.tv_nsec << std::endl;
#endif
                    }

                    rx_timestamps_.push_back(ts);
                }

                received++;
            }
        }
    }

    std::cout << "[RECV] Receiver finished" << std::endl;
    return received;
}

void PacketReceiver::stop() {
    should_stop_ = true;
}
