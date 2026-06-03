#ifndef PACKET_RECEIVER_H
#define PACKET_RECEIVER_H

#include <atomic>
#include <string>
#include <vector>

#include "packet_common.h"

class PacketReceiver {
   public:
    PacketReceiver(const std::string& interface, uint16_t vlan_id, bool enable_timestamps = true);
    ~PacketReceiver();

    // Receive packets for specified duration
    // Returns number of packets received
    int receive(int duration_ms);

    // Stop receiving (can be called from another thread to interrupt)
    void stop();

    // Get collected RX timestamps
    const std::vector<PacketTimestamp>& getRxTimestamps() const { return rx_timestamps_; }

   private:
    std::string interface_;
    uint16_t vlan_id_;
    bool enable_timestamps_;

    int sock_;
    std::vector<PacketTimestamp> rx_timestamps_;
    std::atomic<bool> should_stop_;

    // Helper to create and bind socket
    bool createSocket();
};

#endif  // PACKET_RECEIVER_H
