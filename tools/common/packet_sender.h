#ifndef PACKET_SENDER_H
#define PACKET_SENDER_H

#include <atomic>
#include <map>
#include <string>
#include <thread>

#include "packet_common.h"

class PacketSender {
   public:
    PacketSender(const std::string& interface, const unsigned char* dest_mac, uint16_t vlan_id, uint32_t source_id,
                 bool enable_timestamps = true, int priority = 0, bool enable_txtime = false, int txtime_clockid = 0);
    ~PacketSender();

    // Send packets with specified count and interval
    // Returns number of packets successfully sent
    int send(int count, int interval_ms);

    // Stop sending (can be called from another thread to interrupt)
    void stop();

    // Get collected TX timestamps
    const std::map<uint32_t, PacketTimestamp>& getTxTimestamps() const { return tx_timestamps_; }

   private:
    std::string interface_;
    unsigned char dest_mac_[6];
    uint16_t vlan_id_;
    uint32_t source_id_;
    bool enable_timestamps_;
    int priority_;
    bool enable_txtime_;
    int txtime_clockid_;

    int sock_;
    std::map<uint32_t, PacketTimestamp> tx_timestamps_;
    std::thread tx_timestamp_thread_;
    std::atomic<bool> should_stop_;

    // TX timestamp collection thread function
    void txTimestampCollectionThread(int expected_count);

    // Helper to create and bind socket
    bool createSocket();
};

#endif  // PACKET_SENDER_H
