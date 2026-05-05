#ifndef PACKET_COMMON_H
#define PACKET_COMMON_H

#include <cstdint>
#include <ctime>

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

// Structure to hold a timestamped packet
struct PacketTimestamp {
    uint32_t sequence_number;
    uint32_t source_id;
    struct timespec timestamp;
    bool is_hardware;
};

#endif  // PACKET_COMMON_H
