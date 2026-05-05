#ifndef NETWORK_UTILS_H
#define NETWORK_UTILS_H

#include <cstdint>

// Get MAC address of an interface
bool get_mac_address(const char* ifname, unsigned char* mac);

// Get interface index
int get_interface_index(const char* ifname);

// Enable hardware timestamping on interface
bool enable_hw_timestamping(const char* ifname);

// Attach BPF filter to drop packets with matching source MAC
bool attach_bpf_filter_exclude_mac(int sock, const unsigned char* mac);

// Get current time in milliseconds
uint64_t get_time_ms();

#endif  // NETWORK_UTILS_H
