# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository contains tools and configurations for prototyping TAGP (Time Agreement Protocol). The project consists of two main components:

1. **raw_packet_test**: A C++ testing tool for raw Ethernet packet transmission
2. **istax-configs**: Network switch configurations for a 4-switch test topology

## Development Commands

### Building the Raw Packet Test Tool

```bash
# From repository root
cd tools/raw_packet_test
mkdir -p build && cd build
cmake ..
make
```

The build system uses CMake and requires C++11. The binary will be created at `build/raw_packet_test`.

### Running the Raw Packet Test Tool

The tool requires root privileges to access raw sockets:

```bash
# Basic usage (must be run from build directory)
sudo ./raw_packet_test <send_interface> <recv_interface> <dest_mac> [ethertype] [vlan_id] [count] [interval_ms]

# Example with VLAN tagging
sudo ./raw_packet_test eth0 eth1 ff:ff:ff:ff:ff:ff 0x88BF 100 20 1000
```

## Architecture

### Raw Packet Test Tool

- **Platform Support**: Linux (using AF_PACKET raw sockets)
- **Threading Model**: Multi-threaded sender/receiver architecture
  - Receiver thread starts first and binds to the receive interface
  - After 500ms startup delay, sender thread begins transmission
  - Both threads run concurrently until receiver timeout expires
- **Packet Format**: Custom Ethernet frames with configurable EtherType (default 0x88BF)
  - Optional 802.1Q VLAN tagging support
  - Includes sequence numbers and timestamps for testing
  - Non-VLAN packets: 90 bytes, VLAN-tagged: 94 bytes
- **VLAN Handling**: Uses `PACKET_AUXDATA` and `recvmsg()` to access VLAN information
  - Linux kernel typically strips VLAN tags and provides them via auxiliary data
  - Tool handles both kernel-stripped and in-packet VLAN tags transparently
  - Reports VLAN TCI (Tag Control Information) and TPID from `tpacket_auxdata`
- **Key Feature**: Designed to detect packet duplication by processing all received packets within the timeout window

### Switch Configurations

The `istax-configs/` directory contains standalone configurations for 4 network switches in a fully-connected mesh topology:

- **Topology**: Switch N is connected to host N on port N, and to switch M on port M
  - Example for Switch 1: port 1 → host 1, port 2 → switch 2, port 3 → switch 3, port 4 → switch 4
  - Example for Switch 3: port 1 → switch 1, port 2 → switch 2, port 3 → host 3, port 4 → switch 4
- **ACL-Based Routing**: Uses MAC-based Access Control Lists to define explicit packet paths
  - ACL rules define forwarding for time sync packets from each source node
  - Direct connections forward to all other nodes
  - Indirect (via other switches) forward only to local node to avoid loops
- **Key Configurations**:
  - Spanning Tree Protocol: Disabled (explicit path control via ACLs)
  - VLAN 1: Management interface with static IP (192.0.2.x)
  - VLAN 10: Tagged traffic for time synchronization packets
  - MLD Snooping: Enabled to prevent IPv6 multicast loops
  - Port Mode: Hybrid on all GigabitEthernet ports (1/1-4)

**Important**: ACL order matters! ACE entries are executed in the order they are added, not by their numeric labels. The DENY ALL rule must be last.

### Configuration Evolution

The current switch configs use hardcoded static IPs for testing. In production, these will:
- Move to the tsn-scenarios repository
- Use DHCP for management interfaces
- Apply base configs with templating

## Project Structure

```
time-agreement/
├── tools/
│   └── raw_packet_test/       # C++ raw packet testing tool
│       ├── raw_packet_test.cpp
│       ├── CMakeLists.txt
│       └── README.md
├── istax-configs/              # Switch configurations
│   ├── switch-1.cfg
│   ├── switch-2.cfg
│   ├── switch-3.cfg
│   ├── switch-4.cfg
│   └── README.md
└── build/                      # CMake build directory (gitignored)
```
