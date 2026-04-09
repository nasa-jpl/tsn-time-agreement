# Raw Packet Tester

A multi-threaded C++ program for testing raw ethernet packet transmission between two network interfaces.

## Features

- Sends and receives raw ethernet frames simultaneously using multi-threading
- Configurable EtherType field (default: 0x88BF)
- Optional VLAN tagging support (802.1Q)
- Works on both macOS (using BPF) and (UNTESTED) Linux (using AF_PACKET)
- Custom test packet format with sequence numbers and timestamps
- Broadcast or unicast MAC addressing support

## Building

```bash
mkdir build
cd build
cmake ..
make
```

## Usage

The program requires root privileges to access raw sockets.

### Syntax
```bash
sudo ./raw_packet_test <send_interface> <recv_interface> <dest_mac> [ethertype] [vlan_id] [count] [interval_ms]
```

### Parameters
- `send_interface` - Network interface to send packets from (e.g., en0, eth0)
- `recv_interface` - Network interface to receive packets on (e.g., en1, eth1)
- `dest_mac` - Destination MAC address (use `ff:ff:ff:ff:ff:ff` for broadcast)
- `ethertype` - (Optional) Ethernet type field in hex, default: 0x88BF
- `vlan_id` - (Optional) VLAN ID (0-4095, 0 = no VLAN tagging, default: 0)
- `count` - (Optional) Number of packets to send, default: 10
- `interval_ms` - (Optional) Delay between sent packets in milliseconds, default: 500
- `recv_timeout_ms` - (Optional) Extra time to keep receiving after expected send completion in milliseconds, default: 2000

### Examples

Basic usage with defaults (no VLAN):
```bash
sudo ./raw_packet_test en0 en1 ff:ff:ff:ff:ff:ff
```

With custom ethertype:
```bash
sudo ./raw_packet_test en0 en1 ff:ff:ff:ff:ff:ff 0x88BF
```

With VLAN ID 100:
```bash
sudo ./raw_packet_test en0 en1 ff:ff:ff:ff:ff:ff 0x88BF 100
```

With VLAN ID 100, 20 packets, 1 second interval:
```bash
sudo ./raw_packet_test en0 en1 ff:ff:ff:ff:ff:ff 0x88BF 100 20 1000
```

Without VLAN (explicit), fast transmission:
```bash
sudo ./raw_packet_test eth0 eth1 aa:bb:cc:dd:ee:ff 0x9999 0 50 100
```

## How It Works

1. The receiver thread starts first and binds to the receive interface
2. After a 500ms startup delay, the sender thread starts sending packets
3. Both threads run concurrently:
   - **Sender**: Constructs ethernet frames with custom EtherType (optionally adding 802.1Q VLAN tags) and sends them at the specified interval
   - **Receiver**: Listens for incoming frames matching the specified EtherType (filtering for VLAN-tagged or non-VLAN packets as configured) and displays packet info
4. The receiver runs for a calculated time period: `500ms + (count × interval_ms) + recv_timeout_ms`
   - This allows it to catch all sent packets plus any duplicates or delayed packets
   - The program exits when the receiver's time expires

When VLAN tagging is enabled (vlan_id > 0), the sender inserts an 802.1Q VLAN header between the source MAC and EtherType fields. The receiver applies appropriate BPF filters to match VLAN-tagged packets and extracts the VLAN ID from received packets.

### Handling Packet Duplicates

The receiver will catch all packets that arrive, including duplicates. Since it processes all packets in each BPF buffer and runs for a calculated time period (rather than stopping after a fixed count), it will report every packet received, making it ideal for testing networks that duplicate packets.

## Packet Format

### Non-VLAN Packet (vlan_id = 0)
- Standard Ethernet header (14 bytes)
  - Destination MAC (6 bytes)
  - Source MAC (6 bytes)
  - EtherType (2 bytes)
- Sequence number (4 bytes)
- Timestamp (8 bytes)
- Payload message (64 bytes)

**Total size: 90 bytes**

### VLAN-Tagged Packet (vlan_id > 0)
- Ethernet header with VLAN tag (18 bytes)
  - Destination MAC (6 bytes)
  - Source MAC (6 bytes)
  - VLAN Tag (4 bytes)
    - TPID: 0x8100 (2 bytes) - Tag Protocol Identifier
    - TCI: VLAN ID (2 bytes) - Tag Control Information (12-bit VID + 3-bit PCP + 1-bit DEI)
  - EtherType (2 bytes)
- Sequence number (4 bytes)
- Timestamp (8 bytes)
- Payload message (64 bytes)

**Total size: 94 bytes**

## Platform Notes

- **macOS**: Uses Berkeley Packet Filter (BPF) devices (`/dev/bpf*`)
  - BPF batches multiple packets into single read operations for efficiency
  - Uses `BIOCSRTIMEOUT` ioctl for read timeouts (standard `SO_RCVTIMEO` doesn't work with BPF)
  - The receiver processes all packets in each BPF buffer to catch duplicates

- **Linux**: Uses AF_PACKET raw sockets
  - Uses standard `SO_RCVTIMEO` socket option for read timeouts
  - Each `recvfrom()` call returns a single packet

Both implementations provide equivalent functionality for testing network interfaces and correctly handle packet duplicates.
