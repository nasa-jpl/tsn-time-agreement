#include <unistd.h>

#include <cxxopts.hpp>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <thread>

#include "network_utils.h"
#include "packet_common.h"
#include "packet_receiver.h"
#include "packet_sender.h"

int main(int argc, char* argv[]) {
    try {
        cxxopts::Options options("packet_latency_measurement",
                                 "Packet latency measurement tool with hardware timestamping support");

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
            std::cerr << "Error: Missing required arguments (send-interface, recv-interface, and source-id)"
                      << std::endl;
            std::cerr << "Run with --help for usage information" << std::endl;
            return 1;
        }

        std::string send_interface = result["send-interface"].as<std::string>();
        std::string recv_interface = result["recv-interface"].as<std::string>();
        std::string dest_mac_str = result["dest-mac"].as<std::string>();
        int vlan_id_int = result["vlan-id"].as<int>();
        uint32_t source_id = result["source-id"].as<uint32_t>();
        int count = result["count"].as<int>();
        int interval_ms = result["interval"].as<int>();

        std::string csv_file;
        if (result.count("output")) {
            csv_file = result["output"].as<std::string>();
        }

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

        std::cout << "=== Packet Latency Measurement ===" << std::endl;
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
        std::cout << "===================================" << std::endl << std::endl;

        // Create sender and receiver
        PacketSender sender(send_interface, dest_mac, vlan_id, source_id);
        PacketReceiver receiver(recv_interface, vlan_id);

        // Start receiver in separate thread
        std::thread recv_thread([&receiver, total_recv_time_ms]() { receiver.receive(total_recv_time_ms); });

        // Give receiver time to set up
        usleep(startup_delay_ms * 1000);

        // Send packets in main thread
        sender.send(count, interval_ms);

        // Wait for receiver to finish
        recv_thread.join();

        // Get results
        const auto& tx_timestamps = sender.getTxTimestamps();
        const auto& rx_timestamps = receiver.getRxTimestamps();

        std::cout << "\n=== Test Complete ===" << std::endl;
        std::cout << "TX timestamps collected: " << tx_timestamps.size() << std::endl;
        std::cout << "RX timestamps collected: " << rx_timestamps.size() << std::endl;

        // Filter RX timestamps to exclude packets from our own source_id
        std::vector<PacketTimestamp> filtered_rx_timestamps;
        for (const auto& rx_ts : rx_timestamps) {
            if (rx_ts.source_id != source_id) {
                filtered_rx_timestamps.push_back(rx_ts);
            }
        }

        std::cout << "\n=== Filtered Results ===" << std::endl;
        std::cout << "RX timestamps from other sources: " << filtered_rx_timestamps.size() << std::endl;
        std::cout << "RX timestamps filtered out (own source): " << (rx_timestamps.size() - filtered_rx_timestamps.size()) << std::endl;

        // Calculate and print deltas
        std::cout << "\n=== Timestamp Deltas (TX -> RX) ===" << std::endl;
        for (const auto& rx_ts : filtered_rx_timestamps) {
            auto tx_it = tx_timestamps.find(rx_ts.sequence_number);
            if (tx_it != tx_timestamps.end() && tx_it->second.source_id == rx_ts.source_id) {
                const PacketTimestamp& tx_ts = tx_it->second;

                // Calculate delta in nanoseconds
                int64_t delta_sec = rx_ts.timestamp.tv_sec - tx_ts.timestamp.tv_sec;
                int64_t delta_nsec = rx_ts.timestamp.tv_nsec - tx_ts.timestamp.tv_nsec;
                int64_t delta_ns = (delta_sec * 1000000000LL) + delta_nsec;

                std::cout << "Packet #" << rx_ts.sequence_number << " (src=" << rx_ts.source_id << "): " << delta_ns
                          << " ns"
                          << " [TX=" << (tx_ts.is_hardware ? "HW" : "SW")
                          << ", RX=" << (rx_ts.is_hardware ? "HW" : "SW") << "]" << std::endl;
            } else {
                std::cout << "Packet #" << rx_ts.sequence_number << " (src=" << rx_ts.source_id
                          << "): No matching TX timestamp found" << std::endl;
            }
        }

        // Write to CSV file if specified
        if (!csv_file.empty()) {
            std::ofstream csv(csv_file);
            if (csv.is_open()) {
                // Write CSV header with direction and interface columns
                csv << "direction,interface,sequence_number,source_id,timestamp_sec,timestamp_nsec,type" << std::endl;

                // Write TX timestamps
                for (const auto& tx_pair : tx_timestamps) {
                    const PacketTimestamp& tx_ts = tx_pair.second;
                    csv << "TX," << send_interface << "," << tx_ts.sequence_number << "," << tx_ts.source_id << ","
                        << tx_ts.timestamp.tv_sec << "," << std::setw(9) << std::setfill('0')
                        << tx_ts.timestamp.tv_nsec << "," << (tx_ts.is_hardware ? "HW" : "SW") << std::endl;
                }

                // Write RX timestamps (filtered to exclude our own source_id)
                for (const auto& rx_ts : filtered_rx_timestamps) {
                    csv << "RX," << recv_interface << "," << rx_ts.sequence_number << "," << rx_ts.source_id << ","
                        << rx_ts.timestamp.tv_sec << "," << std::setw(9) << std::setfill('0')
                        << rx_ts.timestamp.tv_nsec << "," << (rx_ts.is_hardware ? "HW" : "SW") << std::endl;
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
