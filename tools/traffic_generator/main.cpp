#include <unistd.h>

#include <climits>
#include <cxxopts.hpp>
#include <fstream>
#include <iomanip>
#include <iostream>

#include "packet_common.h"
#include "packet_sender.h"

int main(int argc, char* argv[]) {
    try {
        cxxopts::Options options("traffic_generator", "Network traffic generator for TSN testing");

        options.add_options()("i,interface", "Interface to send packets from", cxxopts::value<std::string>())(
            "d,dest-mac", "Destination MAC address", cxxopts::value<std::string>()->default_value("ff:ff:ff:ff:ff:ff"))(
            "v,vlan-id", "VLAN ID (1-4095)", cxxopts::value<int>()->default_value("10"))(
            "source-id", "Source ID to include in packet payload (required)", cxxopts::value<uint32_t>())(
            "c,count", "Number of packets to send (0 = infinite)", cxxopts::value<int>()->default_value("0"))(
            "r,rate", "Packet rate in packets per second", cxxopts::value<int>()->default_value("50"))(
            "p,priority", "Socket priority (SO_PRIORITY) 0-7", cxxopts::value<int>()->default_value("0"))(
            "txtime", "Enable SO_TXTIME for scheduled packet transmission")(
            "txtime-clock", "Clock ID for SO_TXTIME (1=MONOTONIC, 11=TAI)", cxxopts::value<int>()->default_value("1"))(
            "timestamps", "Enable TX timestamp collection")(
            "o,output", "CSV file to write TX timestamp data", cxxopts::value<std::string>())(
            "h,help", "Print usage");

        options.parse_positional({"interface"});
        options.positional_help("<interface>");

        auto result = options.parse(argc, argv);

        if (result.count("help")) {
            std::cout << options.help() << std::endl;
            std::cout << "\nNote: EtherType is fixed at 0x88BF" << std::endl;
            std::cout << "Note: All packets are VLAN-tagged" << std::endl;
            std::cout << "Note: This program requires root privileges (run with sudo)" << std::endl;
            std::cout << "\nExamples:" << std::endl;
            std::cout << "  " << argv[0] << " eth0 --source-id 1" << std::endl;
            std::cout << "  " << argv[0] << " -i eth0 --source-id 1 -v 100 -c 1000 -r 100 -p 3" << std::endl;
            std::cout << "  " << argv[0] << " eth0 --source-id 1 -r 1000  # Send 1000 pps indefinitely" << std::endl;
            std::cout << "  " << argv[0] << " eth0 --source-id 1 -c 100 --timestamps -o tx.csv  # Collect TX timestamps" << std::endl;
            return 0;
        }

        // Check required arguments
        if (!result.count("interface") || !result.count("source-id")) {
            std::cerr << "Error: Missing required arguments (interface and source-id)" << std::endl;
            std::cerr << "Run with --help for usage information" << std::endl;
            return 1;
        }

        std::string interface = result["interface"].as<std::string>();
        std::string dest_mac_str = result["dest-mac"].as<std::string>();
        int vlan_id_int = result["vlan-id"].as<int>();
        uint32_t source_id = result["source-id"].as<uint32_t>();
        int count = result["count"].as<int>();
        int rate_pps = result["rate"].as<int>();
        int priority = result["priority"].as<int>();
        bool enable_txtime = result.count("txtime") > 0;
        int txtime_clockid = result["txtime-clock"].as<int>();
        bool enable_timestamps = result.count("timestamps") > 0;

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

        // Validate priority
        if (priority < 0 || priority > 7) {
            std::cerr << "Invalid priority. Must be between 0 and 7." << std::endl;
            return 1;
        }

        // Validate rate
        if (rate_pps <= 0) {
            std::cerr << "Invalid rate. Must be greater than 0." << std::endl;
            return 1;
        }

        // Validate timestamps with infinite count
        if (enable_timestamps && count == 0) {
            std::cerr << "Error: Cannot use --timestamps with infinite count (count=0)" << std::endl;
            std::cerr << "Timestamps are collected after sending completes." << std::endl;
            return 1;
        }

        // Calculate interval in milliseconds
        int interval_ms = 1000 / rate_pps;
        if (interval_ms < 1) {
            interval_ms = 1;  // Minimum 1ms interval
            rate_pps = 1000;  // Effective max rate is 1000 pps
            std::cout << "Warning: Rate limited to 1000 pps (1ms minimum interval)" << std::endl;
        }

        // Parse destination MAC address
        unsigned char dest_mac[6];
        if (sscanf(dest_mac_str.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dest_mac[0], &dest_mac[1], &dest_mac[2],
                   &dest_mac[3], &dest_mac[4], &dest_mac[5]) != 6) {
            std::cerr << "Invalid MAC address format. Use: xx:xx:xx:xx:xx:xx" << std::endl;
            return 1;
        }

        std::cout << "=== Traffic Generator ===" << std::endl;
        std::cout << "Interface: " << interface << std::endl;
        std::cout << "Dest MAC: " << std::hex;
        for (int i = 0; i < 6; i++) {
            std::cout << (int)dest_mac[i];
            if (i < 5) {
                std::cout << ":";
            }
        }
        std::cout << std::dec << std::endl;
        std::cout << "VLAN ID: " << vlan_id << std::endl;
        std::cout << "Source ID: " << source_id << std::endl;
        std::cout << "Priority: " << priority << std::endl;
        std::cout << "SO_TXTIME: " << (enable_txtime ? "enabled" : "disabled");
        if (enable_txtime) {
            std::cout << " (clockid=" << txtime_clockid << ")";
        }
        std::cout << std::endl;
        std::cout << "Timestamps: " << (enable_timestamps ? "enabled" : "disabled") << std::endl;
        std::cout << "Packet count: " << (count == 0 ? "infinite" : std::to_string(count)) << std::endl;
        std::cout << "Rate: " << rate_pps << " pps (" << interval_ms << "ms interval)" << std::endl;
        std::cout << "=========================" << std::endl << std::endl;

        // Create sender
        PacketSender sender(interface, dest_mac, vlan_id, source_id, enable_timestamps, priority, enable_txtime,
                            txtime_clockid);

        if (count == 0) {
            std::cout << "Sending packets indefinitely (Ctrl+C to stop)..." << std::endl;
            // Send indefinitely - use a large number
            sender.send(INT_MAX, interval_ms);
        } else {
            sender.send(count, interval_ms);
        }

        std::cout << "\nTraffic generation complete" << std::endl;

        // Collect and output timestamps if enabled
        if (enable_timestamps) {
            const auto& tx_timestamps = sender.getTxTimestamps();
            std::cout << "TX timestamps collected: " << tx_timestamps.size() << std::endl;

            // Write to CSV file if specified
            if (!csv_file.empty()) {
                std::ofstream csv(csv_file);
                if (csv.is_open()) {
                    // Write CSV header
                    csv << "direction,interface,sequence_number,source_id,timestamp_sec,timestamp_nsec,type"
                        << std::endl;

                    // Write TX timestamps
                    for (const auto& tx_pair : tx_timestamps) {
                        const auto& tx_ts = tx_pair.second;
                        csv << "TX," << interface << "," << tx_ts.sequence_number << "," << tx_ts.source_id << ","
                            << tx_ts.timestamp.tv_sec << "," << std::setw(9) << std::setfill('0')
                            << tx_ts.timestamp.tv_nsec << "," << (tx_ts.is_hardware ? "HW" : "SW") << std::endl;
                    }

                    csv.close();
                    std::cout << "TX timestamp data written to: " << csv_file << std::endl;
                } else {
                    std::cerr << "Error: Failed to open CSV file for writing: " << csv_file << std::endl;
                }
            } else {
                std::cout << "Note: Use -o <file> to save timestamps to CSV" << std::endl;
            }
        }

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
