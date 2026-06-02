#!/usr/bin/env python3
"""
Plot histograms of latency from CSV files with TX/RX data.
Shows min, max, and mean latencies for each source ID.
"""

import argparse
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import re
from pathlib import Path
from collections import defaultdict


def extract_timestamp_from_filename(filename):
    """
    Extract timestamp from filename in format like 20260526.123456

    Args:
        filename: String filename

    Returns:
        Timestamp string if found, None otherwise
    """
    match = re.search(r'(\d{8}\.\d{6})', str(filename))
    return match.group(1) if match else None


def group_files_by_timestamp(directory):
    """
    Group CSV files in directory by timestamp in filename.

    Args:
        directory: Path to directory containing CSV files

    Returns:
        Dictionary mapping timestamp to list of CSV file paths
    """
    path = Path(directory)
    if not path.is_dir():
        raise ValueError(f"Not a directory: {directory}")

    groups = defaultdict(list)

    for csv_file in path.glob("*.csv"):
        timestamp = extract_timestamp_from_filename(csv_file.name)
        if timestamp:
            groups[timestamp].append(csv_file)
        else:
            print(f"Warning: No timestamp found in filename: {csv_file.name}")

    return groups


def load_and_calculate_latency(csv_files):
    """
    Load CSV files and calculate latency for each source.
    Matches TX from source i with sequence k to all RX with sequence k.
    Each RX packet generates a separate latency data point.

    Args:
        csv_files: List of CSV file paths

    Returns:
        Tuple of (latencies dict, statistics dict)
        - latencies: {source_id: list of latencies in nanoseconds}
        - statistics: {source_id: {'tx_count': n, 'rx_count': n, 'matched': n, 'unmatched_tx': n}}
    """
    tx_data = defaultdict(dict)  # {source_id: {seq_num: timestamp}}
    rx_data = defaultdict(lambda: defaultdict(list))  # {source_id: {seq_num: [timestamp1, timestamp2, ...]}}

    # Load all files
    for csv_file in csv_files:
        df = pd.read_csv(csv_file)

        # Calculate full timestamp in seconds
        df['timestamp'] = df['timestamp_sec'] + df['timestamp_nsec'] / 1e9

        # Separate TX and RX entries
        tx_entries = df[df['direction'] == 'TX']
        rx_entries = df[df['direction'] == 'RX']

        # Store TX packets by source_id and sequence_number
        for _, row in tx_entries.iterrows():
            source_id = row['source_id']
            seq_num = row['sequence_number']
            if source_id not in tx_data:
                tx_data[source_id] = {}
            tx_data[source_id][seq_num] = row['timestamp']

        # Store ALL RX packets by source_id and sequence_number
        # The source_id in RX indicates which source's packet was received
        for _, row in rx_entries.iterrows():
            source_id = row['source_id']
            seq_num = row['sequence_number']
            rx_data[source_id][seq_num].append(row['timestamp'])

    # Calculate latency for each source
    latencies = defaultdict(list)
    statistics = {}

    for source_id, tx_packets in tx_data.items():
        tx_count = len(tx_packets)
        matched_count = 0
        unmatched_tx = 0

        for seq_num, tx_timestamp in tx_packets.items():
            # Match TX from source_id with RX that have the same source_id and seq_num
            if seq_num in rx_data[source_id]:
                # Calculate latency for ALL RX packets with this source_id and sequence number
                for rx_timestamp in rx_data[source_id][seq_num]:
                    latency_ns = (rx_timestamp - tx_timestamp) * 1e9
                    latencies[source_id].append(latency_ns)
                matched_count += len(rx_data[source_id][seq_num])
            else:
                unmatched_tx += 1

        # Count total RX packets that could match this source
        rx_seq_nums = set(rx_data[source_id].keys())
        tx_seq_nums = set(tx_packets.keys())
        common_seq_nums = rx_seq_nums & tx_seq_nums
        rx_count = sum(len(rx_data[source_id][seq]) for seq in common_seq_nums)

        statistics[source_id] = {
            'tx_count': tx_count,
            'rx_count': rx_count,
            'matched': matched_count,
            'unmatched_tx': unmatched_tx
        }

    return latencies, statistics


def load_and_calculate_latency_from_directory(directory):
    """
    Load CSV files from directory, group by timestamp, and calculate combined latency.

    Args:
        directory: Path to directory containing CSV files

    Returns:
        Tuple of (latencies dict, statistics dict)
        - latencies: {source_id: list of latencies in nanoseconds from all runs}
        - statistics: {source_id: combined statistics across all runs}
    """
    # Group files by timestamp
    file_groups = group_files_by_timestamp(directory)

    if not file_groups:
        print(f"No CSV files with timestamps found in {directory}")
        return {}, {}

    print(f"Found {len(file_groups)} timestamp groups")

    # Accumulate latencies and statistics across all groups
    combined_latencies = defaultdict(list)
    combined_stats = defaultdict(lambda: {
        'tx_count': 0,
        'rx_count': 0,
        'matched': 0,
        'unmatched_tx': 0
    })

    for timestamp, csv_files in sorted(file_groups.items()):
        print(f"  Processing timestamp {timestamp}: {len(csv_files)} files")

        # Calculate latency for this group
        latencies, statistics = load_and_calculate_latency(csv_files)

        # Combine data for each source
        for source_id, latency_list in latencies.items():
            combined_latencies[source_id].extend(latency_list)

        for source_id, stats in statistics.items():
            combined_stats[source_id]['tx_count'] += stats['tx_count']
            combined_stats[source_id]['rx_count'] += stats['rx_count']
            combined_stats[source_id]['matched'] += stats['matched']
            combined_stats[source_id]['unmatched_tx'] += stats['unmatched_tx']

    return dict(combined_latencies), dict(combined_stats)


def plot_latency_histograms(latencies, statistics, output_file=None, bins=50):
    """
    Plot separate histograms for each source ID.

    Args:
        latencies: Dictionary mapping source_id to list of latencies
        statistics: Dictionary with statistics for each source_id
        output_file: Optional output file to save the plots (source ID added before extension)
        bins: Number of histogram bins (default: 50)
    """
    source_ids = sorted(latencies.keys())

    if len(source_ids) == 0:
        print("No matched packets found!")
        return

    # Generate output filename for each source
    def get_output_filename(source_id):
        if not output_file:
            return None
        path = Path(output_file)
        stem = path.stem
        suffix = path.suffix
        parent = path.parent
        return parent / f"{stem}_source_{source_id}{suffix}"

    figures = []

    for source_id in source_ids:
        latency_data = np.array(latencies[source_id])

        # Calculate statistics
        min_latency = latency_data.min()
        max_latency = latency_data.max()
        mean_latency = latency_data.mean()

        # Create figure
        fig, ax = plt.subplots(1, 1, figsize=(10, 6))
        figures.append(fig)

        # Create histogram
        ax.hist(latency_data, bins=bins, edgecolor='black', alpha=0.7)
        ax.set_xlabel('Latency (ns)')
        ax.set_ylabel('Frequency')
        ax.set_title(f'Source ID {source_id}')
        ax.grid(True, alpha=0.3)

        # Add statistics text box
        stats = statistics[source_id]
        stats_text = (f'TX: {stats["tx_count"]}\n'
                     f'RX: {stats["rx_count"]}\n'
                     f'Min: {min_latency:.0f} ns\n'
                     f'Max: {max_latency:.0f} ns\n'
                     f'Mean: {mean_latency:.2f} ns')
        ax.text(0.98, 0.97, stats_text,
                transform=ax.transAxes,
                verticalalignment='top',
                horizontalalignment='right',
                bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8),
                fontsize=10,
                family='monospace')

        plt.tight_layout()

        # Save if output file specified
        output_filename = get_output_filename(source_id)
        if output_filename:
            plt.savefig(output_filename, dpi=300, bbox_inches='tight')
            print(f"Plot saved to {output_filename}")

        # Print statistics to console
        stats = statistics[source_id]
        print(f"\nStatistics for Source ID {source_id}:")
        print(f"  TX packets:        {stats['tx_count']}")
        print(f"  RX packets:        {stats['rx_count']}")
        print(f"  Matched pairs:     {stats['matched']}")
        print(f"  Unmatched TX:      {stats['unmatched_tx']}")
        print(f"  Min latency:       {min_latency:.0f} ns")
        print(f"  Max latency:       {max_latency:.0f} ns")
        print(f"  Mean latency:      {mean_latency:.2f} ns")

    # Show all figures at once if not saving
    if not output_file:
        plt.show()

    # Close all figures
    for fig in figures:
        plt.close(fig)


def main():
    parser = argparse.ArgumentParser(
        description='Plot histograms of latency from CSV files with TX/RX data',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Plot from single CSV file
  %(prog)s test1

  # Plot from multiple CSV files (combines data)
  %(prog)s test1 test2

  # Save plot to file
  %(prog)s test1 test2 -o latency_histogram.png

  # Process directory with multiple runs (groups by timestamp in filename)
  %(prog)s -d ./test_runs -o latency.png

  # Directory mode groups files by timestamp (e.g., 20260526.123456) and combines all runs
        '''
    )

    parser.add_argument('csv_files', nargs='*', help='CSV file(s) to process')
    parser.add_argument('-d', '--directory', help='Directory containing CSV files (grouped by timestamp in filename)')
    parser.add_argument('-o', '--output', help='Output file to save the plot (e.g., plot.png)')
    parser.add_argument('-b', '--bins', type=int, default=50, help='Number of histogram bins (default: 50)')

    args = parser.parse_args()

    # Validate arguments
    if args.directory and args.csv_files:
        print("Error: Cannot specify both directory and individual CSV files")
        return 1

    if not args.directory and not args.csv_files:
        print("Error: Must specify either directory (-d) or CSV files")
        return 1

    # Load and calculate latency
    if args.directory:
        # Process directory mode
        print(f"Processing directory: {args.directory}")
        latencies, statistics = load_and_calculate_latency_from_directory(args.directory)
    else:
        # Process individual files mode
        # Check if files exist
        for csv_file in args.csv_files:
            if not Path(csv_file).exists():
                print(f"Error: File not found: {csv_file}")
                return 1

        print(f"Loading {len(args.csv_files)} file(s)...")
        latencies, statistics = load_and_calculate_latency(args.csv_files)

    if not latencies:
        print("Error: No matched TX/RX packets found!")
        print("Make sure your CSV files have 'direction', 'source_id', 'sequence_number', and timestamp columns.")
        return 1

    # Plot histograms
    plot_latency_histograms(latencies, statistics, args.output, args.bins)

    return 0


if __name__ == '__main__':
    exit(main())
