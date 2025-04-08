import pyshark
import math
from datetime import datetime
import pandas as pd
from collections import defaultdict
from scipy.stats import entropy
import nest_asyncio
from tqdm import tqdm

nest_asyncio.apply()

# Shannon entropy
def calculate_entropy(data):
    value_counts = pd.Series(data).value_counts(normalize=True)
    return entropy(value_counts, base=2)

# Process pcap file and extract flow features
def process_pcap(file_path, interval=30):
    capture = pyshark.FileCapture(file_path, keep_packets=False)

    # Get packet count for tqdm progress bar
    print("Counting total packets for progress bar...")
    packet_count = sum(1 for _ in pyshark.FileCapture(file_path, keep_packets=False))
    
    capture = pyshark.FileCapture(file_path, keep_packets=False)
    flows = defaultdict(list)

    # Parse packets with progress bar
    print("Processing packets...")
    for packet in tqdm(capture, total=packet_count):
        try:
            timestamp = float(packet.sniff_timestamp)
            src_ip = packet.ip.src if hasattr(packet, 'ip') else "NA"
            dst_ip = packet.ip.dst if hasattr(packet, 'ip') else "NA"
            src_port = packet[packet.transport_layer].srcport if hasattr(packet, 'transport_layer') else "NA"
            dst_port = packet[packet.transport_layer].dstport if hasattr(packet, 'transport_layer') else "NA"
            src_mac = packet.eth.src if hasattr(packet, 'eth') else "NA"
            dst_mac = packet.eth.dst if hasattr(packet, 'eth') else "NA"
            packet_size = int(packet.length)

            flow_key = (src_ip, dst_ip, src_port, dst_port, src_mac, dst_mac)
            flows[flow_key].append((timestamp, packet_size))
        except AttributeError:
            continue

    capture.close()

    # Aggregate features
    start_time = min(min(ts for ts, _ in packets) for packets in flows.values())
    grouped_flows = defaultdict(list)

    for flow_key, packets in flows.items():
        for timestamp, packet_size in packets:
            group_id = math.floor((timestamp - float(start_time)) / interval)
            grouped_flows[group_id].append((flow_key, timestamp, packet_size))

    results = []
    for group, group_packets in grouped_flows.items():
        group_start_time = float(start_time) + group * interval
        group_end_time = float(start_time) + (group + 1) * interval

        durations = []
        total_packets = 0
        src_ports = []
        dst_ports = []

        for flow_key, timestamp, packet_size in group_packets:
            _, _, src_port, dst_port, _, _ = flow_key
            durations.append(packet_size)
            total_packets += 1
            if src_port != "NA":
                src_ports.append(src_port)
            if dst_port != "NA":
                dst_ports.append(dst_port)

        results.append({
            "Group ID": group,
            "Start Time": datetime.fromtimestamp(group_start_time).strftime('%Y-%m-%d %H:%M:%S'),
            "End Time": datetime.fromtimestamp(group_end_time).strftime('%Y-%m-%d %H:%M:%S'),
            "Maximum Duration": max(durations) if durations else 0,
            "Mean Duration": sum(durations) / len(durations) if durations else 0,
            "Standard Deviation": pd.Series(durations).std() if durations else 0,
            "Total Duration": sum(durations),
            "Total Packets": total_packets,
            "Rate": total_packets / interval if interval > 0 else 0,
            "Unique Source Ports": len(set(src_ports)),
            "Unique Destination Ports": len(set(dst_ports)),
            "Total Source Ports": len(src_ports),
            "Total Destination Ports": len(dst_ports),
            "Source Port Entropy": calculate_entropy(src_ports) if src_ports else 0,
            "Destination Port Entropy": calculate_entropy(dst_ports) if dst_ports else 0,
            "Entropy Difference": (calculate_entropy(src_ports) - calculate_entropy(dst_ports)) if src_ports and dst_ports else 0,
            "Total Flows": len(set(flow_key for flow_key, _, _ in group_packets))
        })

    return results

# File path to the PCAPNG file
file_path = "1.pcapng"

# Process the PCAPNG file
flow_features = process_pcap(file_path)

# Convert results to a pandas DataFrame
df = pd.DataFrame(flow_features)

# Save the data into a CSV file
output_path = "flow_features.csv"
df.to_csv(output_path, index=False)

# Display the dataframe
print("Flow feature calculations completed!")
print(df.head())
