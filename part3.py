from scapy.all import sniff
from collections import defaultdict

# Dictionaries to store flow counts and data transfer amounts
source_flows = defaultdict(int)  # source IP -> number of flows
destination_flows = defaultdict(int)  # destination IP -> number of flows
data_transferred = defaultdict(int)  # (source IP, source port, dest IP, dest port) -> total data transferred
unique_pairs = set()

# Function to process each packet during capture
def handle_packet(packet):
    # Check if the packet has IP layer and transport layer (TCP/UDP)
    if packet.haslayer("IP") and (packet.haslayer("TCP") or packet.haslayer("UDP")):
        # Extract source and destination IP addresses
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
        
        # Extract source and destination ports (TCP/UDP)
        if packet.haslayer("TCP"):
            src_port = packet["TCP"].sport
            dst_port = packet["TCP"].dport
        elif packet.haslayer("UDP"):
            src_port = packet["UDP"].sport
            dst_port = packet["UDP"].dport
        
        # Create the source-destination pair and add to the set
        pair = (src_ip, src_port, dst_ip, dst_port)
        
        # Track the unique source-destination pair
        unique_pairs.add(pair)
        
        # Update flow counts for source and destination
        source_flows[src_ip] += 1
        destination_flows[dst_ip] += 1
        
        # Update the total data transferred for each source-destination pair
        packet_size = len(packet)
        data_transferred[pair] += packet_size

# Function to start live packet capture on a given interface
def capture_packets(interface="enp0s3", capture_time=120):
    print(f"Capturing packets on interface {interface} for {capture_time} seconds...")
    sniff(iface=interface, prn=handle_packet, store=False, timeout=capture_time)

# Function to display the results
def show_results():
    print("\nSource IP Flow Counts:")
    for src_ip, flow_count in source_flows.items():
        print(f"{src_ip}: {flow_count} flows")
    
    print("\nDestination IP Flow Counts:")
    for dst_ip, flow_count in destination_flows.items():
        print(f"{dst_ip}: {flow_count} flows")

    # Find the source-destination pair that transferred the most data
    max_data_pair = max(data_transferred, key=data_transferred.get)
    max_data_value = data_transferred[max_data_pair]
    
    print("\nSource-Destination Pair with Most Data Transferred:")
    print(f"Source: {max_data_pair[0]}:{max_data_pair[1]} -> Destination: {max_data_pair[2]}:{max_data_pair[3]}")
    print(f"Total data transferred: {max_data_value} bytes")

# Run the packet capture and display results after completion
if __name__ == "__main__":
    capture_packets()  # Start capturing packets for the defined duration
    show_results()  # Display results including flow counts and the pair with most data transferred
