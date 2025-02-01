from scapy.all import sniff
from collections import defaultdict

# Set to store unique source-destination pairs (source IP:port and destination IP:port)
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
        unique_pairs.add(pair)

# Function to start live packet capture on a given interface
def capture_packets(interface="enp0s3", capture_time=120):
    print(f"Capturing packets on interface {interface} for {capture_time} seconds...")
    sniff(iface=interface, prn=handle_packet, store=False, timeout=capture_time)

# Function to display unique source-destination pairs
def show_unique_pairs():
    print(f"Total unique source-destination pairs: {len(unique_pairs)}")
    for pair in unique_pairs:
        print(f"Source: {pair[0]}:{pair[1]} -> Destination: {pair[2]}:{pair[3]}")

# Run the packet capture and display unique pairs after completion
if __name__ == "__main__":
    capture_packets()  # Start capturing packets for the defined duration
    show_unique_pairs()  # Display unique source-destination pairs
