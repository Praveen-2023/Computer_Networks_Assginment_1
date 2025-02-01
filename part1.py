import matplotlib.pyplot as plt
from scapy.all import sniff
import numpy as np

# Initialize variables for tracking packet data
total_data = 0
packet_lengths = []
packet_count = 0
capture_time = 120  # Duration of capture in seconds

# Function to process each packet during capture
def handle_packet(packet):
    global total_data, packet_lengths, packet_count

    # Get the size of the packet and update tracking variables
    packet_size = len(packet)
    total_data += packet_size
    packet_lengths.append(packet_size)
    packet_count += 1

# Function to start live packet capture on a given interface
def capture_packets(interface="enp0s3"):
    print(f"Capturing packets on interface {interface} for {capture_time} seconds...")
    sniff(iface=interface, prn=handle_packet, store=False, timeout=capture_time)

# Function to generate and display packet size statistics and histogram
def show_results():
    avg_packet_size = total_data / packet_count if packet_count > 0 else 0
    print(f"Total data captured: {total_data} bytes")
    print(f"Total packets captured: {packet_count}")
    print(f"Smallest packet: {min(packet_lengths)} bytes")
    print(f"Largest packet: {max(packet_lengths)} bytes")
    print(f"Average packet size: {avg_packet_size:.2f} bytes")

    # Enhanced visualization of packet size distribution
    plt.figure(figsize=(10, 6))
    plt.hist(packet_lengths, bins=30, color='skyblue', edgecolor='black', alpha=0.7)
    plt.xlabel('Packet Size (Bytes)', fontsize=12)
    plt.ylabel('Frequency', fontsize=12)
    plt.title('Packet Size Distribution', fontsize=14)
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.show()

# Run the packet capture and display results after completion
if __name__ == "__main__":
    capture_packets()  
    show_results()  
