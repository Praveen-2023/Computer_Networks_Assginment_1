# Computer Networks Assignment #1

## Team Members:
- Member 1: 22110206
- Member 2: 22110296
## Submission File:
**Filename**: 35_22110206_22110296.pdf`

## Tools & Technologies Used:
- **Operating System**: Ubuntu on Virtual Machine (VM) (Running on Windows)
- **Packet Replay Tool**: tcpreplay
- **Packet Sniffer**: Scapy (Python-based network sniffing library)
- **Programming Language**: Python

## Part 1: Metrics and Plots
For Part 1 of the assignment, we used three Python scripts (`part1.py`, `part2.py`, `part3.py`) that perform the following tasks:

1. **Data Transfer Metrics** (Handled by `part1.py`):
   - Total data transferred (in bytes).
   - Total number of packets transferred.
   - Minimum, maximum, and average packet sizes.
   - Distribution of packet sizes (displayed using histograms).

2. **Unique Source-Destination Pairs** (Handled by `part2.py`):
   - Displays unique source-destination pairs based on the captured packet data.

3. **Flow Analysis** (Handled by `part3.py`):
   - Displays dictionaries with source and destination IP addresses and the corresponding flow counts.
   - Identifies the source-destination pair that transferred the most data.

### Execution Process:
1. **Packet Replay**:
   - The `tcpreplay` tool was used to replay the `8.pcap` file as shown below:
   ```bash
   sudo tcpreplay -i enp0s3 /home/student/Desktop/CN/8.pcap
