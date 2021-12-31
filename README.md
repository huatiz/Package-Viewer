# Packet Viewer
## Homework description
Please write a packet viewer program with the following functions:
It can read existed `pcap` file, and display for each packet in the file(one line for a packet):
1. Timestamp of the packet capture.
2. Source MAC address, destination MAC address, and Ethernet type field.
3. If the packet is an IP packet, then display the source IP address and destination IP address more.
4. If the packet is an TCP or UDP packet, then display the source port number and destination port number more.
<br>

## How to execute
```
make
./readPacket [filename]
```
