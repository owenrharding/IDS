# Python Intrusion Detection System
This Python-based Intrusion Detection System (IDS) is designed to monitor network traffic and detect suspicious activity by comparing network packets to a set of predefined intrusion detection rules.
It uses the Scapy library to analyse PCAP files to log alerts when packets whose properties align to the given rule(s) are detected.

The IDS has functionality to monitor packet's properties including the following fields (which can be specified by the configurable rules):
- Transmission protocol (IP, ICMP, TCP, UDP)
- Source IP Address
- Source Port
- Destination IP Address
- Destination Port
- Content contained within packet
- Alert message
- TCP Packet Header Flags (SYN, ACK, FIN, RST etc)
- Flooding Detection Filtering (specified number of packets sent within a specified window of time)

An example intrustion detection rule might be:

```
alert tcp 192.168.102.132 any -> 131.171.127.1 25 (content: "malicious"; msg: "multiple malicious TCP syn packets found"; flags: S; detection_filter: count 10, seconds 2;)
```

The IDS would be able to raise an alert if it found more than 10 TCP syn packets
within 2 seconds sent from any port number from IP address 192.168.102.132 to port 25 on IP
address 131.171.127.1 that has a content that contains string “malicious”.
