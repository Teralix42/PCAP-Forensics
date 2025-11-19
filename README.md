# PCAP Capture Tool

Minimal Python packet capture tool for Windows using scapy + Npcap.  
Captures packets to/from the local machine and prints a readable summary.  
Also writes logs to logs/capture.log.

## Features
- Filters traffic to/from local IP only
- Prints packet summaries in real time
- Works on Windows 11 with Npcap

## Run
1. Install Npcap (WinPcap-compatible mode)
2. pip install scapy
3. python main.py