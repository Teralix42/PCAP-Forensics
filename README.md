# PCAP Capture Tool

Minimal Python packet capture tool for Windows using pydivert.  
Captures packets to/from the local machine and prints a readable summary.  
Also writes logs to logs/capture.log.

## Features
- Filters traffic to/from local IP only
- Prints packet summaries in real time
- Works on Windows 11

## Run
1. open terminal in admin and navigate to the project root
2. pip install pydivert, colorama
3. python main.py
4. ctrl + c to terminate