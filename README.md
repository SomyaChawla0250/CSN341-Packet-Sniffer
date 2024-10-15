# Packet Sniffer

## Overview

This project is a **simple packet sniffer** that captures and analyzes network traffic on a local network. It leverages the **Scapy** library in Python to monitor and dissect various network protocols such as **HTTP, DNS, TCP, and UDP**. The packet sniffer provides insight into ongoing network activity by examining key characteristics of the traffic and allowing users to filter for specific types of protocols.

## Features

- **Real-time Packet Capture**: 
  - Captures live network packets from the local network interface.
  
- **Protocol Analysis**: 
  - Automatically identifies and categorizes packets based on their protocol:
    - **TCP** (Transmission Control Protocol)
    - **UDP** (User Datagram Protocol)
    - **HTTP** (Hypertext Transfer Protocol)
    - **DNS** (Domain Name System)
  
- **Packet Inspection**: 
  - Extracts and displays key packet information including:
    - **Source IP** and **Destination IP**
    - **Source Port** and **Destination Port**
    - **Payload** data for deeper analysis
  
- **Customizable Filters**: 
  - Specify the type of traffic to focus on (e.g., only capture HTTP or DNS packets).
  
- **Simple Logging**: 
  - Saves captured packet details to a log file for further review or analysis.

## Requirements

- **Python 3.x**: Make sure Python is installed on your system. You can download the latest version from [here](https://www.python.org/downloads/).


- **Scapy Library**: Scapy is used to capture and dissect packets. Install it using pip:
  ```bash
  pip install scapy

  pip install -r requirements.txt

  sudo python3 sniffer.py
  ```

## Usage

By default, the packet sniffer will capture all packets on your local network interface.  
You can customize the packet sniffer for specific use cases by modifying the script.

### Example: Capture all HTTP packets

```bash
sudo python sniffer.py --filter http
```
    
