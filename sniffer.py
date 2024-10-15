from scapy.all import *
import socket
from datetime import datetime
from colorama import Fore, Style, init
import matplotlib.pyplot as plt
from collect
ions import defaultdict
import threading

# Initialize Colorama and plot tracking
init(autoreset=True)

# Dictionaries to track statistics
protocol_count = defaultdict(int)
packet_size_by_protocol = defaultdict(list)
direction_count = defaultdict(int)

# Open a file to log the packet information
log_file = open("packet_log.txt", "a")  # Append mode

# Initialize plotting in a separate thread
def plot_graphs():
    """Function to plot protocol counts, packet sizes, and directions."""
    while True:
        if protocol_count:
            plt.figure(figsize=(12, 8))
            
            # Plot Protocol Counts
            plt.subplot(2, 2, 1)
            plt.bar(protocol_count.keys(), protocol_count.values(), color='cyan')
            plt.title("Packet Counts by Protocol")
            plt.ylabel("Count")
            plt.xlabel("Protocol")

            # Plot Packet Size Distribution by Protocol
            plt.subplot(2, 2, 2)
            for protocol, sizes in packet_size_by_protocol.items():
                plt.hist(sizes, bins=20, alpha=0.5, label=protocol)
            plt.title("Packet Size Distribution by Protocol")
            plt.ylabel("Frequency")
            plt.xlabel("Packet Size (Bytes)")
            plt.legend()

            # Plot Traffic Direction Count
            plt.subplot(2, 2, 3)
            plt.bar(direction_count.keys(), direction_count.values(), color='magenta')
            plt.title("Traffic Direction")
            plt.ylabel("Count")
            plt.xlabel("Direction")

            plt.tight_layout()
            plt.pause(5)  # Refresh every 5 seconds

def log_packet_info(info, packet):
    """Helper function to log packet information in a structured format with colors."""
    log_output = (
        "\n" + "=" * 80 + "\n" +
        f"{Fore.CYAN}{'Time':<15}: {info['time']}\n" +
        f"{Fore.MAGENTA}{'Protocol':<15}: {info['protocol']}-{info['direction']}\n" +
        f"{Fore.GREEN}{'Length':<15}: {info['length']} Bytes\n" +
        f"{Fore.YELLOW}{'SRC-MAC':<15}: {info.get('src_mac', 'N/A')}\n" +
        f"{Fore.YELLOW}{'DST-MAC':<15}: {info.get('dst_mac', 'N/A')}\n" +
        f"{Fore.YELLOW}{'EtherType':<15}: {info.get('ethertype', 'N/A')}\n" +
        f"{Fore.YELLOW}{'SRC-PORT':<15}: {info.get('src_port', 'N/A')}\n" +
        f"{Fore.YELLOW}{'DST-PORT':<15}: {info.get('dst_port', 'N/A')}\n" +
        f"{Fore.YELLOW}{'SRC-IP':<15}: {info.get('src_ip', 'N/A')}\n" +
        f"{Fore.YELLOW}{'DST-IP':<15}: {info.get('dst_ip', 'N/A')}\n"
    )

    # Print protocol-specific details
    if info.get('details'):
        log_output += f"{Fore.BLUE}{'Details':<15}:\n"
        for key, value in info['details'].items():
            log_output += f"    - {Fore.WHITE}{key}: {value}\n"
    
    log_output += "=" * 80 + "\n"
    
    # Print to console
    print(log_output)
    
    # Write to log file
    log_file.write(log_output)
    log_file.flush()  # Ensure it's written immediately

    # Update metrics
    protocol_count[info['protocol']] += 1
    packet_size_by_protocol[info['protocol']].append(info['length'])
    direction_count[info['direction']] += 1

def packet_callback(packet):
    time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    local_ip = socket.gethostbyname(socket.gethostname())
    
    info = {
        'time': time,
        'src_mac': packet[Ether].src if packet.haslayer(Ether) else 'N/A',
        'dst_mac': packet[Ether].dst if packet.haslayer(Ether) else 'N/A',
        'ethertype': hex(packet[Ether].type) if packet.haslayer(Ether) else 'N/A'
    }

    # Handle IP layers
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        info.update({
            'src_ip': ip_layer.src,
            'dst_ip': ip_layer.dst,
            'direction': 'OUT' if ip_layer.src == local_ip else 'IN' if ip_layer.dst == local_ip else 'OTHER',
            'protocol': 'IP',
            'length': len(packet),
            'details': {
                'Version': ip_layer.version,
                'Header Length': ip_layer.ihl,
                'Type of Service': ip_layer.tos,
                'Total Length': ip_layer.len,
                'ID': ip_layer.id,
                'Flags': ip_layer.flags,
                'Fragment Offset': ip_layer.frag,
                'TTL': ip_layer.ttl,
                'Protocol': ip_layer.proto,
                'Checksum': ip_layer.chksum
            }
        })
    
    # Handle IPv6 layers
    elif packet.haslayer(IPv6):
        ip6_layer = packet[IPv6]
        info.update({
            'src_ip': ip6_layer.src,
            'dst_ip': ip6_layer.dst,
            'direction': 'OUT' if ip6_layer.src == local_ip else 'IN' if ip6_layer.dst == local_ip else 'OTHER',
            'protocol': 'IPv6',
            'length': len(packet),
            'details': {
                'Version': ip6_layer.version,
                'Traffic Class': ip6_layer.tc,
                'Flow Label': ip6_layer.fl,
                'Payload Length': ip6_layer.plen,
                'Next Header': ip6_layer.nh,
                'Hop Limit': ip6_layer.hlim
            }
        })
    
    # Handle TCP layers
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        info.update({
            'protocol': 'TCP',
            'src_port': tcp_layer.sport,
            'dst_port': tcp_layer.dport,
            'details': {
                'Sequence Number': tcp_layer.seq,
                'Acknowledgment Number': tcp_layer.ack,
                'Flags': tcp_layer.flags,
                'Window Size': tcp_layer.window,
                'Checksum': tcp_layer.chksum,
                'Urgent Pointer': tcp_layer.urgptr
            }
        })
        
        # Check for HTTP traffic
        if tcp_layer.dport == 80 or tcp_layer.sport == 80:
            info['protocol'] = 'HTTP'
            if packet.haslayer(Raw):
                try:
                    http_payload = packet[Raw].load.decode(errors='ignore')
                    info['details']['HTTP Payload'] = http_payload[:100]  # Show first 100 characters
                except Exception as e:
                    info['details']['HTTP Payload'] = f"Error decoding payload: {e}"

    # Handle UDP layers
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        info.update({
            'protocol': 'UDP',
            'src_port': udp_layer.sport,
            'dst_port': udp_layer.dport,
            'details': {
                'Length': udp_layer.len,
                'Checksum': udp_layer.chksum
            }
        })
        
        # Check for DNS traffic
        if udp_layer.dport == 53 or udp_layer.sport == 53:
            info['protocol'] = 'DNS'
            if packet.haslayer(DNS):
                dns_layer = packet[DNS]
                if dns_layer.qr == 0:  # DNS Query
                    query_name = dns_layer[DNSQR].qname.decode('utf-8') if dns_layer.qdcount > 0 else "N/A"
                    info['details']['DNS Query'] = query_name
                else:  # DNS Response
                    answers = [dns_layer[DNSRR][i].rrname.decode('utf-8') for i in range(dns_layer.ancount)]
                    info['details']['DNS Response'] = ', '.join(answers)

    # Handle ICMP layers
    elif packet.haslayer(ICMP):
        icmp_layer = packet[ICMP]
        info.update({
            'protocol': 'ICMP',
            'details': {
                'Type': icmp_layer.type,
                'Code': icmp_layer.code,
                'Checksum': icmp_layer.chksum,
                'ID': getattr(icmp_layer, 'id', 'N/A'),
                'Sequence': getattr(icmp_layer, 'seq', 'N/A')
            }
        })
    
    # Handle ARP layers
    elif packet.haslayer(ARP):
        arp_layer = packet[ARP]
        info.update({
            'protocol': 'ARP',
            'src_ip': arp_layer.psrc,
            'dst_ip': arp_layer.pdst,
            'details': {
                'HW SRC': arp_layer.hwsrc,
                'HW DST': arp_layer.hwdst,
                'Operation': 'Request' if arp_layer.op == 1 else 'Reply'
            }
        })

    # Log full packet details
    log_packet_info(info, packet)

# Start a thread for plotting graphs
thread = threading.Thread(target=plot_graphs)
thread.daemon = True  # Ensure the thread will exit when the main program exits
thread.start()

# Start sniffing with the callback function
sniff(prn=packet_callback, store=0)

# Close the log file when the program exits
log_file.close()