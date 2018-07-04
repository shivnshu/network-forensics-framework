#!/usr/bin/env python3
import os
import sys
import ipaddress
from scapy.all import *

# Global dictionary to store profiling data
profiling_dict = {
        "Scanning Traffic": 0,
        "Backscattering": 0,
        "Misconfiguration": 0,

        "TCP": 0,
        "UDP": 0,
        "ICMP": 0,
        "Others": 0,

        "ClassA src": 0,
        "ClassB src": 0,
        "ClassC src": 0,
        "ClassA dst": 0,
        "ClassB dst": 0,
        "ClassC dst": 0,

        "TCP targeted ports": [],
        "UDP targeted ports": []
    }

# TCP flags for readability
tcp_flags = {
    'F': 'FIN',
    'S': 'SYN',
    'R': 'RST',
    'P': 'PSH',
    'A': 'ACK',
    'U': 'URG',
    'E': 'ECE',
    'C': 'CWR',
}

# TCP flags set indicative of backscattering as defined in the research paper
backscattering_flags = [
        ['SYN', 'ACK'],
        ['ACK', 'SYN'],
        ['RST'],
        ['RST', 'ACK'],
        ['ACK', 'RST'],
        ['ACK']
    ]

# Definitions of IP classes as per the standard
classA = ipaddress.IPv4Network(("10.0.0.0", "255.0.0.0"))
classB = ipaddress.IPv4Network(("172.16.0.0", "255.240.0.0"))
classC = ipaddress.IPv4Network(("192.168.0.0", "255.255.0.0"))


# Function to tell if a pkt belongs to darknet class i.e. one of its IP belongs to darknet IPs
def darknet_pkt(pkt, darknet_ips):
    if not IP in pkt:
        return False
    return (pkt[IP].src in darknet_ips) or (pkt[IP].dst in darknet_ips)

# Main function
def main(capture_file):
    global profiling_dict
    # Get script directory absolute path
    script_dir = os.path.dirname(os.path.abspath(__file__)) + "/"
    # Darknet list absolute path
    darknet_file = os.path.join(script_dir, "darknet.list")
    # Create and store the list of darknet IPs from the file
    darknet_ips = open(darknet_file, "r").read().splitlines()
    # print(darknet_ips)
    # Read the pcap file
    packets = rdpcap(capture_file)
    for pkt in packets:
        if not darknet_pkt(pkt, darknet_ips):
            # if not darknet pkt, consider next pkt
            continue

        if TCP in pkt:
            # TCP pkt
            # Increment the TCP value
            profiling_dict["TCP"] += 1
            # Extract pkt TCP flags in readable format
            flags = [tcp_flags[x] for x in pkt.sprintf('%TCP.flags%')]

            if flags == ['SYN']:
                profiling_dict["Scanning Traffic"] += 1
            elif flags in backscattering_flags:
                profiling_dict["Backscattering"] += 1
            else:
                profiling_dict["Misconfiguration"] += 1
            # Add port to TCP port list
            profiling_dict["TCP targeted ports"].append(pkt[TCP].dport)

        elif UDP in pkt:
            # UDP pkt
            profiling_dict["UDP"] += 1
            profiling_dict["Misconfiguration"] += 1
            profiling_dict["UDP targeted ports"].append(pkt[UDP].dport)

        elif ICMP in pkt:
            # ICMP pkt
            profiling_dict["ICMP"] += 1
            profiling_dict["Misconfiguration"] += 1

        else:
            # Other pkt
            profiling_dict["Others"] += 1
            profiling_dict["Misconfiguration"] += 1

        # Extract source and destination IP
        src_ip = ipaddress.IPv4Address(pkt[IP].src)
        dst_ip = ipaddress.IPv4Address(pkt[IP].dst)

        # Get class of source IP
        if src_ip in classA:
            profiling_dict["ClassA src"] += 1
        elif src_ip in classB:
            profiling_dict["ClassB src"] += 1
        elif src_ip in classC:
            profiling_dict["ClassC src"] += 1

        # Get class of destination IP
        if dst_ip in classA:
            profiling_dict["ClassA dst"] += 1
        elif dst_ip in classB:
            profiling_dict["ClassB dst"] += 1
        elif dst_ip in classC:
            profiling_dict["ClassC dst"] += 1

    return profiling_dict


# Script entry point
if __name__ == "__main__":
    # Get script directory absolute path
    script_dir = os.path.dirname(os.path.abspath(__file__)) + "/"
    # Usage: <script> [capture_file]
    if len(sys.argv) > 1:
        capture_file = sys.argv[1]
    else:
        # Default capture file
        capture_file = os.path.join(script_dir, "../captures/sample.pcap")
    # Main functionality
    main(capture_file)
    # print for DEBUG
    print(profiling_dict)
