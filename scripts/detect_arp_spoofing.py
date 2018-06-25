#!/usr/bin/env python3
import sys
import os
from scapy.all import *

ip_mac_dict = {}

# Main functionality
def main(capture_file):
    # Read packets
    packets = rdpcap(capture_file)
    for pkt in packets:
        if not ARP in pkt: # checking the ARP Packet
                continue
        if pkt[ARP].op != 2: # Filter only reply packets
                continue
        mac = pkt[ARP].hwsrc # Extracting mac address
        ip = pkt[ARP].psrc  # Extracting ip address
        timestamp = pkt.time
        if ip in ip_mac_dict:
            ip_mac_dict[ip].append((mac, timestamp))
        else:
            ip_mac_dict[ip] = [(mac, timestamp)]
    # DEBUG
    # print(mac_ip_dict)
    return ip_mac_dict
    # for mac in mac_ip_dict:
        # if len(mac_ip_dict[mac]) > 1: #checking arp spoofing
            # print("Possible ARP spoofing for MAC", mac)

# Script Entry Point
if __name__ == "__main__":
    # Get script directory absolute path
    script_dir = os.path.dirname(os.path.abspath(__file__)) + "/"
    # Usage: <script> [capture_file]
    if len(sys.argv) > 1:
        capture_file = sys.argv[1]
    else:
        # Default capture file
        capture_file = os.path.join(script_dir, "../captures/sample.pcap")
    print(main(capture_file))
