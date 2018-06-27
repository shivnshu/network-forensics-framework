#!/usr/bin/env python3
import sys
import os
import ipaddress
from scapy.all import *


# Main functionality
def main(capture_file):
    # Read packets
    packets = rdpcap(capture_file)
    ip_mac_dict = {}
    for pkt in packets:
        if not IP in pkt:
            continue
        src_ip = ipaddress.ip_address(pkt[IP].src)
        dst_ip = ipaddress.ip_address(pkt[IP].dst)
        if not (src_ip.is_private and dst_ip.is_global):
            continue
        gateway_mac = pkt[Ether].dst
        return gateway_mac

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
