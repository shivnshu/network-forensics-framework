#!/usr/bin/env python3
import os
import sys
from scapy.all import *

# Time Window acting as delta T of paper
time_window = 5 # in seconds
# Following list contains the timestamp of the pkts captured
dhcp_discover_list = []
dhcp_request_list = []
dhcp_decline_list = []
arp_source_ip_0_list = []

# Main Function
def main(capture_file):
    # Load model
    #model = 
    packets = rdpcap(capture_file)
    for pkt in packets:
        if not (DHCP in pkt or ARP in pkt):
            continue
        if ARP in pkt:
            # Only request pkts
            if pkt[ARP].op == 1 and pkt[ARP].psrc == '0.0.0.0':
                arp_source_ip_0_list.append(pkt.timestamp)
            continue
        # DHCP pkt
        for elem in pkt[DHCP].options:
            if elem[0] == 'message-type':
                message_type = elem[1]
                break
        
        if message_type == 1:
            dhcp_discover_list.append(pkt.timestamp)
        elif message_type == 3:
            dhcp_request_list.append(pkt.timestamp)
        elif message_type == 4:
            dhcp_decline_list.append(pkt.timestamp)


# Script Entry Point
if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if len(sys.argv) > 1:
        capture_file = sys.argv[1]
    else:
        capture_file = "../captures/sample.pcap"

    main(capture_file)
