#!/usr/bin/env python3
import sys
import os
from scapy.all import *


# Main functionality
def main(capture_file):
    # Read packets
    packets = rdpcap(capture_file)
    ip_mac_dict = {}
    for pkt in packets:
        if not ARP in pkt: # checking the ARP Packet
                continue
        if pkt[ARP].op != 2: # Filter only reply packets
                continue
        mac = pkt[ARP].hwsrc # Extracting mac address
        ip = pkt[ARP].psrc  # Extracting ip address
        timestamp = int(pkt.time)
        if ip in ip_mac_dict:
            ip_mac_dict[ip].append((mac, timestamp))
        else:
            ip_mac_dict[ip] = []
            ip_mac_dict[ip].append((mac, timestamp))
    # DEBUG
    # print(mac_ip_dict)
    # Filter dict
    arp_detect_dict = {}
    for ip in ip_mac_dict:
        mac = ip_mac_dict[ip][0][0]
        for m in ip_mac_dict[ip]:
            if mac != m[0]:
                arp_detect_dict[ip] = ip_mac_dict[ip]
                break
    
    ip_mac_dict.clear()
    for ip in arp_detect_dict:
        new_dict = {}
        for tup in arp_detect_dict[ip]:
            mac = tup[0]
            timestamp = tup[1]
            if mac in new_dict:
                mac_time = new_dict[mac]
                if timestamp in mac_time:
                    mac_time[timestamp] += 1
                else:
                    mac_time[timestamp] = 1
            else:
                new_dict[mac] = {}
                new_dict[mac][timestamp] = 1
        ip_mac_dict[ip] = new_dict

    return ip_mac_dict

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
