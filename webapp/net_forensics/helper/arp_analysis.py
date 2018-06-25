#!/usr/bin/env python3
import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scripts'))
import detect_arp_spoofing

def main(capture_file):
    ip_mac_dict = detect_arp_spoofing.main(capture_file)
    ip_mac_mappings = []
    for ip in ip_mac_dict:
        new_dict = {'ip': ip, 'mac':[], 'timestamp': []}
        for mac_timestamp in ip_mac_dict[ip]:
            new_dict['mac'].append(mac_timestamp[0])
            new_dict['timestamp'].append(mac_timestamp[1])
        ip_mac_mappings.append(new_dict)
    return ip_mac_mappings

print(main('../../../captures/arp.pcap'))
