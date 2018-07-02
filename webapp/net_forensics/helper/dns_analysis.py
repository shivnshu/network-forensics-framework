#!/usr/bin/env python3
import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scripts'))
import detect_dns_spoofing

def main(capture_file):
    dns_detect_dict = detect_dns_spoofing.main(capture_file)
    return dns_detect_dict

# print(main('../../../captures/sample.pcap'))
