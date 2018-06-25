#!/usr/bin/env python3
import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scripts'))
import port_scanning_attack

def main(capture_file):
    port_scanning_dict = port_scanning_attack.main(capture_file)
    return port_scanning_dict

# print(main('../../../captures/sample_port_scan.pcap'))
