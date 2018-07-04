#!/usr/bin/env python3
import sys
import os
from scapy.all import *

def main(capture_file):
    packets = rdpcap(capture_file)
    k=0
    for pkt in packets:
        if TCP in pkt:
            if pkt[TCP].sport == pkt[TCP].dport and pkt[IP].src==pkt[IP].dst:
                print(pkt.show(),"Alert : Land Attack")  

if __name__ == "__main__":
    # Get absolute path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # Usage: <script> [capture file]
    if len(sys.argv) > 1:
        filename = sys.argv[1]
    else:
        filename = os.path.join(script_dir, '../captures/sample.pcap')

    main(filename)
