#!/usr/bin/env python3
import sys
import os
from scapy.all import *

def main(capture_file):
    packets = rdpcap(capture_file)
    k=0
    for pkt in packets:
        if TCP in pkt:
                k=k+1;
    # print(k)		
    for pkt in packets:
        if TCP in pkt:
            if pkt[TCP].sport == 25 or pkt[TCP].sport == 425 or pkt[TCP].sport == 587:
                if len(pkt)>1000 and k>10000:
                    print("mail bomb attack")

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if len(sys.argv) > 1:
        filename = sys.argv[1]
    else:
        filename = os.path.join(script_dir, '../captures/sample.pcap')
    main(filename)

                                    
