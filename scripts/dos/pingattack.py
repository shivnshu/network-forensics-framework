#!/usr/bin/env python3
import sys
import os
from scapy.all import *

def main(capture_file):
    packets = rdpcap(capture_file)
    k=0
    for pkt in packets:
        if ICMP in pkt:
            k=k+len(pkt.load)
    #print(k)		
    for pkt in packets:
        if ICMP in pkt:
            if pkt[ICMP].type == 8 and len(pkt.load)>900 and k>65000: 
                print(len(pkt.load),"ping attack"," source IP  ",pkt[IP].src,"   Dest IP  ",pkt[IP].dst)


if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if len(sys.argv) > 1:
        filename = sys.argv[1]
    else:
        filename = os.path.join(script_dir, '../captures/sample.pcap')

    main(filename)
