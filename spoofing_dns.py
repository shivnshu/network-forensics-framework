#!/usr/bin/env python
import sys

from scapy.all import *

def main(filename):
    packets = rdpcap(filename)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        filename = sys.argv[1]
    else:
        filename = 'sample.pcap'
    main(filename)
