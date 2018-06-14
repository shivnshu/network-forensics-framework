#!/usr/bin/env python3
import sys
import time
from scapy.all import *

tcp_flags = {
    'F': 'FIN',
    'S': 'SYN',
    'R': 'RST',
    'P': 'PSH',
    'A': 'ACK',
    'U': 'URG',
    'E': 'ECE',
    'C': 'CWR',
}

class ipliststruct:
    def __init__(self, src_ipaddr, dst_ipaddr, start_timestamp, port):
        self.src_ipaddr = src_ipaddr
        self.dst_ipaddr = dst_ipaddr
        self.port_count = 1
        self.start_timestamp = start_timestamp
        self.end_timestamp = start_timestamp
        self.ports = [port]

    def change_end_time(self, time):
        self.end_timestamp = time

    def add_scanned_port(self, port):
        if port in self.ports:
            return
        self.ports.append(port)
        self.port_count += 1


tcp_port_attacks = {} # Global dict to save object corresponding to (src, dst) tuple


def main(capture_file):
    packets = rdpcap(capture_file)
    for pkt in packets:
        if not TCP in pkt:
            continue
        flags = [tcp_flags[x] for x in pkt.sprintf('%TCP.flags%')]
        if not 'SYN' in flags or len(flags) != 1:
            continue
        src_ipaddr = pkt[IP].src
        dst_ipaddr = pkt[IP].dst
        port = pkt[TCP].dport
        timestamp = pkt.time
        dict_key = (src_ipaddr, dst_ipaddr)
        if dict_key in tcp_port_attacks:
            iplistobject = tcp_port_attacks[dict_key]
            iplistobject.change_end_time(timestamp)
            iplistobject.add_scanned_port(port)
        else:
            iplistobject = ipliststruct(src_ipaddr, dst_ipaddr, timestamp, port)
            tcp_port_attacks[dict_key] = iplistobject

    # print(tcp_port_attacks)
    for dict_key in tcp_port_attacks:
        iplistobject = tcp_port_attacks[dict_key]
        print(iplistobject.src_ipaddr)
        print(iplistobject.dst_ipaddr)
        print(iplistobject.port_count)
        print(iplistobject.start_timestamp)
        print(iplistobject.end_timestamp)
        iplistobject.ports.sort()
        print(iplistobject.ports)
        print("********************")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        capture_file = sys.argv[1]
    else:
        capture_file = 'sample_port_scan.pcap'
    main(capture_file)
