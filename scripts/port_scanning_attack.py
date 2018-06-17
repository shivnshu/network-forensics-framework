#!/usr/bin/env python3
import os
import sys
import time
from scapy.all import *

# Threshold pkt rate to classify its category
threshold_pkts_rate = 50

# Human-readable TCP flags mapping
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

# Definition of iplist structure
class ipliststruct:
    def __init__(self, src_ipaddr, dst_ipaddr, start_timestamp, port):
        # Initialise the data while first creating the object
        self.src_ipaddr = src_ipaddr
        self.dst_ipaddr = dst_ipaddr
        self.port_count = 1
        self.packets_count = 1
        self.start_timestamp = start_timestamp
        self.end_timestamp = start_timestamp
        self.ports = [port]

    # Function to update end_timestamp of a flow
    def change_end_time(self, time):
        self.end_timestamp = time

    # Function to add scanned port
    # Also maintain pkt count
    def add_scanned_port(self, port):
        self.packets_count += 1
        if port in self.ports:
            return
        self.ports.append(port)
        self.port_count += 1

    # Function to calculate a metric to decide its category
    def calculate_rate(self):
        if self.start_timestamp == self.end_timestamp:
            return None
        return self.packets_count / (self.end_timestamp - self.start_timestamp)

    # Pretty printing
    def print(self):
        print("Attacker IP:", self.src_ipaddr)
        print("Victim Machine IP:", self.dst_ipaddr)
        print("No. of ports scanned:", self.port_count)
        category = "Normal" if self.calculate_rate() < threshold_pkts_rate else \
                "Suspicious"
        print("Category:", category)
        localtime = time.localtime(self.start_timestamp)
        # Pretty printing of time
        start_localtime = str(localtime.tm_hour) + ":" + str(localtime.tm_min) + \
                ":" + str(localtime.tm_sec) + " " + str(localtime.tm_mon) + "/" \
                + str(localtime.tm_mday) + "/" + str(localtime.tm_year)
        print("Scan Start Time:", start_localtime)

        localtime = time.localtime(self.end_timestamp)
        # Pretty printing of time
        end_localtime = str(localtime.tm_hour) + ":" + str(localtime.tm_min) + \
                ":" + str(localtime.tm_sec) + " " + str(localtime.tm_mon) + "/" \
                + str(localtime.tm_mday) + "/" + str(localtime.tm_year)
        print("Scan End Time:", end_localtime)
        self.ports.sort()
        print("Scanned Ports:", self.ports)
        print()


tcp_port_attacks = {} # Global dict to save object corresponding to (src, dst) tuple


# Main function
def main(capture_file):
    # Read pcap file
    packets = rdpcap(capture_file)
    for pkt in packets:
        if not TCP in pkt:
            continue
        flags = [tcp_flags[x] for x in pkt.sprintf('%TCP.flags%')]
        if not 'SYN' in flags or len(flags) != 1:
            # if not pkt for syn scan, continue
            continue
        # Extract src and dsr ip address
        src_ipaddr = pkt[IP].src
        dst_ipaddr = pkt[IP].dst
        port = pkt[TCP].dport
        timestamp = pkt.time
        # Tuple (src, dst) to be used as key
        dict_key = (src_ipaddr, dst_ipaddr)
        if dict_key in tcp_port_attacks:
            # If already exists, modify existing metadata
            iplistobject = tcp_port_attacks[dict_key]
            iplistobject.change_end_time(timestamp)
            iplistobject.add_scanned_port(port)
        else:
            # Else create new object and add it to global list
            iplistobject = ipliststruct(src_ipaddr, dst_ipaddr, timestamp, port)
            tcp_port_attacks[dict_key] = iplistobject

    # print(tcp_port_attacks)
    # Pretty print each object metadata information
    for dict_key in tcp_port_attacks:
        iplistobject = tcp_port_attacks[dict_key]
        iplistobject.print()


# Script entry point
if __name__ == "__main__":
    # Absolue path of script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # Usage: <script> [capture_file]
    if len(sys.argv) > 1:
        capture_file = sys.argv[1]
    else:
        capture_file = os.path.join(script_dir, '../captures/sample_port_scan.pcap')
    # Invoke main function
    main(capture_file)
