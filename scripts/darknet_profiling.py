#!/usr/bin/env python3
import sys
import ipaddress
from scapy.all import *

profiling_dict = {
        "Scanning Traffic": 0,
        "Backscattering": 0,
        "Misconfiguration": 0,

        "TCP": 0,
        "UDP": 0,
        "ICMP": 0,
        "Others": 0,

        "ClassA src": 0,
        "ClassB src": 0,
        "ClassC src": 0,
        "ClassA dst": 0,
        "ClassB dst": 0,
        "ClassC dst": 0,

        "TCP targeted ports": [],
        "UDP targeted ports": []
    }

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

backscattering_flags = [
        ['SYN', 'ACK'],
        ['ACK', 'SYN'],
        ['RST'],
        ['RST', 'ACK'],
        ['ACK', 'RST'],
        ['ACK']
    ]

classA = ipaddress.IPv4Network(("10.0.0.0", "255.0.0.0"))
classB = ipaddress.IPv4Network(("172.16.0.0", "255.240.0.0"))
classC = ipaddress.IPv4Network(("192.168.0.0", "255.255.0.0"))


def darknet_pkt(pkt, darknet_ips):
    if not IP in pkt:
        return False
    return (pkt[IP].src in darknet_ips) or (pkt[IP].dst in darknet_ips)

def main(capture_file, darknet_file):
    darknet_ips = open(darknet_file, "r").read().splitlines()
    # print(darknet_ips)
    packets = rdpcap(capture_file)
    for pkt in packets:
        if not darknet_pkt(pkt, darknet_ips):
            continue

        if TCP in pkt:
            profiling_dict["TCP"] += 1
            flags = [tcp_flags[x] for x in pkt.sprintf('%TCP.flags%')]
            if flags == ['SYN']:
                profiling_dict["Scanning Traffic"] += 1
            elif flags in backscattering_flags:
                profiling_dict["Backscattering"] += 1
            else:
                profiling_dict["Misconfiguration"] += 1
            profiling_dict["TCP targeted ports"].append(pkt[TCP].dport)

        elif UDP in pkt:
            profiling_dict["UDP"] += 1
            profiling_dict["Misconfiguration"] += 1
            profiling_dict["UDP targeted ports"].append(pkt[UDP].dport)

        elif ICMP in pkt:
            profiling_dict["ICMP"] += 1
            profiling_dict["Misconfiguration"] += 1

        else:
            profiling_dict["Others"] += 1
            profiling_dict["Misconfiguration"] += 1

        src_ip = ipaddress.IPv4Address(pkt[IP].src)
        dst_ip = ipaddress.IPv4Address(pkt[IP].dst)

        if src_ip in classA:
            profiling_dict["ClassA src"] += 1
        elif src_ip in classB:
            profiling_dict["ClassB src"] += 1
        elif src_ip in classC:
            profiling_dict["ClassC src"] += 1

        if dst_ip in classA:
            profiling_dict["ClassA dst"] += 1
        elif dst_ip in classB:
            profiling_dict["ClassB dst"] += 1
        elif dst_ip in classC:
            profiling_dict["ClassC dst"] += 1


if __name__ == "__main__":
    if len(sys.argv) > 1:
        capture_file = sys.argv[1]
    else:
        capture_file = "sample.pcap"

    darknet_file = "darknet.list"
    main(capture_file, darknet_file)
    print(profiling_dict)
