#!/usr/bin/env python3
import sys, os, time
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scripts'))
import darknet_profiling
from collections import Counter

def main(capture_file):
    profiling_dict = darknet_profiling.main(capture_file)
    chart_data_dict = {}

    # Packets Distribution
    packets_dist = []
    packets_dist.append({"label": "Scanning Traffic", 
                         "value": profiling_dict["Scanning Traffic"]})
    packets_dist.append({"label": "Backscattering",
                         "value": profiling_dict["Backscattering"]})
    packets_dist.append({"label": "Misconfiguration",
                         "value": profiling_dict["Misconfiguration"]})
    chart_data_dict["packets_dist"] = packets_dist

    # Protocols Distribution
    protocols_dist = []
    protocols_dist.append({"label": "TCP", "value": profiling_dict["TCP"]})
    protocols_dist.append({"label": "UDP", "value": profiling_dict["UDP"]})
    protocols_dist.append({"label": "ICMP", "value": profiling_dict["ICMP"]})
    protocols_dist.append({"label": "Others", "value": profiling_dict["Others"]})
    chart_data_dict["protocols_dist"] = protocols_dist

    # Source IP Class
    src_ip_class_dist = []
    src_ip_class_dist.append({"label": "Class A", "value": profiling_dict["ClassA src"]})
    src_ip_class_dist.append({"label": "Class B", "value": profiling_dict["ClassB src"]})
    src_ip_class_dist.append({"label": "Class C", "value": profiling_dict["ClassC src"]})
    chart_data_dict["src_ip_class_dist"] = src_ip_class_dist

    # Destination IP Class
    dst_ip_class_dist = []
    dst_ip_class_dist.append({"label": "Class A", "value": profiling_dict["ClassA dst"]})
    dst_ip_class_dist.append({"label": "Class B", "value": profiling_dict["ClassB dst"]})
    dst_ip_class_dist.append({"label": "Class C", "value": profiling_dict["ClassC dst"]})
    chart_data_dict["dst_ip_class_dist"] = dst_ip_class_dist

    # TCP targeted ports
    tcp_targeted_ports = []
    tmp_dict = dict(Counter(profiling_dict["TCP targeted ports"]))
    for elem in tmp_dict:
        tcp_targeted_ports.append({"label": str(elem), "value": tmp_dict[elem]})
    chart_data_dict["tcp_targeted_ports"] = tcp_targeted_ports

    # UDP targeted ports
    udp_targeted_ports = []
    tmp_dict = dict(Counter(profiling_dict["UDP targeted ports"]))
    for elem in tmp_dict:
        udp_targeted_ports.append({"label": str(elem), "value": tmp_dict[elem]})
    chart_data_dict["udp_targeted_ports"] = udp_targeted_ports

    return chart_data_dict

# print(main('../../../captures/sample.pcap'))
