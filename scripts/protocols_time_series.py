#!/usr/bin/env python3
from scapy.all import *
import os
import sys
import yaml

tcp_port_service_map = {}
layers_all = [[], [], [], []]
x_axis_data_count = 20

output = {'count':0, 'proto': {}}
protocols_time_series = {"x_axis_labels": [], "y_axis_data": {}}

def lying_position(pkt_time, x_axis_labels):
    num_labels = len(x_axis_labels)
    for i in range(num_labels - 1):
        if pkt_time >= x_axis_labels[i] and pkt_time < x_axis_labels[i+1]:
            return i + 1
    return num_labels - 1

def main(capture_file):
    global x_axis_data_count
    global protocols_time_series
    _script_location = os.path.dirname(os.path.abspath(__file__))

    packets = rdpcap(capture_file)
    min_timestamp = packets[0].time
    max_timestamp = packets[-1].time
    diff_timestamp = max_timestamp - min_timestamp
    # print(diff_timestamp)
    time_interval = diff_timestamp / x_axis_data_count
    x_axis_labels = list(range(int(min_timestamp), int(max_timestamp), int(time_interval)))
    # print(x_axis_labels)

    protocols_time_series["x_axis_labels"] = x_axis_labels
    protocols_y_axis_data = protocols_time_series["y_axis_data"]
    protocols_y_axis_data["tcp"] = [0] * len(x_axis_labels)
    protocols_y_axis_data["udp"] = [0] * len(x_axis_labels)
    protocols_y_axis_data["icmp"] = [0] * len(x_axis_labels)

    for pkt in packets:
        pkt_time = pkt.time
        x_axis_labels_index = lying_position(pkt_time, x_axis_labels)
        if TCP in pkt:
            protocols_y_axis_data["tcp"][x_axis_labels_index] += 1
        elif UDP in pkt:
            protocols_y_axis_data["udp"][x_axis_labels_index] += 1
        elif ICMP in pkt:
            protocols_y_axis_data["icmp"][x_axis_labels_index] += 1

    return protocols_time_series

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if len(sys.argv) > 1:
        capture_file = sys.argv[1]
    else:
        capture_file = os.path.join(script_dir, '../captures/sample.pcap')

    print(main(capture_file))
