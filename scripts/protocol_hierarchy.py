#!/usr/bin/env python3
from scapy.all import *
import os
import sys
import yaml

tcp_port_service_map = {}
layers_all = [[], [], [], []]

output = {'count':0, 'proto': {}}


def get_common_elem(l1, l2):
    for l in l1:
        if l in l2:
            return l
    return None

def get_tcp_proto(pkt):
    tcp = pkt[TCP]
    if tcp.sport in tcp_port_service_map:
        return tcp_port_service_map[tcp.sport]
    elif tcp.dport in tcp_port_service_map:
        return tcp_port_service_map[tcp.dport]
    return 'Raw'

def get_all_layers(pkt):
    layers = []
    counter = 0
    while True:
        layer = pkt.getlayer(counter)
        if (layer != None):
            layers.append(layer.name)
        else:
            break
        counter += 1
   # Filter layers
    i = 0
    while i < len(layers) and i < len(layers_all):
        if not layers[i] in layers_all[i]:
            layers.remove(layers[i])
        else:
            i += 1

    if len(layers) > 4:
        layers = layers[:4]

    if len(layers) > 3:
        if layers[2] == 'TCP':
            layers[3] = get_tcp_proto(pkt)
 
    return layers


def check_add_layer_output(layers):
    for i in range(len(layers)):
        layer = layers[i]
        prev_layer = layers[i-1] if i > 0 else layer
        prevv_layer = layers[i-2] if i > 1 else layer
        prevvv_layer = layers[i-3] if i > 2 else layer

        if layer in layers_all[0]:
            try:
                output['proto'][layer]
            except:
                output['proto'][layer] = {'count':0, 'proto': {}}

        elif layer in layers_all[1]:
            try:
                output['proto'][prev_layer]['proto'][layer]
            except:
                output['proto'][prev_layer]['proto'][layer] = \
                        {'count': 0, 'proto': {}}

        elif layer in layers_all[2]:
            try:
                output['proto'][prevv_layer]['proto'][prev_layer]['proto'][layer]
            except:
                output['proto'][prevv_layer]['proto'][prev_layer]['proto'][layer] = \
                        {'count': 0, 'proto': {}}

        elif layer in layers_all[3]:
            try:
                output['proto'][prevvv_layer]['proto'][prevv_layer]['proto'][prev_layer]['proto'][layer]
            except:
                output['proto'][prevvv_layer]['proto'][prevv_layer]['proto'][prev_layer]['proto'][layer] = \
                        {'count': 0, 'proto': {}}



def main(capture_file):
    # Add protocols to layers_all and populate tcp_service_map
    _script_location = os.path.dirname(os.path.abspath(__file__))
    r =  open(_script_location + "/data/protocols.yaml")
    protocols_dict = yaml.load(r)
    for protocol_dict in protocols_dict:
        layers_all[protocol_dict['level']].append(protocol_dict['name'])
        if 'port' in protocol_dict:
            tcp_port_service_map[protocol_dict['port']] = protocol_dict['name']

    packets = rdpcap(capture_file)
    for pkt in packets:
        layers = get_all_layers(pkt)
        # print(layers)
        check_add_layer_output(layers)
        output['count'] += 1
        tmp_proto_dict = output['proto']
        for layer in layers:
            tmp_proto_dict[layer]['count'] += 1
            tmp_proto_dict = tmp_proto_dict[layer]['proto']

    return output


if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if len(sys.argv) > 1:
        capture_file = sys.argv[1]
    else:
        capture_file = os.path.join(script_dir, '../captures/sample.pcap')

    print(main(capture_file))
