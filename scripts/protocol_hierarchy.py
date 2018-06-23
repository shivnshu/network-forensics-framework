#!/usr/bin/env python3
from scapy.all import *
import os
import sys
import json

layer_second_candidate = ['Ethernet', '802.11']
layer_third_candidate = ['IP', 'IPv6', 'ARP']
layer_fourth_candidate = ['TCP', 'UDP', 'ICMP']
layer_top = ['DNS', 'NBNS query request', 'Raw']
layers_all = [layer_second_candidate, layer_third_candidate, layer_fourth_candidate, layer_top]

output = {'top': {'count':0, 'proto': {}}}


def get_common_elem(l1, l2):
    for l in l1:
        if l in l2:
            return l
    return None


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
    return layers


def check_add_layer_output(layers):
    for i in range(len(layers)):
        layer = layers[i]
        prev_layer = layers[i-1] if i > 0 else layer
        prevv_layer = layers[i-2] if i > 1 else layer
        prevvv_layer = layers[i-3] if i > 2 else layer

        if layer in layer_second_candidate:
            try:
                output['top']['proto'][layer]
            except:
                output['top']['proto'][layer] = {'count':0, 'proto': {}}

        elif layer in layer_third_candidate:
            try:
                output['top']['proto'][prev_layer]['proto'][layer]
            except:
                output['top']['proto'][prev_layer]['proto'][layer] = \
                        {'count': 0, 'proto': {}}

        elif layer in layer_fourth_candidate:
            try:
                output['top']['proto'][prevv_layer]['proto'][prev_layer]['proto'][layer]
            except:
                output['top']['proto'][prevv_layer]['proto'][prev_layer]['proto'][layer] = \
                        {'count': 0, 'proto': {}}

        elif layer in layer_top:
            try:
                output['top']['proto'][prevvv_layer]['proto'][prevv_layer]['proto'][prev_layer]['proto'][layer]
            except:
                output['top']['proto'][prevvv_layer]['proto'][prevv_layer]['proto'][prev_layer]['proto'][layer] = \
                        {'count': 0, 'proto': {}}



def main(capture_file):
    packets = rdpcap(capture_file)
    for pkt in packets:
        layers = get_all_layers(pkt)
        # print(layers)
        check_add_layer_output(layers)
        output['top']['count'] += 1
        tmp_proto_dict = output['top']['proto']
        for layer in layers:
            tmp_proto_dict[layer]['count'] += 1
            tmp_proto_dict = tmp_proto_dict[layer]['proto']

    json_output = json.dumps(output)
    print(json_output)


if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if len(sys.argv) > 1:
        capture_file = sys.argv[1]
    else:
        capture_file = os.path.join(script_dir, '../captures/sample.pcap')

    main(capture_file)
