#!/usr/bin/env python3
import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scripts'))
import protocol_hierarchy

protocol_color = {
    "Ethernet": "#f8bd19",
    "802.11": "#33ccff",
    "IP": "#ffcccc",
    "IPv6": "#ccff66",
    "ARP": "#00FF00",
    "TCP": "#008000",
    "UDP": "#FFFF00",
    "ICMP": "#990033",
    "DNS": "#ccccff",
    "NBNS query request": "#996633",
    "Raw": "#9933ff"
}


def main(capture_file):
    protocols_dict = protocol_hierarchy.main(capture_file)
    # print(protocols_dict)
    protocol_category = []

    first_protocols = protocols_dict['proto']
    for first in first_protocols:
        # print(first)
        first_dict = {}
        first_dict['label'] = first
        first_dict['color'] = protocol_color[first]
        first_dict['value'] = first_protocols[first]['count']
        first_dict['tooltext'] = first + ", $$valueK, $percentValue"
        first_dict['category'] = []

        second_protocols = first_protocols[first]['proto']
        for second in second_protocols:
            # print(second)
            second_dict = {}
            second_dict['label'] = second
            second_dict['color'] = protocol_color[second]
            second_dict['value'] = second_protocols[second]['count']
            second_dict['tooltext'] = second + ", $$valueK, $percentValue"
            second_dict['category'] = []

            third_protocols = second_protocols[second]['proto']
            for third in third_protocols:
                # print(third)
                third_dir = {}
                third_dir['label'] = third
                third_dir['color'] = protocol_color[third]
                third_dir['value'] = third_protocols[third]['count']
                third_dir['tooltext'] = third + ", $$valueK, $percentValue"
                third_dir['category'] = []

                fourth_protocols = third_protocols[third]['proto']
                for fourth in fourth_protocols:
                    # print(fourth)
                    fourth_dir = {}
                    fourth_dir['label'] = fourth
                    fourth_dir['color'] = protocol_color[fourth]
                    fourth_dir['value'] = fourth_protocols[fourth]['count']
                    fourth_dir['tooltext'] = fourth + ", $$valueK, $percentValue"

                    third_dir['category'].append(fourth_dir)

                second_dict['category'].append(third_dir)

            first_dict['category'].append(second_dict)

        protocol_category.append(first_dict)

    chart_dict = {
        "chart":
        {
            "showPlotBorder": "1",
            "piefillalpha": "60",
            "pieborderthickness": "2",
            "piebordercolor": "#FFFFFF",
            "hoverfillcolor": "#CCCCCC",
            "numberPrefix": "$",
            "plottooltext": "$label, $$valueK, $percentValue",
            "theme": "fint"
        },
        "category": protocol_category
    }

    return chart_dict

# print(main('../../../captures/sample.pcap'))
