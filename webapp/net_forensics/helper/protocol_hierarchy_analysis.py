#!/usr/bin/env python3
import sys, os
import yaml
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scripts'))
import protocol_hierarchy

protocol_color = {}

def extract_stat_recursively(stats_dict, output_dict):
    for stat_dict in stats_dict:
        if not stat_dict['label'] in output_dict:
            output_dict[stat_dict['label']] = float(stat_dict['value'])
        else:
            output_dict[stat_dict['label']] += float(stat_dict['value'])
        if 'category' in stat_dict:
            extract_stat_recursively(stat_dict['category'], output_dict)

def chart_dict_to_stats(chart_dict):
    output_dict = {}
    output_list = []
    stats_dict = chart_dict['category']
    extract_stat_recursively(stats_dict, output_dict)
    for proto in output_dict:
        new_dict = {}
        new_dict['label'] = proto
        new_dict['value'] = str(output_dict[proto])
        new_dict['color'] = protocol_color[proto]
        output_list.append(new_dict)

    protocol_stats_data_source = {
        "chart":
        {
            "caption": "Protocols Distribution",
            "numberPrefix": "",
            "numberSuffix": " packets",
            "placeValuesInside": "0",
            "showAxisLines": "1",
            "axisLineAlpha": "25",              
            "alignCaptionWithCanvas": "0",
            "showAlternateVGridColor": "0",
            "theme":"fint"
        },
        "data": output_list
    }

    return protocol_stats_data_source

def main(capture_file):
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    r = open(_script_dir + "/../scripts/data/protocols.yaml")
    protocols_color_dict = yaml.load(r)
    for protocol_color_dict in protocols_color_dict:
        protocol_color[protocol_color_dict['name']] = protocol_color_dict['color']

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
