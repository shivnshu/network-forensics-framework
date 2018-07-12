#!/usr/bin/env python3
import sys, os
import time
import yaml
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scripts'))
import protocols_time_series

def pretty_time(t):
    local_time = time.localtime(t)
    hour = str(local_time.tm_hour)
    if len(hour) == 1:
        hour = "0" + hour
    minutes = str(local_time.tm_min)
    if len(minutes) == 1:
        minutes = "0" + minutes
    seconds = str(local_time.tm_sec)
    if len(seconds) == 1:
        seconds = "0" + seconds
    str_time = hour + ":" + minutes + \
            ":" + seconds
    return str_time

def main(capture_file):
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    r = open(_script_dir + "/../scripts/data/protocols.yaml")
    protocols_color_dict = yaml.load(r)

    protocols_time_series_dict = protocols_time_series.main(capture_file)

    category_list = []
    dataset_list = []
    for t in protocols_time_series_dict["x_axis_labels"]:
        new_dict = {}
        new_dict["label"] = pretty_time(t)
        new_dict['stepSkipped'] = 'false'
        new_dict['appliedSmartLabel'] = 'true'
        category_list.append(new_dict)

    for proto in protocols_time_series_dict["y_axis_data"]:
        new_dict = {}
        new_dict['seriesname'] = proto
        new_dict['data'] = []
        for v in protocols_time_series_dict["y_axis_data"][proto]:
            new_dict['data'].append({'value': v})
        dataset_list.append(new_dict)

    chart_dict = {

            "chart": {
            "caption": "Protocols Time Series",
            "subCaption": "",
            "xAxisName": "Time",
            "yAxisName": "No. of packets",
            "labelDisplay": "rotate",
            "slantLabel": "1",
            "numberprefix": "",
            "theme": "fint",
            "showvalues": "0"
            },

            "categories": [
                {
                    "category": category_list    
                } 
            ],

            "dataset": dataset_list
    }

    return chart_dict

# print(main('../../../captures/sample.pcap'))
