#!/usr/bin/env python3
import sys, os
import yaml
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scripts'))
import protocols_time_series


def main(capture_file):
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    r = open(_script_dir + "/../scripts/data/protocols.yaml")
    protocols_color_dict = yaml.load(r)

    protocols_time_series_dict = protocols_time_series.main(capture_file)

    category_list = []
    dataset_list = []
    for t in protocols_time_series_dict["x_axis_labels"]:
        new_dict = {}
        new_dict["label"] = t
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
            "subCaption": "sub",
            "numberprefix": "",
            "plotgradientcolor": "",
            "bgcolor": "FFFFFF",
            "showalternatehgridcolor": "0",
            "divlinecolor": "CCCCCC",
            "showvalues": "0",
            "showLabels": "0",
            "showcanvasborder": "0",
            "canvasborderalpha": "0",
            "canvasbordercolor": "CCCCCC",
            "canvasborderthickness": "1",
            "captionpadding": "30",
            "linethickness": "3",
            "yaxisvaluespadding": "15",
            "legendshadow": "0",
            "legendborderalpha": "0",
            "palettecolors": "#f8bd19,#008ee4,#33bdda,#e44a00,#6baa01,#583e78",
            "showborder": "0"
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
