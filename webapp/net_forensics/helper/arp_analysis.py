#!/usr/bin/env python3
import sys, os, time
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scripts'))
import detect_arp_spoofing

def main(capture_file):
    ip_mac_dict = detect_arp_spoofing.main(capture_file)

    category_list = []
    dataset_list = []
    chart_dict_all = []
    for ip in ip_mac_dict:
        min_timestamp = time.time()
        max_timestamp = 0
        timestamp_list = []
        for mac in ip_mac_dict[ip]:
            timestamp_list = list(ip_mac_dict[ip][mac].keys())
            min_timestamp = min(min_timestamp, min(timestamp_list))
            max_timestamp = max(max_timestamp, max(timestamp_list))
        # print(min_timestamp, max_timestamp)
        timestamp_list = list(range(min_timestamp, max_timestamp+1))
        for t in timestamp_list:
            new_dict = {}
            new_dict["label"] = str(t)
            new_dict["stepSkipped"] = "false"
            new_dict["appliedSmartLabel"] = "true"
            category_list.append(new_dict)
        # print(category_list)

        for mac in ip_mac_dict[ip]:
            timestamp_mac_dict = ip_mac_dict[ip][mac]
            data_list = []
            cumulative_val = 0
            for t in timestamp_list:
                new_dict = {}
                try:
                    cumulative_val += timestamp_mac_dict[t]
                    # new_dict["value"] = timestamp_mac_dict[t]
                    new_dict["value"] = cumulative_val
                except:
                    # new_dict["value"] = 0
                    new_dict["value"] = cumulative_val
                data_list.append(new_dict)
            new_dict = {}
            new_dict["seriesname"] = mac
            new_dict["data"] = data_list
            dataset_list.append(new_dict)
        # print(dataset_list)

        chart_dict = {

            "chart": {
            "caption": "IP Mac Mapping Stats",
            "subCaption": ip,
            "numberprefix": "",
            "plotgradientcolor": "",
            "bgcolor": "FFFFFF",
            "showalternatehgridcolor": "0",
            "divlinecolor": "CCCCCC",
            "showvalues": "0",
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

        chart_dict_all.append(chart_dict)

    return chart_dict_all

# print(main('../../../captures/arp.pcap'))
