#!/usr/bin/env python3
import sys, os, time
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scripts'))
import detect_arp_spoofing

def pretty_time(seconds):
    local_time = time.localtime(seconds)
    year = local_time.tm_year
    month = local_time.tm_mon
    day = local_time.tm_mday
    hour = local_time.tm_hour
    minute = local_time.tm_min
    second = local_time.tm_sec
    time_str = str(hour)+":"+str(minute)+":"+str(second)+" "+str(month)\
            +"/"+str(day)+"/"+str(year)
    return time_str

def main(capture_file):
    ip_mac_dict, mac_ip_dict = detect_arp_spoofing.main(capture_file)

    chart_dict_all = {"metadata": [], "chart_data": []}
    for ip in ip_mac_dict:
        category_list = []
        dataset_list = []
        min_timestamp = time.time()
        max_timestamp = 0
        timestamp_list = []
        for mac in ip_mac_dict[ip]:
            timestamp_list = list(ip_mac_dict[ip][mac]["timestamps"].keys())
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

        attacker_mac = None
        num_spoofed_pkts = 0
        for mac in ip_mac_dict[ip]:
            timestamp_mac_dict = ip_mac_dict[ip][mac]["timestamps"]
            data_list = []
            cumulative_val = 0

            try:
                timestamp_mac_dict[timestamp_list[0]]
            except:
                attacker_mac = mac

            first_pkt_time = 0
            last_pkt_time = 0
            for t in timestamp_list:
                new_dict = {}
                try:
                    cumulative_val += timestamp_mac_dict[t]
                    # new_dict["value"] = timestamp_mac_dict[t]
                    new_dict["value"] = cumulative_val
                    if first_pkt_time == 0:
                        first_pkt_time = t
                    last_pkt_time = t
                except:
                    # new_dict["value"] = 0
                    new_dict["value"] = cumulative_val
                data_list.append(new_dict)
            new_dict = {}
            new_dict["seriesname"] = mac
            new_dict["data"] = data_list
            dataset_list.append(new_dict)
            if attacker_mac == mac:
                num_spoofed_pkts = cumulative_val
                first_spoofed_pkt_time = first_pkt_time
                last_spoofed_pkt_time = last_pkt_time
        # print(dataset_list)

        if attacker_mac == None:
            attacker_mac = "Could not determine"

        chart_dict = {

            "chart": {
            "caption": "IP Mac Mapping Stats",
            "subCaption": ip,
            "numberprefix": "",
            "xAxisName": "Time",
            "yAxisName": "Cumulative no. of packets",
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

        try:
            for tmp_ip in mac_ip_dict[attacker_mac]:
                if tmp_ip != ip:
                    attacker_ip = tmp_ip
        except:
            attacker_ip = "Not Found!"

        chart_dict_all["chart_data"].append(chart_dict)
        new_dict = {"target_ip": ip, "attacker_mac": attacker_mac,
                "num_spoofed_pkts": num_spoofed_pkts,
                "first_spoofed_pkt_time": pretty_time(first_spoofed_pkt_time),
                "last_spoofed_pkt_time": pretty_time(last_spoofed_pkt_time),
                "victim_ips": ip_mac_dict[ip][attacker_mac]["victim_ips"],
                "attacker_ip": attacker_ip,
                "div_id": ip.replace('.', '')}
        chart_dict_all["metadata"].append(new_dict)

    return chart_dict_all

# print(main('../../../captures/arp.pcap'))
