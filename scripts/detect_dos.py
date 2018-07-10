#!/usr/bin/env python3
import sys
import os
from scapy.all import *
list=[]
dict_all={"ping":[],"land":[],"mail":[]}

def main(capture_file):
    ip_dict_ping={}
    ip_dict_land={}
    ip_dict_mail={}
    packets = rdpcap(capture_file)
    k, r = 0, 0
    for pkt in packets:
        if TCP in pkt:
            r = r + 1
            sip = pkt[IP].src
            dip = pkt[IP].dst

            if pkt[TCP].sport == 25 or pkt[TCP].sport == 425 or pkt[TCP].sport == 587:
                # if len(pkt) > 1000 and r > 10000:
                if len(pkt) > 100 and r > 100:
                    ip_dict_mail["src_ip"] = sip
                    ip_dict_mail["dst_ip"] = dip

            if not ip_dict_mail in dict_all["mail"]:
                dict_all["mail"].append(ip_dict_mail)

            if pkt[TCP].sport == pkt[TCP].dport and pkt[IP].src == pkt[IP].dst:
                ip_dict_land["src_ip"] = sip
                ip_dict_land["dst_ip"] = dip

            if not ip_dict_land in dict_all["land"]:
                dict_all["land"].append(ip_dict_land)

        if ICMP in pkt:
            try:
                k = k + len(pkt.load)
            except:
                continue
            sip = pkt[IP].src
            dip = pkt[IP].dst
            # if pkt[ICMP].type == 8 and len(pkt.load) > 900 and k > 65000: 
            if pkt[ICMP].type == 8 and len(pkt.load) > 50 and k > 3500:
                ip_dict_ping["src_ip"] = sip
                ip_dict_ping["dst_ip"] = dip
            if not ip_dict_ping in dict_all["ping"]:
                dict_all["ping"].append(ip_dict_ping)
    return dict_all

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if len(sys.argv) > 1:
        filename = sys.argv[1]
    else:
        filename = os.path.join(script_dir, '../captures/sample.pcap')

    print(main(filename))
