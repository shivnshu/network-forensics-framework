#!/usr/bin/env python3
from scapy.all import *
import ipaddress
import os
import sys
import ast


# Function to assist to extract both sided communication flow
def full_duplex(p):
    sess = "Other"
    if 'Ether' in p:
        if 'IP' in p:
            if 'TCP' in p:
                sess = str(sorted(["TCP", p[IP].src, p[TCP].sport, \
                        p[IP].dst, p[TCP].dport],key=str))
            elif 'UDP' in p:
                sess = str(sorted(["UDP", p[IP].src, p[UDP].sport, \
                        p[IP].dst, p[UDP].dport] ,key=str))
            elif 'ICMP' in p:
                sess = str(sorted(["ICMP", p[IP].src, p[IP].dst, \
                        p[ICMP].code, p[ICMP].type, p[ICMP].id] ,key=str)) 
            else:
                sess = str(sorted(["IP", p[IP].src, p[IP].dst, \
                        p[IP].proto] ,key=str)) 
        elif 'ARP' in p:
            sess = str(sorted(["ARP", p[ARP].psrc, p[ARP].pdst],key=str)) 
        else:
            sess = p.sprintf("Ethernet type=%04xr,Ether.type%")
    return sess


# Main function
def main(pcap_file):
    # Read pcap file
    packets = rdpcap(pcap_file)
    # Extract all sessions passing out full_duplex function
    sessions = packets.sessions(full_duplex)
    smtp_dissections = []

    for session in sessions:
        session_list = ast.literal_eval(session) # convert str(list) to list
        # Consider only SMTP communication
        if not ('TCP' in session_list and (25 in session_list or \
                                            465 in session_list or \
                                            587 in session_list)):
            continue

        # list to store IP of both communicating parties
        ips = []
        for elem in session_list:
            if not type(elem) is str:
                continue
            try:
                ipaddress.ip_address(elem)
            except:
                continue
            ips.append(elem)

        # print(session)
        # print(ips)
        
        assert(len(ips) == 2)
        new_smtp_dissection_dict = {}
        title = "Found Email conversation between " + ips[0] + " and " + ips[1]
        # print(title)
        new_smtp_dissection_dict['title'] = title
        new_smtp_dissection_dict['content'] = []
        # print()
        for pkt in sessions[session]:
            try:
                # Print decoded string of TCP payload of each pkt
                content = pkt[TCP][Raw].load.decode()
                # print(content)
                new_smtp_dissection_dict['content'].append(content)
            except:
                pass
        smtp_dissections.append(new_smtp_dissection_dict)

    return smtp_dissections


# Script entry point
if __name__ == "__main__":
    # Get script absolute path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # Usage: <script> [pcap_file]
    if (len(sys.argv) > 1):
        pcap_file = sys.argv[1]
    else:
        pcap_file = os.path.join(script_dir, '../captures/smtp.pcap')

    # Main invocation
    main(pcap_file)
