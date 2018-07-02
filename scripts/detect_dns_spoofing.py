#!/usr/bin/env python3
import os
import sys
import ast
from scapy.all import *

# Dict with DNS id as key and set of request/response tuple as data
dns_dict = {}
# Dict that store DNS pkt id corresponding to its timestamp
dns_time_dict = {}
# Temp set to store to be deleted entries from dns_time_dict
to_be_deleted_from_dns_time_diction = set()
# Timing window to be considered for expiry definition
time_window = 5 # in seconds

output_list = []

def duplicate_exists(ans_list):
    ans_response_list = []
    for i in range(len(ans_list)):
        ans_list[i]['answers'].sort()
        ans = ans_list[i]['answers']
        if not ans in ans_response_list:
            ans_response_list.append(ans)
    if len(ans_response_list) > 1:
        return False
    return True

def purge_expired_pkts(pkt): # DNS pkt
    min_allowed_time = pkt.time - time_window

    to_be_deleted_from_dns_diction = set()
    for t in dns_time_dict: # Get the lists of expired pkts
        if (t < min_allowed_time):
            to_be_deleted_from_dns_time_diction.add(t)
            for pkt_id in dns_time_dict[t]:
                to_be_deleted_from_dns_diction.add(pkt_id)

    for pkt_id in to_be_deleted_from_dns_diction: # Purge from dns_dict
        if pkt_id in dns_dict:
            del(dns_dict[pkt_id])

    for t in to_be_deleted_from_dns_time_diction: # Purge from dns_time_dict
        if t in dns_time_dict:
            del(dns_time_dict[t])


# Function to store some metadata and detect any dns spoofing
def store_detect(pkt):
    # Return of pkt is not DNS
    if not DNS in pkt or ICMP in pkt:
        return
    
    # Purge expired pkts metadata
    purge_expired_pkts(pkt)

    # Extract and store layers
    dns = pkt.getlayer('DNS')
    ip  = pkt.getlayer('IP')

    # Request pkt tuple generation and storage
    if (dns.qr == 0): # Query pkt
        t = ('Qry', ip.src, ip.dst, dns.qd.qname)
        dns_dict[dns.id] = set()
        # Add tuple to dns_dict[dns_id] set
        dns_dict[dns.id].add(t)
        
        # Populate dns_time_dict with this pkt id
        pkt_time = int(pkt.time)
        if pkt_time in dns_time_dict:
            dns_time_dict[pkt_time].add(dns.id)
        else:
            dns_time_dict[pkt_time] = set()
            dns_time_dict[pkt_time].add(dns.id)

    # Response pkt tuple generation and storage
    else: # Response pkt
        count = dns.ancount # no. of answers

        if (count == 0):
            ans = []
        elif (count == 1):
            ans = [dns.an.rdata]
        else:
            # ans = ""
            ans = []
            l = dns.an
            for i in range(count):
                if (l.type == 1):
                    # ans = (l.rdata) + "," + ans
                    ans.append(l.rdata)
                l = l.payload
            # ans = ans[:len(ans)-1]

        t = ('Ans', ip.src, ip.dst, dns.qd.qname, str(ans))
        dns_dict[dns.id].add(t)

    # Spoofing Detection Logic
    if (len(dns_dict[dns.id]) > 2):
        ans = ""
        ans_dict = {}
        i = 0
        # Check for no. of response pkt to a request dns pkt
        ans_list = []
        for s in dns_dict[dns.id]:
            if (s[0] == 'Ans'):
                i += 1
                ans += 'Ans' + str(i) + ": " + s[4] + ", "
                new_dict = {}
                new_dict['answers'] = ast.literal_eval(s[4])
                new_dict['src'] = s[1]
                new_dict['features'] = {}
                ans_list.append(new_dict)

        if (i < 2):
            return

        if duplicate_exists(ans_list):
            return

        new_dict = {}
        new_dict['domain'] = dns.qd.qname.decode()
        # new_dict["id"] = dns.id
        new_dict["victim"] = ip.dst
        # new_dict["src"] = ip.src
        new_dict["response"] = ans_list

        if not new_dict in output_list:
            output_list.append(new_dict)

        # If greater than or equal to 2, Alert
        # print('DETECT: ID: %s Domain: %s Dst: %s:%s Src: %s:%s Answers: %s' \
                # % (str(dns.id) , dns.qd.qname.decode(), ip.dst, str(pkt[UDP].dport), \
                # ip.src, str(pkt[UDP].sport), ans))


# Main function
def main(filename):
    # Read pcap file and send each to its pkt to store_detect()
    packets = rdpcap(filename)
    for pkt in packets:
        store_detect(pkt)
    # print(dns_dict)
    return output_list

# Script entry point
if __name__ == "__main__":
    # Get absolute path of script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # Usage: <script> [capture_file]
    if len(sys.argv) > 1:
        filename = sys.argv[1]
    else:
        filename = os.path.join(script_dir, '../captures/sample.pcap')
    main(filename)
    # print(output_list)
