#!/usr/bin/env python
import sys
from scapy.all import *

dns_dict = {}
dns_time_dict = {}
to_be_deleted_from_dns_time_diction = set()
time_window = 5 # in seconds


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


def store_detect(pkt):
    if not DNS in pkt or ICMP in pkt:
        return
    
    purge_expired_pkts(pkt)

    dns = pkt.getlayer('DNS')
    ip  = pkt.getlayer('IP')

    if (dns.qr == 0): # Query pkt
        t = ('Qry', ip.src, ip.dst, dns.qd.qname)
        dns_dict[dns.id] = set()
        dns_dict[dns.id].add(t)
        
        pkt_time = int(pkt.time)
        if pkt_time in dns_time_dict:
            dns_time_dict[pkt_time].add(dns.id)
        else:
            dns_time_dict[pkt_time] = set()
            dns_time_dict[pkt_time].add(dns.id)

    else: # Response pkt
        count = dns.ancount # no. of answers

        if (count == 0):
            ans = "null"
        elif (count == 1):
            ans = dns.an.rdata
        else:
            ans = ""
            l = dns.an
            for i in range(count):
                if (l.type == 1):
                    ans = (l.rdata) + "," + ans
                l = l.payload
            ans = ans[:len(ans)-1]

        t = ('Ans', ip.src, ip.dst, dns.qd.qname, ans)
        dns_dict[dns.id].add(t)

    # Spoofing Detection
    if (len(dns_dict[dns.id]) > 2):
        ans = ""
        i = 0
        for s in dns_dict[dns.id]:
            if (s[0] == 'Ans'):
                i += 1
                ans += 'Ans' + str(i) + ": " + s[4] + ", "

        if (i < 2):
            return

        print('DETECT: ID: %s Domain: %s Dst: %s:%s Src: %s:%s Answers: %s' \
                % (str(dns.id) , dns.qd.qname.decode(), ip.dst, str(pkt[UDP].dport), \
                ip.src, str(pkt[UDP].sport), ans))


def main(filename):
    packets = rdpcap(filename)
    for pkt in packets:
        store_detect(pkt)

    # print(dns_dict)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        filename = sys.argv[1]
    else:
        filename = 'sample.pcap'
    main(filename)
