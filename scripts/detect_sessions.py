#!/usr/bin/env python3
from scapy.all import *
import ipaddress
import os
import sys

def main(capture_file):
    sessions_info = []
    packets = rdpcap(capture_file)
    sessions = packets.sessions()
    for session in sessions:
        this_session = {}
        summary = session.split()
        this_session["proto"] = summary[0]
        this_session["src"] = summary[1]
        this_session["dst"] = summary[3]
        this_session["data"] = sessions[session]
        if this_session["proto"] == "TCP":
            sessions_info.append(this_session)

    return sessions_info


if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if len(sys.argv) > 1:
        filename = sys.argv[1]
    else:
        filename = os.path.join(script_dir, '../captures/sample.pcap')
    print(main(filename))
