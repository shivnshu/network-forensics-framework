#!/usr/bin/env python3
import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), '../scripts'))
import detect_sessions

def main(capture_file):
    sessions_info = detect_sessions.main(capture_file)

    return sessions_info

#print(main('../../../captures/sample.pcap'))
