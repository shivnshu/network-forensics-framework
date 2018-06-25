#!/usr/bin/env python3
import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scripts'))
import smtp_dissection

def main(capture_file):
    smtp_dissections = smtp_dissection.main(capture_file)
    return smtp_dissections

# print(main('../../../captures/smtp.pcap'))
