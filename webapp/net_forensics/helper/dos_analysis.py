#!/usr/bin/env python3
import sys, os, time
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scripts'))
import detect_dos

def pretty_time(seconds):
    local_time = time.localtime(seconds)
    year = local_time.tm_year
    month = local_time.tm_mon
    date = local_time.tm_mday
    hour = local_time.tm_hour
    min = local_time.tm_min
    sec = local_time.tm_sec
    time_str = str(hour)+":"+str(min)+":"+str(sec)+" "+str(month)+"/"\
        +str(date)+"/"+str(year)
    return time_str

def main(capture_file):
    dos_attacks_dict = detect_dos.main(capture_file)
    return dos_attacks_dict

# print(main('../../../captures/sample.pcap'))
