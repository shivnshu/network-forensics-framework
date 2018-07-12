#!/usr/bin/env python3
import sys, os, time
import pickle
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scripts'))
import detect_dns_spoofing

def pretty_timestamp(time_list):
    def pretty_time(seconds):
        local_time = time.localtime(seconds)
        year = local_time.tm_year
        month = local_time.tm_mon
        date = local_time.tm_mday
        hour = str(local_time.tm_hour)
        if len(hour) == 1:
            hour = "0" + hour
        min = str(local_time.tm_min)
        if len(min) == 1:
            min = "0" + min
        sec = str(local_time.tm_sec)
        if len(sec) == 1:
            sec = "0" + sec
        time_str = hour+":"+min+":"+sec+" "+str(month)+"/"\
            +str(date)+"/"+str(year)
        return time_str
    for i in range(len(time_list)):
        time_list[i] = pretty_time(time_list[i])
    return time_list

def main(capture_file):
    dns_detect_list = detect_dns_spoofing.main(capture_file)
    model_filename = "../scripts/data/dns_classifier.model"
    loaded_model = pickle.load(open(model_filename, 'rb'))
    for domain in dns_detect_list:
        domain["timestamps"] = pretty_timestamp(domain["timestamps"])
        domain["attacker_ip"] = ""
        spoof_pkt_highest_proba = 0
        for response in domain['response']:
            features = response['feature_vector']
            feature_vector = [features['ancount'], features['nscount'],
                                features['arcount']]
            # print(feature_vector)
            prediction = loaded_model.predict_proba([feature_vector])[0]
            # print(prediction)
            del response['feature_vector']
            # response['prediction'] = "Spoof" if prediction else "Genuine"
            response["prediction"] = prediction[1]
            if spoof_pkt_highest_proba < prediction[1]:
                domain["attacker_ip"] = response['answers'][0]
                spoof_pkt_highest_proba = prediction[1]

        spoof_pkt_tag_attached = False
        for response in domain["response"]:
            if not spoof_pkt_tag_attached and response['prediction'] == spoof_pkt_highest_proba:
                response['prediction'] = "Spoof"
                spoof_pkt_tag_attached = True
            else:
                response['prediction'] = 'Genuine'

    return dns_detect_list

# print(main('../../../captures/sample.pcap'))
