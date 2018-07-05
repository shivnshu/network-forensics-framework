#!/usr/bin/env python3
import sys, os
import pickle
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scripts'))
import detect_dns_spoofing

def main(capture_file):
    dns_detect_list = detect_dns_spoofing.main(capture_file)
    model_filename = "../scripts/data/dns_classifier.model"
    loaded_model = pickle.load(open(model_filename, 'rb'))
    for domain in dns_detect_list:
        domain["attacker_ip"] = ""
        for response in domain['response']:
            features = response['feature_vector']
            feature_vector = [features['ancount'], features['nscount'],
                                features['arcount']]
            # print(feature_vector)
            prediction = loaded_model.predict([feature_vector])
            # print(prediction)
            del response['feature_vector']
            response['prediction'] = "Spoof" if prediction else "Genuine"
            if prediction:
                domain["attacker_ip"] = response['answers'][0]

    return dns_detect_list

# print(main('../../../captures/sample.pcap'))
