#!/usr/bin/env python
from sklearn.neural_network import MLPClassifier
from scapy.all import *
import sys
import random

def create_dataset(dataset_location):
    genuine_packets = []
    spoofed_packets = []

    genuine_pcap = rdpcap(dataset_location + "/0.pcap")
    spoofed_pcap = rdpcap(dataset_location + "/1.pcap")

    for pkt in genuine_pcap:
        # Features are [Answer RRs, Authority RRs, Additional RRs]
        feature_vector = [pkt[DNS].ancount, pkt[DNS].nscount, pkt[DNS].arcount]
        genuine_packets.append(feature_vector)
    for pkt in spoofed_pcap:
        feature_vector = [pkt[DNS].ancount, pkt[DNS].nscount, pkt[DNS].arcount]
        spoofed_packets.append(feature_vector)

    merged_packets = genuine_packets + spoofed_packets
    merged_outputs = [0]*len(genuine_packets) + [1]*len(spoofed_packets)
    assert(len(merged_packets) == len(merged_outputs))
    tmp = list(zip(merged_packets, merged_outputs))
    random.shuffle(tmp)
    merged_packets, merged_outputs = zip(*tmp)
    return merged_packets, merged_outputs


def test_accuracy(model, dataset_location):
    test_packets, actual_labels = create_dataset(dataset_location)
    predicted_labels = model.predict(test_packets)

    c = 0
    for i in range(len(predicted_labels)):
        if (predicted_labels[i] == actual_labels[i]):
            c += 1

    print('Accuracy:', c*100/len(predicted_labels))

def main(train_dataset_location, test_dataset_location):
    packets, labels = create_dataset(train_dataset_location)
    # print(packets)
    # print(labels)
    clf = MLPClassifier(solver='lbfgs', alpha=1e-5, \
            hidden_layer_sizes=(4,1), random_state=1)
    clf.fit(packets, labels)

    test_accuracy(clf, test_dataset_location)

if __name__ == "__main__":
    if len(len(sys.argv) > 1):
        dataset_location = argv[1]
    else:
        dataset_location = '../dataset'
    # For now, test on same dataset
    main(dataset_location, dataset_location)
