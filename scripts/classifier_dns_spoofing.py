#!/usr/bin/env python3
# from sklearn.neural_network import MLPClassifier
# from sklearn import linear_model
from sklearn.svm import SVC
from scapy.all import *
import os
import sys
import pickle
import random

# Function to create dataset from the files
def create_dataset(dataset_location):
    genuine_packets = []
    spoofed_packets = []

    # Genuine packets are stored in 0.pcap file
    genuine_pcap = rdpcap(dataset_location + "/0.pcap")
    # Spoofed packets are stored in 1.pcap file
    spoofed_pcap = rdpcap(dataset_location + "/1.pcap")

    for pkt in genuine_pcap:
        # Features are [Answer RRs, Authority RRs, Additional RRs]
        feature_vector = [pkt[DNS].ancount, pkt[DNS].nscount, pkt[DNS].arcount]
        genuine_packets.append(feature_vector)
    for pkt in spoofed_pcap:
        feature_vector = [pkt[DNS].ancount, pkt[DNS].nscount, pkt[DNS].arcount]
        spoofed_packets.append(feature_vector)

    # Inorder merging of dataset
    merged_packets = genuine_packets + spoofed_packets
    merged_outputs = [0]*len(genuine_packets) + [1]*len(spoofed_packets)

    # Ensure that there is a output corresponding to each feature vector
    assert(len(merged_packets) == len(merged_outputs))
    tmp = list(zip(merged_packets, merged_outputs))
    # Shuffle the dataset for optimum learning
    random.shuffle(tmp)
    merged_packets, merged_outputs = zip(*tmp)
    # Return shuffled inputs and correponding outputs list
    return merged_packets, merged_outputs


# Function to test accuracy of learnt model
def test_accuracy(model, dataset_location):
    test_packets, actual_labels = create_dataset(dataset_location)
    predicted_labels = model.predict_proba(test_packets)
    c = 0
    for i in range(len(predicted_labels)):
        # print(predicted_labels[i][1], actual_labels[i])
        predict = 1 if predicted_labels[i][1] > 0.5 else 0
        if (predict == actual_labels[i]):
            c += 1
    print('Accuracy:', c*100/len(predicted_labels))


# Main function
def main(train_dataset_location, test_dataset_location):
    # Create and store the feature vectors along with their output
    packets, labels = create_dataset(train_dataset_location)
    # print(packets)
    # print(labels)
    # Define a Multi-layer Neuron based classifier
    # clf = MLPClassifier(solver='lbfgs', alpha=1e-5, \
            # hidden_layer_sizes=(5,), random_state=1)
    # clf = linear_model.LogisticRegression()
    clf = SVC(probability=True)
    # Train the model using the created dataset
    clf.fit(packets, labels)

    # Test accuracy and print it
    test_accuracy(clf, test_dataset_location)

    # Save model
    # filename = "data/dns_classifier.model"
    # pickle.dump(clf, open(filename, 'wb'))


# Script entry point
if __name__ == "__main__":
    # Get the script dir path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # Usage: <script> [dataset_folder_location]
    if (len(sys.argv) > 1):
        dataset_location = argv[1]
    else:
        # Default dataset location
        dataset_location = os.path.join(script_dir, '../captures/dataset')
    
    # For now, test on same dataset
    main(dataset_location, dataset_location)
