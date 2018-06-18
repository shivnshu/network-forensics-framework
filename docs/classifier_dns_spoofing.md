# ML based DNS response packets classifier
Based on the paper [Defense against DNS ManInTheMiddle Spoofing](https://link.springer.com/chapter/10.1007/978-3-642-23971-7_39)

## Implementation
* Our aim is to classify the DNS reply packets as being genuine or spoofed.
* For this classification, we used a Multi Layer Perceptron with one hidden layer of size 5, input size of 3 and output size of 1.
* To extract the 3-sized feature vector of packets, we used the fields Answer RRs, Authority RRs and Additional RRs as suggested by the paper.
* The output is either 0 indicative of genuine packet or 1 indicative of spoofed packet.
* To acquire our training database, we captured the network traffic having some known spoofed and genuine DNS replies. We extracted genuine pkt and save them in 0.pcap and spoofed ones in 1.pcap.
* Our script reads these files and temporary stores the packets into python list. We also store the actual output (0 or 1) into another temporary list.
* We shuffle both of these lists, maintaining their relationship, before using them for training MLP as to facilitate better learning.
* Finally, we train the MLP with our newly shuffled list and, after training, we test the model accuracy using our test dataset.
