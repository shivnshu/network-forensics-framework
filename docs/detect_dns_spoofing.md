# Detection of DNS spoofing

## Implementation
* The principle behind the DNS detection script is that if there is more than one replies corresponding to a DNS query within a time window, we consider it a possible candidate of DNS spoofing.
* A reply is considered to be corresponding to a DNS query if the identifier of reply packet is same as the identifier of query packet.
* For our script, we maintain two dictionary named dns\_dict and dns\_time\_dict.
* Dictionary dns\_dict is used to maintain the mapping between DNS packet identifier and set of corresponding packets metadata.
* Dictionary dns\_time\_dict is used to maintain mapping between packet timestamp and set of corresponding packets Identifiers. The function of this dictionary is to keep track of packets timestamp as to facilitate the purging of expired packets.
* For each new packet we consider from the pcap file, first we check dns\_time\_dict to remove from it any expired packet. We also remove these packets from dns\_dict by following the Identifier from dns\_time\_dict.
* In the next step, we extract the metadata from this packet and store it in dns\_dict corresponding to its identifier and we store its identifer corresponding to timestamp in dns\_time\_dict.
* Finally, corresponding to each identifier of the dictionary dns\_dict we check for no. of replies. If it is greater that one, we alert for the possible DNS spoofing.
