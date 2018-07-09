## Detection of Ping of Death attack
 
#Implementation

* Principle:Ping of Death Attack involves large number of oversize IP packets in one flow from one computer to another.   Each packet is about 1,000 byte and size of attack flow if high, approximately 64,000 Bytes and it is under ICMP protocol which causes rebooting, freezing and crashing  the victim machine.
* In order to detect PoD attack we will extract ICMP packets from pcap file.
* Then we calculate the total payload of all ICMP packets.
* After this we carve out the ICMP request packets.
* Then we check the size of each packet.
* If size of payload exceeds the threshold value, we can alert the possibility of PoD attack. 

