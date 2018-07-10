# Detection of ARP spoofing

## Implementation
* ARP spoofing is a type of attack in which a malicious actor sends falsified ARP messages over a local area network. This results in the linking of an attacker's MAC address with the IP address of a legitimate computer or server on the network.
* We can detect whether network is being ARP spoofed by monitoring the mapping between IP addresses and MAC addresses.
* In this script, we maintained the mapping between MAC address to IP address , making use of dictionary variable mac\_ip\_dict.
* First, We filter ARP packets from the given pcap file.
* Variable mac is used to store the MAC address and ip is used to store the corresponding IP address.
* Finally, we are checking the no. of IPs corresponding to each of MAC address. If more than one IP is found, then an alert is generated for ARP Spoofing.
