## Detection of Mail bomb attack

#Implementation

* Principle: An attacker sends huge volumes of duplicate mails to the same mail address in a very short time.These mails may come with a large attachments.The mailbox will become unusable, when it confronts with a large number of mail packets and as it's storage capacity is limited.Mail bomb utilizes the Simple Mail Transfer Protocol (SMTP).
* In order to detect mail-bomb attack ,firstly we will extract total number of TCP packets from pcap file.
* After extracting TCP packets, we will check for source port as SMTP(i.e port 25 ,425, 587).
* Then we will check the flow size.If the flow size exceeds the threshold value ,then we can generate alert for Mail-Bomb  	attack.
