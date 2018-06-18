# SMTP packet stream data extraction

## Implementation
* This script extracts the email communication between two parties over SMTP protocol.
* To accomplish this task, we made use of sessions method of scapy library passing our custom full\_duplex() function.
* Our full\_duplex function is responsible for merging the pairs of two one-way sessions into one two-way session.
* Following our two-way sessions extraction is the filtering of the SMTP protocol which is based on the known ports 25, 465 and 587.
* Next step involves the inorder extraction of packets payload and printing.
