# Detection of Port Scanning Attack
_Based on the paper [Network Forensic system for Port Scanning Attack](https://ieeexplore.ieee.org/document/5422935/)_

## Implementation
* This script detects the SYN TCP packets based network scanning.
* To accomplish this objective, we maintain a dictionary named tcp\_port\_attacks having key as pair (srcIP, dstIP) and data as the object of class _ipliststruct_.
* The metadata of TCP SYN packets corresponding to each pair of (srcIP, dstIP) is maintained through the class _ipliststruct_.
* An object of class _ipliststruct_ contains srcIP address, dstIP address, port count, packets count, start timestamp, end timestamp and ports scanned so far. It also have methods to change end timestamp, add more scanned port, calculate a metric indicative of its category and printing the metadata in human readable form.
* To decide the category of the object as Normal or Suspicious, a threshold value is used. The method calculate\_rate() of the object can be invoked to get this vale which can further be compared with the threshold value.
