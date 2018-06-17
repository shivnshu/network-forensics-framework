import scripts.detect_dns_spoofing
import scripts.classifier_dns_spoofing
import scripts.darknet_profiling
import scripts.detect_arp_spoofing
import scripts.port_scanning_attack
import scripts.smtp_dissection

def test_detect_dns_spoofing():
    scripts.detect_dns_spoofing.main('captures/sample.pcap')

def test_classifier_dns_spoofing():
    scripts.classifier_dns_spoofing.main('dataset', 'dataset')

def test_darknet_profiling():
    scripts.darknet_profiling.main('captures/sample.pcap', 'scripts/darknet.list')

def test_detect_arp_spoofing():
    pass

def test_port_scanning_attack():
    scripts.port_scanning_attack.main('captures/sample.pcap')

def test_smtp_dissection():
    scripts.smtp_dissection.main('captures/sample.pcap')
