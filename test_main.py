import scripts.detect_dns_spoofing
import scripts.classifier_dns_spoofing

def test_detect_dns_spoofing():
    scripts.detect_dns_spoofing.main('scripts/sample.pcap')

def test_classifier_dns_spoofing():
    scripts.classifier_dns_spoofing.main('dataset', 'dataset')
