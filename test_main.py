import scripts.classifier_dns_spoofing
import scripts.darknet_profiling
import scripts.detect_arp_spoofing
import scripts.detect_dhcp_starvation
import scripts.detect_dns_spoofing
import scripts.detect_dos
import scripts.detect_gateway
import scripts.detect_sessions
import scripts.port_scanning_attack
import scripts.protocol_hierarchy
import scripts.protocols_time_series
import scripts.smtp_dissection

def test_classifier_dns_spoofing():
    scripts.classifier_dns_spoofing.main('captures/dataset', 'captures/dataset')

def test_darknet_profiling():
    scripts.darknet_profiling.main('captures/sample.pcap')

def test_detect_arp_spoofing():
    scripts.detect_arp_spoofing.main('captures/sample.pcap')

def test_detect_dhcp_starvation():
    scripts.detect_dhcp_starvation.main('captures/sample.pcap')

def test_detect_dns_spoofing():
    scripts.detect_dns_spoofing.main('captures/sample.pcap')

def test_detect_dos():
    scripts.detect_dos.main('captures/sample.pcap')

def test_detect_gateway():
    scripts.detect_gateway.main('captures/sample.pcap')

def test_detect_sessions():
    scripts.detect_sessions.main('captures/sample.pcap')

def test_port_scanning_attack():
    scripts.port_scanning_attack.main('captures/sample.pcap')

def test_protocol_hierarchy():
    scripts.protocol_hierarchy.main('captures/sample.pcap')

def test_protocols_time_series():
    scripts.protocols_time_series.main('captures/sample.pcap')

def test_smtp_dissection():
    scripts.smtp_dissection.main('captures/sample.pcap')
