from ids.analyzer import TrafficAnalyzer
from scapy.all import IP, TCP

def test_extract_features():
    analyzer = TrafficAnalyzer()
    pkt = IP()/TCP(flags="S")
    f = analyzer.extract_features(pkt)

    assert "packet_size" in f
    assert "tcp_flags" in f
    assert f["tcp_flags"] == 0x02