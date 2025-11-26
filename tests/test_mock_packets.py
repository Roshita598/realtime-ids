from scapy.all import IP, TCP
from ids.engine import DetectionEngine
from ids.analyzer import TrafficAnalyzer

def test_signature_detection():
    engine = DetectionEngine()
    analyzer = TrafficAnalyzer()

    pkt = IP()/TCP(flags="S")
    features = analyzer.extract_features(pkt)
    alerts = engine.detect_threats(features)

    assert "signature" in alerts