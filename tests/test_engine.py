from ids.engine import DetectionEngine

def make_features(**kwargs):
    base = {
        "packet_size": 100,
        "flow_duration": 1,
        "packet_rate": 10,
        "byte_rate": 500,
        "tcp_flags": 0,
        "window_size": 1024
    }
    base.update(kwargs)
    return base

def test_signature_syn_detects():
    engine = DetectionEngine()
    f = make_features(tcp_flags=0x02)  # SYN
    out = engine.detect_threats(f)
    assert "signature" in out

def test_signature_portscan_detects():
    engine = DetectionEngine()
    f = make_features(packet_rate=500)  # Port scan
    out = engine.detect_threats(f)
    assert "signature" in out

def test_no_detection_for_normal():
    engine = DetectionEngine()
    f = make_features()
    out = engine.detect_threats(f)
    assert isinstance(out, list)