from ids.alert import AlertSystem

def test_alert_log_simple():
    alert_system = AlertSystem(logfile="test_alerts.log")

    alert = "signature"
    features = {"packet_size": 123}

    # Should not crash
    alert_system.send_alert(alert, features)

    with open("test_alerts.log") as f:
        content = f.read()

    assert "signature" in content