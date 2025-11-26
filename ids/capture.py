from scapy.all import sniff
from .analyzer import TrafficAnalyzer
from .engine import DetectionEngine
from .alert import AlertSystem
from .database import Database

class PacketCapture:

    def __init__(self, iface=None):
        self.analyzer = TrafficAnalyzer()
        self.engine = DetectionEngine()
        self.alerts = AlertSystem()
        self.db = Database()
        self.iface = iface

    def handle_packet(self, pkt):
        features = self.analyzer.extract_features(pkt)
        alerts = self.engine.detect(features)

        for alert in alerts:
            self.alerts.send_alert(alert, features)
            self.db.log_alert(alert, str(features))

    def start(self):
        print("[+] Starting capture… (Ctrl+C to stop)")
        sniff(prn=self.handle_packet, iface=self.iface, store=False)