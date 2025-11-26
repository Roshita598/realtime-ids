# ids/main.py
import argparse
import time
import csv
import os
from ids.capture import PacketCapture
from ids.analyzer import TrafficAnalyzer
from ids.engine import DetectionEngine
from ids.alert import AlertSystem

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
os.makedirs(DATA_DIR, exist_ok=True)
TRAIN_CSV = os.path.join(DATA_DIR, "training.csv")

def append_training_row(features):
    header = ["packet_size", "flow_duration", "packet_rate", "byte_rate", "tcp_flags", "window_size"]
    row = [
        features.get("packet_size", 0),
        features.get("flow_duration", 0),
        features.get("packet_rate", 0),
        features.get("byte_rate", 0),
        int(features.get("tcp_flags", 0)),
        features.get("window_size", 0)
    ]
    write_header = not os.path.exists(TRAIN_CSV)
    with open(TRAIN_CSV, "a", newline="") as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow(header)
        writer.writerow(row)

class IntrusionDetectionSystem:
    def __init__(self, record=False):
        self.capturer = PacketCapture()
        self.analyzer = TrafficAnalyzer()
        self.engine = DetectionEngine()
        self.alerts = AlertSystem()
        self.record = record

    def start(self):
        print("[+] Starting IDS...")
        self.capturer.start()

        try:
            while True:
                pkt = self.capturer.get_packet()
                features = self.analyzer.extract_features(pkt)

                # OPTION: If user only wants to record data for training, skip detection & alerting
                if self.record:
                    append_training_row(features)
                    # skip detection/alerts while recording normal traffic
                    continue

                # if model not trained, accumulate training buffer automatically (useful for quick experiments)
                if not self.engine.is_trained:
                    self.engine.add_training_data(features)
                    # attempt to train when enough samples
                    self.engine.train_model()

                alerts = self.engine.detect_threats(features)

                for a in alerts:
                    self.alerts.send_alert(a, features)

        except KeyboardInterrupt:
            print("\n[+] IDS stopped.")

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--record", action="store_true", help="Record features to data/training.csv for later training")
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    ids = IntrusionDetectionSystem(record=args.record)
    ids.start()