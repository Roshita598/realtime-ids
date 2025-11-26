import os
import numpy as np
from joblib import dump, load
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from .rules.signatures import SIGNATURE_RULES
from .rules.heuristics import HEURISTIC_RULES

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
os.makedirs(MODEL_DIR, exist_ok=True)
MODEL_PATH = os.path.join(MODEL_DIR, "if_model.joblib")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.joblib")

class DetectionEngine:

    def __init__(self):
        self.signature_rules = SIGNATURE_RULES + HEURISTIC_RULES

        self.model = IsolationForest(n_estimators=100, contamination=0.05)
        self.scaler = StandardScaler()
        self.training_data = []
        self.is_trained = False

        try:
            self.model = load(MODEL_PATH)
            self.scaler = load(SCALER_PATH)
            self.is_trained = True
            print("[+] Loaded ML model")
        except:
            pass

    def feature_vector(self, features):
        return [
            features.get("packet_size", 0),
            features.get("flow_duration", 0),
            features.get("packet_rate", 0),
            features.get("byte_rate", 0),
            int(features.get("tcp_flags", 0)),
            features.get("window_size", 0)
        ]

    def train(self):
        if len(self.training_data) < 20:
            print("Not enough data to train")
            return False

        X = np.array(self.training_data)
        self.scaler.fit(X)
        Xs = self.scaler.transform(X)
        self.model.fit(Xs)
        dump(self.model, MODEL_PATH)
        dump(self.scaler, SCALER_PATH)
        self.is_trained = True
        return True

    def detect(self, features):
        alerts = []

        for rule in self.signature_rules:
            if rule(features):
                alerts.append("signature")

        if self.is_trained:
            fv = np.array([self.feature_vector(features)])
            score = self.model.predict(self.scaler.transform(fv))
            if score[0] == -1:
                alerts.append("anomaly")

        return alerts