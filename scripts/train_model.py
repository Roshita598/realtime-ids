# scripts/train_model.py
import csv
import os
import sys
from joblib import dump
from ids.engine import DetectionEngine

DATA_CSV = os.path.join(os.path.dirname(__file__), "..", "data", "training.csv")

def load_csv(path):
    rows = []
    with open(path, newline="") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        for r in reader:
            rows.append([float(x) for x in r])
    return rows

def main():
    if not os.path.exists(DATA_CSV):
        print(f"[!] Training CSV not found at {DATA_CSV}. Create it by running the IDS in record mode.")
        sys.exit(1)

    engine = DetectionEngine()
    rows = load_csv(DATA_CSV)
    for r in rows:
        # map row back to engine training_data shape
        engine.training_data.append(r)
    success = engine.train_model(persist=True)
    if not success:
        print("[!] Training failed: not enough data")
    else:
        print("[+] Training complete and model persisted.")

if __name__ == "__main__":
    main()