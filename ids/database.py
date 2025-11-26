import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "alerts.db")

class Database:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._create_tables()

    def _create_tables(self):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                alert_type TEXT,
                details TEXT
            )
        """)
        conn.commit()
        conn.close()

    def log_alert(self, alert_type, details):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO alerts (timestamp, alert_type, details) VALUES (?, ?, ?)",
            (datetime.now().isoformat(), alert_type, details)
        )
        conn.commit()
        conn.close()

    def get_recent_alerts(self, limit=50):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?",
            (limit,)
        )
        rows = cur.fetchall()
        conn.close()
        return rows