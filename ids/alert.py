# ids/alert.py
import json
import time

def _json_serializer(obj):
    """
    Try to convert common non-serializable types to simple serializable forms.
    - Try int(...) first (works for many Scapy flag/number types).
    - Fallback to str(obj).
    """
    try:
        return int(obj)
    except Exception:
        try:
            return float(obj)
        except Exception:
            return str(obj)

class AlertSystem:
    def __init__(self, logfile="ids_alerts.log"):
        self.logfile = logfile

    def send_alert(self, alert_type_or_dict, features):
        """
        alert_type_or_dict: either a string alert_type or a dict produced by the engine.
        features: the raw features dict (may include Scapy objects).
        """
        # Normalize alert object to a dict with predictable fields
        if isinstance(alert_type_or_dict, str):
            alert_obj = {"alert_type": alert_type_or_dict}
        elif isinstance(alert_type_or_dict, dict):
            # Engine now returns richer dicts like {"type": "signature", "rule": "syn_flood_rule"}
            # Map to a stable top-level key "alert_type" while keeping details in "details"
            alert_type = alert_type_or_dict.get("type") or alert_type_or_dict.get("alert_type") or "unknown"
            # include rest of the engine-provided keys under "meta"
            meta = {k: v for k, v in alert_type_or_dict.items() if k != "type" and k != "alert_type"}
            alert_obj = {"alert_type": alert_type, "meta": meta}
        else:
            alert_obj = {"alert_type": "unknown", "meta": {"raw": str(alert_type_or_dict)}}

        # Create a serializable copy of features
        serializable_features = {}
        for k, v in (features or {}).items():
            try:
                # try the common case first
                json.dumps(v)
                serializable_features[k] = v
            except Exception:
                # fallback to the serializer
                serializable_features[k] = _json_serializer(v)

        alert = {
            "timestamp": time.time(),
            "alert_type": alert_obj.get("alert_type"),
            "meta": alert_obj.get("meta", {}),
            "details": serializable_features
        }

        # Use json.dumps with default serializer as a last-resort safety net
        with open(self.logfile, "a") as f:
            f.write(json.dumps(alert, default=_json_serializer) + "\n")

        print(f"[ALERT] {alert_obj.get('alert_type')} detected! meta={alert_obj.get('meta')}")