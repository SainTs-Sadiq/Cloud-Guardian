import logging
from dataclasses import dataclass
from datetime import datetime, timezone
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from detection.cloudtrail_ingest import NormalizedEvent

logger = logging.getLogger("cloud_guardian.ml")

@dataclass
class FeatureRow:
    event_name_freq: float
    hour_of_day: int
    is_weekend: int
    new_source_ip: int
    new_region: int
    actor_event_count_1h: int
    is_management_event: int

WRITE_PREFIXES = ("Create","Delete","Put","Update","Attach","Detach","Modify","Terminate","Stop","Start","Revoke","Authorize","Run")

def extract_features(event, actor_history=None):
    t = event.get("event_time")
    if not isinstance(t, datetime): t = datetime.now(timezone.utc)
    t = t.astimezone(timezone.utc)
    name = event["event_name"]
    ip = event.get("source_ip")
    region = event["region"]
    if actor_history is not None and len(actor_history) > 0:
        total = len(actor_history)
        freq = (actor_history["event_name"] == name).sum() / total
        new_ip = int(ip not in set(actor_history["source_ip"].dropna()))
        new_reg = int(region not in set(actor_history["region"].dropna()))
        one_hr_ago = t - pd.Timedelta(hours=1)
        count_1h = len(actor_history[actor_history["event_time"] >= one_hr_ago])
    else:
        freq, new_ip, new_reg, count_1h = 0.0, 1, 1, 1
    return FeatureRow(
        event_name_freq=freq, hour_of_day=t.hour, is_weekend=int(t.weekday() >= 5),
        new_source_ip=new_ip, new_region=new_reg, actor_event_count_1h=count_1h,
        is_management_event=int(name.startswith(WRITE_PREFIXES)),
    )

class AnomalyDetector:
    def __init__(self, contamination=0.05, random_state=42):
        self.contamination = contamination
        self.random_state = random_state
        self.model = None
        self.scaler = None
        self.trained_at = None
        self.n_training_samples = 0

    def fit(self, feature_rows):
        if len(feature_rows) < 20:
            logger.warning(f"Only {len(feature_rows)} training samples. Recommend 100+ for reliable scoring.")
        X = self._to_array(feature_rows)
        self.scaler = StandardScaler()
        X_s = self.scaler.fit_transform(X)
        contamination = min(self.contamination, 0.5) if len(feature_rows) >= 20 else 0.1
        self.model = IsolationForest(contamination=contamination, random_state=self.random_state, n_estimators=100)
        self.model.fit(X_s)
        self.trained_at = datetime.now(timezone.utc)
        self.n_training_samples = len(feature_rows)
        logger.info(f"Anomaly model trained on {len(feature_rows)} samples.")

    def score(self, row):
        if self.model is None or self.scaler is None:
            logger.warning("score() called before fit(). Returning 0.5.")
            return 0.5
        X = self.scaler.transform(self._to_array([row]))
        raw = self.model.decision_function(X)[0]
        return float(np.clip(1 / (1 + np.exp(raw * 6)), 0.0, 1.0))

    def save(self, path):
        joblib.dump({"model": self.model, "scaler": self.scaler, "trained_at": self.trained_at,
                     "n_training_samples": self.n_training_samples, "contamination": self.contamination}, path)
        logger.info(f"Model saved to {path}")

    @classmethod
    def load(cls, path):
        d = joblib.load(path)
        inst = cls(contamination=d.get("contamination", 0.05))
        inst.model = d["model"]
        inst.scaler = d["scaler"]
        inst.trained_at = d.get("trained_at")
        inst.n_training_samples = d.get("n_training_samples", 0)
        return inst

    @staticmethod
    def _to_array(rows):
        return np.array([[r.event_name_freq, r.hour_of_day, r.is_weekend, r.new_source_ip,
                          r.new_region, r.actor_event_count_1h, r.is_management_event] for r in rows], dtype=float)

def build_actor_history(events):
    rows = [{"actor_arn": e["actor"].get("arn","unknown"), "event_name": e["event_name"],
             "source_ip": e.get("source_ip"), "region": e["region"], "event_time": e["event_time"]} for e in events]
    df = pd.DataFrame(rows)
    if df.empty: return {}
    return {arn: grp for arn, grp in df.groupby("actor_arn")}
