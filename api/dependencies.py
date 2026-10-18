"""
FastAPI dependency injection.

Provides shared resources (store, anomaly detector) as FastAPI
dependencies so they're initialized once at startup and injected
into route handlers — not recreated on every request.

Also houses the future auth dependency placeholder so adding JWT/API
key auth in the next sprint is a one-line change per route.
"""
from pathlib import Path
from functools import lru_cache
from fastapi import Header, HTTPException, status

from detection.storage import AlertStore, get_store
from ml.anomaly_detector import AnomalyDetector

MODEL_PATH = "./data/anomaly_model.joblib"


_store: AlertStore | None = None
_detector: AnomalyDetector | None = None


def get_alert_store() -> AlertStore:
    global _store
    if _store is None:
        _store = get_store()
    return _store


def get_anomaly_detector() -> AnomalyDetector | None:
    global _detector
    if _detector is None and Path(MODEL_PATH).exists():
        try:
            _detector = AnomalyDetector.load(MODEL_PATH)
        except Exception:
            pass
    return _detector


async def auth_placeholder():
    """No-op auth for now. Replace with real auth in the next sprint."""
    pass
