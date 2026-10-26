"""
FastAPI dependency injection.

Provides shared resources (store, anomaly detector) as FastAPI
dependencies so they're initialized once at startup and injected
into route handlers — not recreated on every request.

Also houses the future auth dependency placeholder so adding JWT/API
key auth in the next sprint is a one-line change per route.
"""
from fastapi import Header, HTTPException, status

from detection.storage import AlertStore, get_store
from ml.anomaly_detector import AnomalyDetector

_store: AlertStore | None = None


def get_alert_store() -> AlertStore:
    global _store
    if _store is None:
        _store = get_store()
    return _store


async def get_anomaly_detector(db) -> AnomalyDetector | None:
    """Load the global anomaly model from durable DB storage (cached in memory).

    Returns None when no valid model exists; detection then runs without
    learned state (fail-closed). Never reads from the local filesystem.
    """
    from ml.model_store import GLOBAL_SCOPE, load_model
    return await load_model(db, GLOBAL_SCOPE)


async def auth_placeholder():
    """No-op auth for now. Replace with real auth in the next sprint."""
    pass
