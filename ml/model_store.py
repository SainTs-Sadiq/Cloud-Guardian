"""
Durable, signed storage for anomaly models (replaces the ./data/*.joblib files).

- save_model(scope, detector) writes the joblib blob + HMAC signature to the DB.
- load_model(scope) returns a detector or None. None means "run without learned
  state" (fail-closed): missing rows, a bad signature, or an unreadable blob all
  log a warning and return None. Nothing is retrained silently here.
- A process-wide cache avoids a DB round trip per scan. clear_cache() is for tests
  and for picking up a freshly retrained model.
"""
import hashlib
import hmac
import io
import logging
import os
import threading

import joblib
from sqlalchemy import select

logger = logging.getLogger("cloud_guardian.model_store")

GLOBAL_SCOPE = "global"
_cache: dict[str, object] = {}
_lock = threading.Lock()


def _signing_key() -> bytes:
    key = os.environ.get("SECRET_KEY", "")
    if not key:
        raise RuntimeError("SECRET_KEY is required to sign anomaly models")
    return key.encode()


def _sign(blob: bytes) -> str:
    return hmac.new(_signing_key(), blob, hashlib.sha256).hexdigest()


def clear_cache() -> None:
    with _lock:
        _cache.clear()


def _serialize(detector) -> bytes:
    buf = io.BytesIO()
    joblib.dump({
        "model": detector.model, "scaler": detector.scaler,
        "trained_at": detector.trained_at,
        "n_training_samples": detector.n_training_samples,
        "contamination": detector.contamination,
    }, buf)
    return buf.getvalue()


async def save_model(db, scope: str, detector) -> None:
    from db.models.anomaly_model import AnomalyModelRecord, _utcnow
    blob = _serialize(detector)
    sig = _sign(blob)
    row = await db.get(AnomalyModelRecord, scope)
    if row is None:
        row = AnomalyModelRecord(scope=scope, blob=blob, signature=sig, updated_at=_utcnow())
        db.add(row)
    else:
        row.blob, row.signature, row.updated_at = blob, sig, _utcnow()
    await db.flush()
    with _lock:
        _cache[scope] = detector
    logger.info(f"Anomaly model saved to DB (scope={scope})")


async def load_model(db, scope: str):
    """Return a detector for scope, or None (fail-closed, never raises)."""
    with _lock:
        if scope in _cache:
            return _cache[scope]
    try:
        from db.models.anomaly_model import AnomalyModelRecord
        row = await db.get(AnomalyModelRecord, scope)
    except Exception as e:
        logger.warning(f"Anomaly model lookup failed (scope={scope}): {type(e).__name__}; running without learned state")
        return None
    if row is None:
        logger.warning(f"No anomaly model stored (scope={scope}); running without learned state")
        return None
    blob = bytes(row.blob)
    try:
        ok = hmac.compare_digest(_sign(blob), row.signature or "")
    except Exception as e:
        logger.warning(f"Anomaly model cannot be verified (scope={scope}): {type(e).__name__}; running without learned state")
        return None
    if not ok:
        logger.warning(f"Anomaly model signature mismatch (scope={scope}); refusing it, running without learned state")
        return None
    try:
        from ml.anomaly_detector import AnomalyDetector
        d = joblib.load(io.BytesIO(blob))
        inst = AnomalyDetector(contamination=d.get("contamination", 0.05))
        inst.model = d["model"]
        inst.scaler = d["scaler"]
        inst.trained_at = d.get("trained_at")
        inst.n_training_samples = d.get("n_training_samples", 0)
    except Exception as e:
        logger.warning(f"Anomaly model unreadable (scope={scope}): {type(e).__name__}; running without learned state")
        return None
    with _lock:
        _cache[scope] = inst
    return inst
