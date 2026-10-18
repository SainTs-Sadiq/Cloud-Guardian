"""Run synthetic attack scenarios through the real Cloud Guardian rule engine."""
from __future__ import annotations
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from detection.mitre_mappings import get_mapping
from detection.rule_engine import score_event
from config.settings import DETECTION
from simulation.evaluator import evaluate_results
from simulation.scenarios import SCENARIOS

DEFAULT_RESULTS_DIR = Path(os.environ.get("CG_SIMULATION_DIR", "./data/simulations"))


def _normalized_event(scenario: dict, now: datetime) -> dict:
    return {
        "event_id": f"sim-{scenario['id']}-{uuid.uuid4().hex[:12]}",
        "source": "cloudtrail",
        "event_name": scenario["event_name"],
        "event_time": now,
        "actor": {"type": "IAMUser", "principal_id": "SIMULATION", "arn": "arn:aws:iam::000000000000:user/cloud-guardian-simulator", "account_id": "000000000000"},
        "source_ip": "192.0.2.10",
        "region": "us-east-1",
        "resources": [],
        "raw": scenario["raw"],
    }


def run_simulation(results_dir: str | Path | None = None, severity_threshold: int | None = None) -> dict:
    """Run a deterministic, offline scenario batch; never calls AWS APIs."""
    now = datetime.now(timezone.utc)
    threshold = DETECTION.alert_threshold if severity_threshold is None else max(0, min(100, int(severity_threshold)))
    run_id = f"sim-{now.strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:8]}"
    results = []

    for scenario in SCENARIOS:
        event_time = datetime.now(timezone.utc)
        event = _normalized_event(scenario, event_time)
        mapping = get_mapping(scenario["event_name"])
        alert = score_event(event)
        detected = bool(alert and alert.severity >= threshold)
        actual_technique_id = alert.technique_id if alert else (mapping.technique_id if mapping else None)
        # Synthetic detection is evaluated in-process. This is not a claim about
        # CloudTrail ingestion latency; label it as synthetic zero-latency.
        results.append({
            "scenario_id": scenario["id"],
            "scenario_name": scenario["name"],
            "description": scenario["description"],
            "event_id": event["event_id"],
            "event_name": scenario["event_name"],
            "event_time": event_time.isoformat(),
            "expected_detection": scenario["expected_detection"],
            "detected": detected,
            "detection_source": "rule_engine" if alert else None,
            "severity": alert.severity if alert else None,
            "risk_tier": alert.risk_tier if alert else None,
            "actual_technique_id": actual_technique_id,
            "expected_technique_id": scenario["expected_technique_id"],
            "actual_tactic": alert.tactic if alert else None,
            "expected_tactic": scenario["expected_tactic"],
            "mapping_match": bool(scenario["expected_technique_id"] and actual_technique_id == scenario["expected_technique_id"]),
            "detection_latency_seconds": 0.0 if detected else None,
            "remediation_attempted": False,
            "remediation_success": None,
            "status": "detected" if detected else "missed" if scenario["expected_detection"] else "not_detected_as_expected",
        })

    report = evaluate_results(results, run_id=run_id)
    report["severity_threshold"] = threshold
    report["mode"] = "synthetic_offline"
    target_dir = Path(results_dir) if results_dir is not None else DEFAULT_RESULTS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    # One immutable JSON report per run; do not mix tenant/user data.
    report_path = target_dir / f"{run_id}.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    report["report_path"] = str(report_path)
    return report


def latest_report(results_dir: str | Path | None = None) -> dict | None:
    target_dir = Path(results_dir) if results_dir is not None else DEFAULT_RESULTS_DIR
    if not target_dir.exists():
        return None
    reports = sorted(target_dir.glob("sim-*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not reports:
        return None
    try:
        return json.loads(reports[0].read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
