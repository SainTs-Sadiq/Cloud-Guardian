"""Metric calculation for scenario-level Cloud Guardian evaluations."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any


def _safe_div(numerator: float, denominator: float) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def evaluate_results(results: list[dict[str, Any]], run_id: str | None = None) -> dict[str, Any]:
    """Compute confusion-matrix and coverage metrics from saved scenario results.

    A detection is counted only when the detector returned a finding meeting
    the configured severity threshold. Unavailable denominators are null,
    never misleading zeroes.
    """
    tp = fp = tn = fn = 0
    mapping_checked = mapping_correct = 0
    detection_lags = []
    for result in results:
        expected = bool(result["expected_detection"])
        detected = bool(result["detected"])
        if expected and detected: tp += 1
        elif not expected and detected: fp += 1
        elif not expected and not detected: tn += 1
        else: fn += 1

        expected_technique = result.get("expected_technique_id")
        if expected_technique:
            mapping_checked += 1
            if result.get("actual_technique_id") == expected_technique:
                mapping_correct += 1
        if detected and result.get("detection_latency_seconds") is not None:
            detection_lags.append(float(result["detection_latency_seconds"]))

    total = tp + fp + tn + fn
    detected_positive = tp + fn
    report = {
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scenario_count": total,
        "confusion_matrix": {"true_positive": tp, "false_positive": fp, "true_negative": tn, "false_negative": fn},
        "metrics": {
            "precision": _safe_div(tp, tp + fp),
            "recall_detection_rate": _safe_div(tp, tp + fn),
            "f1_score": _safe_div(2 * tp, 2 * tp + fp + fn),
            "accuracy": _safe_div(tp + tn, total),
            "false_positive_rate": _safe_div(fp, fp + tn),
            "false_negative_rate": _safe_div(fn, fn + tp),
            "mitre_mapping_accuracy": _safe_div(mapping_correct, mapping_checked),
            "mitre_mapping_checked": mapping_checked,
            "mean_time_to_detect_seconds": round(sum(detection_lags) / len(detection_lags), 3) if detection_lags else None,
            "remediation_success_rate": None,
            "remediation_note": "Not measured by the synthetic simulator; no remediation actions are executed.",
            "positive_scenarios": detected_positive,
        },
        "results": results,
        "limitations": [
            "Synthetic event evaluation measures the current rule engine against this scenario set, not live AWS telemetry.",
            "A missing technique mapping is treated as a false negative when the scenario is ground-truth positive.",
            "Remediation success is not measured because this simulator never performs cloud changes.",
        ],
    }
    return report
