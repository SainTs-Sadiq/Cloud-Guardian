import json

from simulation.evaluator import evaluate_results
from simulation.runner import run_simulation
from simulation.scenarios import list_scenarios


def test_scenarios_are_synthetic_and_do_not_expose_raw_event_payloads():
    scenarios = list_scenarios()
    assert len(scenarios) >= 5
    assert all("raw" not in scenario for scenario in scenarios)
    assert any(s["expected_detection"] is False for s in scenarios)


def test_evaluator_confusion_matrix_and_metrics():
    results = [
        {"expected_detection": True, "detected": True, "expected_technique_id": "T1", "actual_technique_id": "T1", "detection_latency_seconds": 1},
        {"expected_detection": True, "detected": False, "expected_technique_id": "T2", "actual_technique_id": None, "detection_latency_seconds": None},
        {"expected_detection": False, "detected": True, "expected_technique_id": None, "actual_technique_id": "T3", "detection_latency_seconds": 2},
        {"expected_detection": False, "detected": False, "expected_technique_id": None, "actual_technique_id": None, "detection_latency_seconds": None},
    ]
    report = evaluate_results(results, "test-run")
    assert report["confusion_matrix"] == {"true_positive": 1, "false_positive": 1, "true_negative": 1, "false_negative": 1}
    assert report["metrics"]["precision"] == 0.5
    assert report["metrics"]["recall_detection_rate"] == 0.5
    assert report["metrics"]["f1_score"] == 0.5
    assert report["metrics"]["accuracy"] == 0.5
    assert report["metrics"]["mitre_mapping_accuracy"] == 1.0
    assert report["metrics"]["remediation_success_rate"] is None


def test_run_simulation_persists_json_report(tmp_path):
    report = run_simulation(results_dir=tmp_path, severity_threshold=30)
    assert report["mode"] == "synthetic_offline"
    assert report["scenario_count"] == len(list_scenarios())
    assert (tmp_path / f"{report['run_id']}.json").exists()
    saved = json.loads((tmp_path / f"{report['run_id']}.json").read_text())
    assert saved["run_id"] == report["run_id"]
    assert "limitations" in saved
