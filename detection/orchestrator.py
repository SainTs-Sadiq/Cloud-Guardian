"""
Cloud Guardian detection orchestrator.

Usage:
    python -m detection.orchestrator scan [--minutes N] [--no-ml]
    python -m detection.orchestrator monitor
    python -m detection.orchestrator check
"""
import argparse
import logging
import sys
import time
from pathlib import Path
from config.settings import AWS, DETECTION
from detection.cloudtrail_ingest import check_credentials, fetch_recent_events
from detection.guardduty_ingest import fetch_findings, list_active_detectors
from detection.rule_engine import score_event
from detection.storage import get_store
from ml.anomaly_detector import AnomalyDetector, build_actor_history, extract_features

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("cloud_guardian.orchestrator")

MODEL_PATH = "./data/anomaly_model.joblib"

def run_scan(lookback_minutes=None, use_ml=True):
    store = get_store()
    all_alerts = []

    logger.info(f"Fetching CloudTrail events (last {lookback_minutes or DETECTION.lookback_minutes} min)...")
    try:
        ct_events = list(fetch_recent_events(lookback_minutes=lookback_minutes))
    except Exception as e:
        logger.error(f"CloudTrail fetch failed: {e}"); ct_events = []
    logger.info(f"Retrieved {len(ct_events)} CloudTrail events.")

    anomaly_detector = None
    actor_histories = {}
    if use_ml and Path(MODEL_PATH).exists():
        try:
            anomaly_detector = AnomalyDetector.load(MODEL_PATH)
            actor_histories = build_actor_history(ct_events)
            logger.info(f"Loaded anomaly model (trained on {anomaly_detector.n_training_samples} samples).")
        except Exception as e:
            logger.warning(f"Could not load anomaly model: {e}")
    elif use_ml:
        logger.info(f"No trained model at {MODEL_PATH}. Run `python -m ml.train_baseline` first.")

    for event in ct_events:
        ml_score = None
        if anomaly_detector:
            history = actor_histories.get(event["actor"].get("arn", "unknown"))
            ml_score = anomaly_detector.score(extract_features(event, actor_history=history))
        alert = score_event(event, ml_anomaly_score=ml_score)
        if alert and alert.severity >= DETECTION.alert_threshold:
            store.save(alert)
            all_alerts.append(alert.to_dict())
            logger.warning(f"ALERT [{alert.severity}/100] {alert.technique_id} {alert.technique_name} ({alert.tactic}) — {alert.event_name}")

    logger.info("Fetching GuardDuty findings...")
    try:
        gd_events = fetch_findings()
    except Exception as e:
        logger.error(f"GuardDuty fetch failed: {e}"); gd_events = []
    logger.info(f"Retrieved {len(gd_events)} GuardDuty findings.")

    for event in gd_events:
        alert = score_event(event)
        if alert and alert.severity >= DETECTION.alert_threshold:
            store.save(alert)
            all_alerts.append(alert.to_dict())
            logger.warning(f"ALERT [{alert.severity}/100] {alert.technique_id} GuardDuty: {alert.event_name}")

    logger.info(f"Scan complete. {len(all_alerts)} new alert(s) above threshold ({DETECTION.alert_threshold}).")
    return all_alerts

def run_monitor():
    logger.info(f"Starting continuous monitor (poll: {DETECTION.poll_interval_seconds}s, lookback: {DETECTION.lookback_minutes}m)")
    while True:
        try: run_scan()
        except Exception as e: logger.error(f"Scan iteration failed: {e}", exc_info=True)
        time.sleep(DETECTION.poll_interval_seconds)

def run_check():
    print("=== Cloud Guardian: Configuration Check ===\n")
    identity = check_credentials()
    if identity["ok"]:
        print(f"✓ AWS credentials valid\n  Account: {identity['account']}\n  ARN:     {identity['arn']}")
    else:
        print(f"✗ AWS credentials INVALID: {identity['error']}")
        print("\nConfigure credentials via:")
        print("  - environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)")
        print("  - aws configure (writes to ~/.aws/credentials)")
        print("  - IAM role (if running on EC2/ECS)")
        return
    print(f"\nRegion: {AWS.region}")
    detectors = list_active_detectors()
    if detectors:
        print(f"✓ GuardDuty enabled ({len(detectors)} detector(s))")
    else:
        print("⚠ GuardDuty not enabled in this region. Recommended for full coverage.")
    try:
        events = list(fetch_recent_events(lookback_minutes=5))
        print(f"✓ CloudTrail accessible ({len(events)} event(s) in last 5 minutes)")
    except Exception as e:
        print(f"✗ CloudTrail LookupEvents failed: {e}")
    print(f"\nAlert threshold: {DETECTION.alert_threshold}/100")
    from config.settings import REMEDIATION, STORAGE
    print(f"Remediation: {'ENABLED' if REMEDIATION.enabled else 'DRY-RUN (disabled)'}")
    print(f"Storage: {'local JSONL' if STORAGE.use_local_store else 'DynamoDB'}")
    print(f"Model: {'loaded' if Path(MODEL_PATH).exists() else 'not trained yet — run python -m ml.train_baseline'}")

def main():
    parser = argparse.ArgumentParser(description="Cloud Guardian detection engine")
    sub = parser.add_subparsers(dest="command", required=True)
    sp = sub.add_parser("scan")
    sp.add_argument("--minutes", type=int, default=None)
    sp.add_argument("--no-ml", action="store_true")
    sub.add_parser("monitor")
    sub.add_parser("check")
    args = parser.parse_args()
    if args.command == "scan":
        alerts = run_scan(lookback_minutes=args.minutes, use_ml=not args.no_ml)
        if not alerts: print("No alerts above threshold.")
    elif args.command == "monitor":
        run_monitor()
    elif args.command == "check":
        run_check()

if __name__ == "__main__":
    sys.exit(main())
