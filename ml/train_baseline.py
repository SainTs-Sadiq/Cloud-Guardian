"""Train the baseline anomaly detection model from historical CloudTrail activity."""
import argparse
import logging
import sys
from pathlib import Path
from detection.cloudtrail_ingest import fetch_recent_events
from ml.anomaly_detector import AnomalyDetector, build_actor_history, extract_features

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("cloud_guardian.train")

def train(days=14, model_path="./data/anomaly_model.joblib"):
    lookback = days * 24 * 60
    logger.info(f"Fetching {days} day(s) of CloudTrail history...")
    events = list(fetch_recent_events(lookback_minutes=lookback))
    logger.info(f"Retrieved {len(events)} events.")
    if len(events) < 10:
        logger.error(f"Only {len(events)} events — need more history. Widen --days or wait for more activity.")
        sys.exit(1)
    histories = build_actor_history(events)
    rows = [extract_features(e, actor_history=histories.get(e["actor"].get("arn","unknown"))) for e in events]
    detector = AnomalyDetector(contamination=0.05)
    detector.fit(rows)
    Path(model_path).parent.mkdir(parents=True, exist_ok=True)
    detector.save(model_path)
    print(f"\n✓ Model trained on {len(rows)} samples from {days} day(s) of activity.")
    print(f"✓ Saved to {model_path}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--days", type=int, default=14)
    parser.add_argument("--output", type=str, default="./data/anomaly_model.joblib")
    args = parser.parse_args()
    train(days=args.days, model_path=args.output)

if __name__ == "__main__":
    main()
