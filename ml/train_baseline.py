"""Train the baseline anomaly detection model from historical CloudTrail activity."""
import argparse
import logging
import sys
from detection.cloudtrail_ingest import fetch_recent_events
from ml.anomaly_detector import AnomalyDetector, build_actor_history, extract_features

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("cloud_guardian.train")

def train(days=14, scope="global"):
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
    import asyncio
    from db.engine import AsyncSessionLocal, init_db
    from ml.model_store import clear_cache, save_model

    async def _persist():
        await init_db()
        async with AsyncSessionLocal() as db:
            await save_model(db, scope, detector)
            await db.commit()
    asyncio.run(_persist())
    clear_cache()
    print(f"\n✓ Model trained on {len(rows)} samples from {days} day(s) of activity.")
    print(f"✓ Saved to database (scope={scope})")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--days", type=int, default=14)
    parser.add_argument("--scope", type=str, default="global")
    args = parser.parse_args()
    train(days=args.days, scope=args.scope)

if __name__ == "__main__":
    main()
