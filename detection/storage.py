import json
import logging
from datetime import datetime, timezone
from pathlib import Path
import boto3
from botocore.exceptions import ClientError
from config.settings import AWS, STORAGE
from detection.rule_engine import DetectedAlert

logger = logging.getLogger("cloud_guardian.storage")

class AlertStore:
    def save(self, alert): raise NotImplementedError
    def update_status(self, event_id, status, remediation_action=None): raise NotImplementedError
    def get_recent(self, limit=50): raise NotImplementedError
    def get_by_id(self, event_id): raise NotImplementedError

class LocalJSONLStore(AlertStore):
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists(): self.path.touch()

    def save(self, alert):
        record = alert.to_dict()
        record.update({"status": "detected", "remediation_action": None, "stored_at": datetime.now(timezone.utc).isoformat()})
        with open(self.path, "a") as f:
            f.write(json.dumps(record) + "\n")

    def update_status(self, event_id, status, remediation_action=None):
        records = self._read_all()
        updated = False
        for r in records:
            if r["event_id"] == event_id:
                r["status"] = status
                if remediation_action: r["remediation_action"] = remediation_action
                r["updated_at"] = datetime.now(timezone.utc).isoformat()
                updated = True
        if updated:
            with open(self.path, "w") as f:
                for r in records: f.write(json.dumps(r) + "\n")
        else:
            logger.warning(f"event_id {event_id} not found")

    def get_recent(self, limit=50):
        records = self._read_all()
        records.sort(key=lambda r: r.get("stored_at", ""), reverse=True)
        return records[:limit]

    def get_by_id(self, event_id):
        for r in self._read_all():
            if r["event_id"] == event_id: return r
        return None

    def _read_all(self):
        records = []
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try: records.append(json.loads(line))
                    except json.JSONDecodeError: continue
        return records

class DynamoDBStore(AlertStore):
    def __init__(self, table_name, region=None):
        kwargs = {}
        if AWS.profile: kwargs["profile_name"] = AWS.profile
        self.table = boto3.Session(**kwargs).resource("dynamodb", region_name=region or AWS.region).Table(table_name)

    def save(self, alert):
        record = alert.to_dict()
        record.update({"status": "detected", "remediation_action": "none", "stored_at": datetime.now(timezone.utc).isoformat()})
        try: self.table.put_item(Item=record)
        except ClientError as e:
            logger.error(f"DynamoDB write failed: {e}"); raise

    def update_status(self, event_id, status, remediation_action=None):
        expr = "SET #s = :status, updated_at = :ts"
        vals = {":status": status, ":ts": datetime.now(timezone.utc).isoformat()}
        names = {"#s": "status"}
        if remediation_action:
            expr += ", remediation_action = :a"
            vals[":a"] = remediation_action
        try: self.table.update_item(Key={"event_id": event_id}, UpdateExpression=expr, ExpressionAttributeValues=vals, ExpressionAttributeNames=names)
        except ClientError as e:
            logger.error(f"DynamoDB update failed: {e}"); raise

    def get_recent(self, limit=50):
        try:
            items = self.table.scan(Limit=limit).get("Items", [])
            items.sort(key=lambda r: r.get("stored_at", ""), reverse=True)
            return items
        except ClientError as e:
            logger.error(f"DynamoDB scan failed: {e}"); return []

    def get_by_id(self, event_id):
        try: return self.table.get_item(Key={"event_id": event_id}).get("Item")
        except ClientError as e:
            logger.error(f"DynamoDB get failed: {e}"); return None

def get_store():
    return LocalJSONLStore(STORAGE.local_store_path) if STORAGE.use_local_store else DynamoDBStore(STORAGE.events_table)
