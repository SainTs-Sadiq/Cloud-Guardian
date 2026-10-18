import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Iterator
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from config.settings import AWS, DETECTION

logger = logging.getLogger("cloud_guardian.ingest")

class NormalizedEvent(dict):
    pass

def get_cloudtrail_client(region=None):
    kwargs = {}
    if AWS.profile:
        kwargs["profile_name"] = AWS.profile
    return boto3.Session(**kwargs).client("cloudtrail", region_name=region or AWS.region)

def _normalize_cloudtrail_record(record):
    raw = json.loads(record.get("CloudTrailEvent", "{}"))
    ui = raw.get("userIdentity", {})
    return NormalizedEvent({
        "event_id": record.get("EventId"),
        "source": "cloudtrail",
        "event_name": record.get("EventName"),
        "event_time": record.get("EventTime"),
        "actor": {"type": ui.get("type","Unknown"), "principal_id": ui.get("principalId",""), "arn": ui.get("arn",""), "account_id": ui.get("accountId","")},
        "source_ip": raw.get("sourceIPAddress"),
        "region": raw.get("awsRegion", AWS.region),
        "resources": [{"type": r.get("ResourceType"), "name": r.get("ResourceName")} for r in record.get("Resources", [])],
        "raw": raw,
    })

def fetch_recent_events(lookback_minutes=None, region=None, event_names=None):
    lookback = lookback_minutes or DETECTION.lookback_minutes
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(minutes=lookback)
    client = get_cloudtrail_client(region)
    try:
        if event_names:
            for name in event_names:
                yield from _lookup_events(client, start_time, end_time, [{"AttributeKey": "EventName", "AttributeValue": name}])
        else:
            yield from _lookup_events(client, start_time, end_time)
    except NoCredentialsError:
        logger.error("No AWS credentials found.")
        raise
    except ClientError as e:
        logger.error(f"CloudTrail API error: {e}")
        raise

def _lookup_events(client, start_time, end_time, lookup_attributes=None):
    paginator = client.get_paginator("lookup_events")
    kwargs = {"StartTime": start_time, "EndTime": end_time, "MaxResults": DETECTION.max_events_per_page}
    if lookup_attributes:
        kwargs["LookupAttributes"] = lookup_attributes
    for page in paginator.paginate(**kwargs):
        for record in page.get("Events", []):
            try:
                yield _normalize_cloudtrail_record(record)
            except Exception as e:
                logger.warning(f"Failed to normalize event {record.get('EventId')}: {e}")

def check_credentials():
    kwargs = {}
    if AWS.profile:
        kwargs["profile_name"] = AWS.profile
    sts = boto3.Session(**kwargs).client("sts", region_name=AWS.region)
    try:
        identity = sts.get_caller_identity()
        return {"ok": True, "account": identity.get("Account"), "arn": identity.get("Arn"), "user_id": identity.get("UserId")}
    except (NoCredentialsError, ClientError) as e:
        return {"ok": False, "error": str(e)}
