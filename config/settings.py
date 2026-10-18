import os
from dataclasses import dataclass, field

@dataclass
class AWSConfig:
    region: str = os.environ.get("AWS_REGION", "us-east-1")
    additional_regions: list = field(default_factory=lambda: [r.strip() for r in os.environ.get("AWS_SCAN_REGIONS", "").split(",") if r.strip()])
    profile: str = os.environ.get("AWS_PROFILE")

@dataclass
class DetectionConfig:
    lookback_minutes: int = int(os.environ.get("CG_LOOKBACK_MINUTES", "15"))
    poll_interval_seconds: int = int(os.environ.get("CG_POLL_INTERVAL", "60"))
    alert_threshold: int = int(os.environ.get("CG_ALERT_THRESHOLD", "30"))
    remediation_threshold: int = int(os.environ.get("CG_REMEDIATION_THRESHOLD", "50"))
    max_events_per_page: int = 50
    config_scan_enabled: bool = os.environ.get("CG_CONFIG_SCAN_ENABLED", "true").lower() == "true"

@dataclass
class RemediationConfig:
    enabled: bool = os.environ.get("CG_REMEDIATION_ENABLED", "false").lower() == "true"
    auto_approve_tiers: list = field(default_factory=lambda: ["low"])
    require_approval_tiers: list = field(default_factory=lambda: ["medium", "high", "critical"])
    notification_topic_arn: str = os.environ.get("CG_SNS_TOPIC_ARN")

@dataclass
class StorageConfig:
    events_table: str = os.environ.get("CG_EVENTS_TABLE", "cloud_guardian_events")
    use_local_store: bool = os.environ.get("CG_USE_LOCAL_STORE", "true").lower() == "true"
    local_store_path: str = os.environ.get("CG_LOCAL_STORE_PATH", "./data/events.jsonl")

AWS = AWSConfig()
DETECTION = DetectionConfig()
REMEDIATION = RemediationConfig()
STORAGE = StorageConfig()
