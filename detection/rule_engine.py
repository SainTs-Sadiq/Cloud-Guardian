import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from detection.cloudtrail_ingest import NormalizedEvent
from detection.mitre_mappings import DANGEROUS_MANAGED_POLICIES, RiskTier, Tactic, get_mapping

logger = logging.getLogger("cloud_guardian.rules")

@dataclass
class DetectedAlert:
    event_id: str
    source: str
    event_name: str
    event_time: datetime
    technique_id: str
    technique_name: str
    tactic: str
    severity: int
    risk_tier: str
    description: str
    actor_arn: str
    account_id: str
    region: str
    source_ip: str
    modifiers: list = field(default_factory=list)
    raw_event: dict = field(default_factory=dict)
    # Standardized finding fields — populated by config_scanner checks;
    # optional/derived for event-based (cloudtrail/guardduty) alerts.
    service: str | None = None
    resource_id: str | None = None
    title: str | None = None
    recommendation: str | None = None
    compliance: list = field(default_factory=list)

    def to_dict(self):
        return {
            "event_id": self.event_id, "source": self.source, "event_name": self.event_name,
            "event_time": self.event_time.isoformat() if isinstance(self.event_time, datetime) else str(self.event_time),
            "technique_id": self.technique_id, "technique_name": self.technique_name,
            "tactic": self.tactic, "severity": self.severity, "risk_tier": self.risk_tier,
            "description": self.description, "actor_arn": self.actor_arn, "account_id": self.account_id,
            "region": self.region, "source_ip": self.source_ip, "modifiers": self.modifiers,
            "service": self.service, "resource_id": self.resource_id, "title": self.title,
            "recommendation": self.recommendation, "compliance": self.compliance,
        }

def _modifier_root_actor(event):
    if event["actor"].get("type") == "Root":
        return 25, "Root account used (high risk)"
    return 0, None

def _modifier_console_no_mfa(event):
    if event["event_name"] != "ConsoleLogin": return 0, None
    mfa = event.get("raw", {}).get("additionalEventData", {}).get("MFAUsed", "Unknown")
    if mfa == "No": return 20, "Console login without MFA"
    return 0, None

def _modifier_console_failed(event):
    if event["event_name"] != "ConsoleLogin": return 0, None
    if event.get("raw", {}).get("responseElements", {}).get("ConsoleLogin") == "Failure":
        return 15, "Failed console login attempt"
    return 0, None

def _modifier_dangerous_policy(event):
    if event["event_name"] not in ("AttachUserPolicy", "AttachRolePolicy"): return 0, None
    arn = event.get("raw", {}).get("requestParameters", {}).get("policyArn", "")
    if arn in DANGEROUS_MANAGED_POLICIES:
        return 35, f"High-privilege policy attached: {arn.split('/')[-1]}"
    return 0, None

def _modifier_public_s3(event):
    if event["event_name"] not in ("PutBucketAcl", "PutObjectAcl"): return 0, None
    acl = str(event.get("raw", {}).get("requestParameters", {}))
    if any(x in acl for x in ("AllUsers", "public-read", "public-read-write")):
        return 30, "S3 resource set to public access"
    return 0, None

def _modifier_off_hours(event):
    t = event.get("event_time")
    if not isinstance(t, datetime): return 0, None
    if 0 <= t.astimezone(timezone.utc).hour < 5:
        return 10, "Activity during off-hours (00:00-05:00 UTC)"
    return 0, None

def _modifier_unusual_region(event, baseline_regions):
    if event["region"] not in baseline_regions:
        return 15, f"Activity in unusual region: {event['region']}"
    return 0, None

MODIFIERS = [_modifier_root_actor, _modifier_console_no_mfa, _modifier_console_failed,
             _modifier_dangerous_policy, _modifier_public_s3, _modifier_off_hours]

_TIER_ORDER = [RiskTier.LOW.value, RiskTier.MEDIUM.value, RiskTier.HIGH.value, RiskTier.CRITICAL.value]

def _tier_rank(tier):
    try: return _TIER_ORDER.index(tier)
    except ValueError: return 0

def _severity_to_tier(severity):
    if severity >= 80: return RiskTier.CRITICAL.value
    if severity >= 60: return RiskTier.HIGH.value
    if severity >= 35: return RiskTier.MEDIUM.value
    return RiskTier.LOW.value

def _infer_tactic(technique_id):
    m = {"T1078": Tactic.INITIAL_ACCESS, "T1552": Tactic.CREDENTIAL_ACCESS, "T1580": Tactic.DISCOVERY,
         "T1098": Tactic.PERSISTENCE, "T1562": Tactic.DEFENSE_EVASION, "T1537": Tactic.EXFILTRATION,
         "T1496": Tactic.IMPACT, "T1071": Tactic.EXECUTION}
    return m.get(technique_id.split(".")[0], Tactic.DISCOVERY).value

import re


def _humanize(name: str) -> str:
    """'S3BucketPublic' -> 'S3 Bucket Public'; a readable default title from an event_name."""
    return re.sub(r"(?<!^)(?=[A-Z])", " ", name).replace("  ", " ").strip()


def _derive_service_and_resource(event: dict) -> tuple[str | None, str | None]:
    """Best-effort service/resource_id derivation for event-based (cloudtrail/guardduty) alerts."""
    resources = event.get("resources") or []
    resource_id = resources[0].get("name") if resources and resources[0].get("name") else None

    if event.get("source") == "guardduty":
        return "GuardDuty", resource_id

    event_source = event.get("raw", {}).get("eventSource", "")
    service = event_source.replace(".amazonaws.com", "").upper() if event_source else None
    return service, resource_id


def score_event(event, baseline_regions=None, ml_anomaly_score=None):
    mapping = None
    if event["source"] == "guardduty":
        gd_mitre = event.get("_gd_mitre")
        technique_id, technique_name = gd_mitre if gd_mitre else ("T1078", "Valid Accounts")
        tactic = _infer_tactic(technique_id)
        gd_sev = event.get("_gd_severity", 5.0)
        severity = int(min(100, gd_sev * 10))
        risk_tier = _severity_to_tier(severity)
        modifiers = [f"GuardDuty severity: {gd_sev}/10"]
        description = f"GuardDuty finding: {event['event_name']}"
    else:
        mapping = get_mapping(event["event_name"])
        if mapping is None: return None
        technique_id, technique_name = mapping.technique_id, mapping.technique_name
        tactic, severity, risk_tier = mapping.tactic.value, mapping.severity_base, mapping.risk_tier.value
        modifiers, description = [], mapping.description
        for fn in MODIFIERS:
            delta, reason = fn(event)
            if delta:
                severity += delta
                modifiers.append(reason)
        if baseline_regions:
            delta, reason = _modifier_unusual_region(event, baseline_regions)
            if delta:
                severity += delta
                modifiers.append(reason)

    if ml_anomaly_score is not None and ml_anomaly_score > 0.5:
        boost = int((ml_anomaly_score - 0.5) * 60)
        severity += boost
        modifiers.append(f"ML anomaly score: {ml_anomaly_score:.2f}")

    severity = max(0, min(100, severity))
    sev_tier = _severity_to_tier(severity)
    if _tier_rank(sev_tier) > _tier_rank(risk_tier):
        risk_tier = sev_tier

    from detection.compliance_mappings import compliance_for
    service, resource_id = _derive_service_and_resource(event)

    return DetectedAlert(
        event_id=event["event_id"], source=event["source"], event_name=event["event_name"],
        event_time=event["event_time"], technique_id=technique_id, technique_name=technique_name,
        tactic=tactic, severity=severity, risk_tier=risk_tier, description=description,
        actor_arn=event["actor"].get("arn",""), account_id=event["actor"].get("account_id",""),
        region=event["region"], source_ip=event.get("source_ip"), modifiers=modifiers,
        raw_event=event.get("raw", {}),
        service=service, resource_id=resource_id, title=_humanize(event["event_name"]),
        compliance=compliance_for(event["event_name"]),
    )
