import hashlib
import json
from detection.rule_engine import DetectedAlert


TIME_BUCKETS = {
    range(0, 6):   "off_hours_night",
    range(6, 9):   "early_morning",
    range(9, 18):  "business_hours",
    range(18, 22): "evening",
    range(22, 24): "off_hours_late",
}


def _time_bucket(hour: int) -> str:
    for r, label in TIME_BUCKETS.items():
        if hour in r:
            return label
    return "unknown"


def _service_from_event(event_name: str) -> str:
    e = event_name.lower()
    if any(x in e for x in ("bucket", "object", "s3")):      return "S3"
    if any(x in e for x in ("instance", "security", "ec2")): return "EC2"
    if any(x in e for x in ("function", "lambda")):           return "Lambda"
    if any(x in e for x in ("secret", "parameter")):          return "Secrets"
    if any(x in e for x in ("detector", "finding")):          return "GuardDuty"
    if any(x in e for x in ("trail", "logging")):             return "CloudTrail"
    if any(x in e for x in ("user", "role", "policy",
                              "key", "access", "iam")):        return "IAM"
    return "Other"


def _actor_type(actor_arn: str) -> str:
    if "root" in actor_arn.lower():        return "root"
    if ":user/"          in actor_arn:     return "iam_user"
    if ":assumed-role/"  in actor_arn:     return "assumed_role"
    return "service"


def _privilege_level(modifiers: list[str], actor_arn: str) -> str:
    """
    Infer privilege level from alert modifiers and actor ARN.
    high   → root account, AdministratorAccess, IAMFullAccess attached
    medium → PowerUserAccess, or any dangerous policy modifier
    low    → standard user/role, no escalation signals
    """
    modifier_text = " ".join(modifiers).lower()
    if "root account" in modifier_text:
        return "high"
    if any(p in modifier_text for p in ("administratoraccess", "iamfullaccess")):
        return "high"
    if any(p in modifier_text for p in ("poweruseraccess", "high-privilege")):
        return "medium"
    if "root" in actor_arn.lower():
        return "high"
    return "low"


def _mfa_status(modifiers: list[str]) -> str:
    """
    Extract MFA status from alert modifiers.
    Returns: 'no_mfa' | 'mfa_present' | 'unknown'
    """
    modifier_text = " ".join(modifiers).lower()
    if "without mfa" in modifier_text or "no mfa" in modifier_text:
        return "no_mfa"
    if "mfa" in modifier_text:
        return "mfa_present"
    return "unknown"


def extract_features(alert: DetectedAlert) -> dict:
    """
    Extract the fixed feature set that defines a unique attack fingerprint.

    Two alerts are considered 'the same pattern' if all features match.
    Features deliberately exclude account-specific values (actor ARN,
    IP address) so the pattern generalises across accounts and analysts.

    Features:
      technique_id    MITRE technique (e.g. T1078)
      event_name      CloudTrail event (e.g. ConsoleLogin)
      tactic          MITRE tactic (e.g. Initial Access)
      risk_tier       critical / high / medium / low
      service         AWS service inferred from event name
      actor_type      root / iam_user / assumed_role / service
      time_bucket     business_hours / off_hours_night / etc.
      source          cloudtrail / guardduty
      privilege_level high / medium / low  (from modifiers)
      mfa_status      no_mfa / mfa_present / unknown  (from modifiers)
    """
    from datetime import timezone
    event_time = alert.event_time
    if hasattr(event_time, "astimezone"):
        hour = event_time.astimezone(timezone.utc).hour
    else:
        hour = 0

    modifiers = alert.modifiers or []

    return {
        "technique_id":    alert.technique_id,
        "event_name":      alert.event_name,
        "tactic":          alert.tactic,
        "risk_tier":       alert.risk_tier,
        "service":         _service_from_event(alert.event_name),
        "actor_type":      _actor_type(alert.actor_arn),
        "time_bucket":     _time_bucket(hour),
        "source":          alert.source,
        "privilege_level": _privilege_level(modifiers, alert.actor_arn),
        "mfa_status":      _mfa_status(modifiers),
    }


def compute_fingerprint(features: dict) -> str:
    canonical = json.dumps(features, sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def describe_fingerprint(features: dict) -> str:
    """Human-readable description shown in the dashboard and review queue."""
    parts = [
        f"{features.get('technique_id')} ({features.get('tactic')})",
        f"via {features.get('event_name')}",
        f"on {features.get('service')}",
        f"by {features.get('actor_type').replace('_', ' ')}",
    ]
    if features.get("privilege_level") != "low":
        parts.append(f"{features.get('privilege_level')} privilege")
    if features.get("mfa_status") == "no_mfa":
        parts.append("without MFA")
    parts.append(f"during {features.get('time_bucket', '').replace('_', ' ')}")
    return " · ".join(parts)


def build_fingerprint(alert: DetectedAlert) -> tuple[str, str, dict]:
    features = extract_features(alert)
    fp_hash  = compute_fingerprint(features)
    desc     = describe_fingerprint(features)
    return fp_hash, desc, features
