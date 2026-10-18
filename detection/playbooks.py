from dataclasses import dataclass
from enum import Enum
from detection.mitre_mappings import RiskTier
from detection.rule_engine import DetectedAlert

class ActionType(str, Enum):
    REVOKE_SESSION = "revoke_session_token"
    DISABLE_ACCESS_KEY = "disable_access_key"
    DETACH_DANGEROUS_POLICY = "detach_dangerous_policy"
    BLOCK_PUBLIC_S3_ACCESS = "block_public_s3_access"
    QUARANTINE_SECURITY_GROUP = "quarantine_security_group"
    ISOLATE_EC2_INSTANCE = "isolate_ec2_instance"
    TERMINATE_EC2_INSTANCE = "terminate_ec2_instance"
    DISABLE_LAMBDA = "disable_lambda_function"
    NOTIFY_ONLY = "notify_only"
    RESTORE_CLOUDTRAIL_LOGGING = "restore_cloudtrail_logging"

@dataclass(frozen=True)
class Playbook:
    action: ActionType
    action_risk_tier: RiskTier
    description: str
    reversible: bool

PLAYBOOKS = {
    "T1098.001": Playbook(ActionType.DISABLE_ACCESS_KEY, RiskTier.MEDIUM, "Disable the newly created IAM access key (reversible)", True),
    "T1098.003": Playbook(ActionType.DETACH_DANGEROUS_POLICY, RiskTier.HIGH, "Detach the attached IAM policy that granted elevated privileges", True),
    "T1537":     Playbook(ActionType.BLOCK_PUBLIC_S3_ACCESS, RiskTier.LOW, "Apply S3 Block Public Access settings to the affected bucket", True),
    "T1078":     Playbook(ActionType.REVOKE_SESSION, RiskTier.MEDIUM, "Revoke active session credentials for the IAM principal", True),
    "T1496":     Playbook(ActionType.ISOLATE_EC2_INSTANCE, RiskTier.HIGH, "Move instance to isolation security group for forensic capture", True),
    "T1562.008": Playbook(ActionType.RESTORE_CLOUDTRAIL_LOGGING, RiskTier.CRITICAL, "Re-enable CloudTrail logging / GuardDuty detector that was disabled", True),
    "T1578":     Playbook(ActionType.DISABLE_LAMBDA, RiskTier.HIGH, "Set Lambda function concurrency to 0, disabling invocation", True),
    "T1485":     Playbook(ActionType.NOTIFY_ONLY, RiskTier.CRITICAL, "Resource deletion detected - notify security team immediately", False),
    "T1561":     Playbook(ActionType.NOTIFY_ONLY, RiskTier.CRITICAL, "Instance termination detected - notify security team immediately", False),
}

def get_playbook(alert):
    if alert.technique_id in PLAYBOOKS:
        return PLAYBOOKS[alert.technique_id]
    base = alert.technique_id.split(".")[0]
    return PLAYBOOKS.get(base)
