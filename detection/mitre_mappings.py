from dataclasses import dataclass
from enum import Enum

class Tactic(str, Enum):
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"

class RiskTier(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass(frozen=True)
class TechniqueMapping:
    technique_id: str
    technique_name: str
    tactic: Tactic
    severity_base: int
    risk_tier: RiskTier
    description: str

EVENT_TECHNIQUE_MAP = {
    "ConsoleLogin": TechniqueMapping("T1078","Valid Accounts",Tactic.INITIAL_ACCESS,30,RiskTier.MEDIUM,"Console login - check for anomalous location/time/MFA status"),
    "AssumeRole": TechniqueMapping("T1078.004","Valid Accounts: Cloud Accounts",Tactic.INITIAL_ACCESS,20,RiskTier.LOW,"Role assumption - watch for unusual role chains"),
    "GetSessionToken": TechniqueMapping("T1550.001","Use Alternate Auth Material",Tactic.DEFENSE_EVASION,15,RiskTier.LOW,"Temporary credential issuance"),
    "RunInstances": TechniqueMapping("T1496","Resource Hijacking",Tactic.IMPACT,25,RiskTier.MEDIUM,"EC2 launch - check unusual instance types/regions (crypto-mining)"),
    "InvokeFunction": TechniqueMapping("T1648","Serverless Execution",Tactic.EXECUTION,20,RiskTier.LOW,"Lambda invocation"),
    "CreateFunction20150331": TechniqueMapping("T1648","Serverless Execution",Tactic.EXECUTION,35,RiskTier.MEDIUM,"New Lambda function created - potential backdoor"),
    "CreateUser": TechniqueMapping("T1136.003","Create Account: Cloud Account",Tactic.PERSISTENCE,40,RiskTier.HIGH,"New IAM user created - potential persistence"),
    "CreateAccessKey": TechniqueMapping("T1098.001","Account Manipulation: Additional Cloud Credentials",Tactic.PERSISTENCE,45,RiskTier.HIGH,"New access key created - common persistence technique"),
    "CreateLoginProfile": TechniqueMapping("T1098.001","Account Manipulation: Additional Cloud Credentials",Tactic.PERSISTENCE,45,RiskTier.HIGH,"Console password set for IAM user"),
    "PutRolePolicy": TechniqueMapping("T1098.003","Account Manipulation: Additional Cloud Roles",Tactic.PERSISTENCE,50,RiskTier.HIGH,"Inline policy attached to role - potential privilege backdoor"),
    "UpdateAssumeRolePolicy": TechniqueMapping("T1098.003","Account Manipulation: Additional Cloud Roles",Tactic.PERSISTENCE,55,RiskTier.HIGH,"Trust policy modified - could allow external account assumption"),
    "AttachUserPolicy": TechniqueMapping("T1098.003","Account Manipulation: Additional Cloud Roles",Tactic.PRIVILEGE_ESCALATION,50,RiskTier.HIGH,"Managed policy attached to user - check for priv escalation"),
    "AttachRolePolicy": TechniqueMapping("T1098.003","Account Manipulation: Additional Cloud Roles",Tactic.PRIVILEGE_ESCALATION,50,RiskTier.HIGH,"Managed policy attached to role - check for priv escalation"),
    "PutUserPolicy": TechniqueMapping("T1098.003","Account Manipulation: Additional Cloud Roles",Tactic.PRIVILEGE_ESCALATION,50,RiskTier.HIGH,"Inline policy attached to user - direct privilege grant"),
    # T1562.008 was revoked by MITRE and replaced by T1685.002 (Disable Cloud Logs)
    "StopLogging": TechniqueMapping("T1685.002","Disable Cloud Logs",Tactic.DEFENSE_EVASION,80,RiskTier.CRITICAL,"CloudTrail logging stopped - classic attacker move"),
    "DeleteTrail": TechniqueMapping("T1685.002","Disable Cloud Logs",Tactic.DEFENSE_EVASION,85,RiskTier.CRITICAL,"CloudTrail trail deleted - destruction of audit evidence"),
    "DeleteFlowLogs": TechniqueMapping("T1685.002","Disable Cloud Logs",Tactic.DEFENSE_EVASION,70,RiskTier.CRITICAL,"VPC Flow Logs deleted"),
    # T1562.001 was revoked and replaced by T1685 (Disable or Modify Tools)
    "UpdateDetector": TechniqueMapping("T1685","Disable or Modify Tools",Tactic.DEFENSE_EVASION,75,RiskTier.CRITICAL,"GuardDuty detector modified"),
    "DeleteDetector": TechniqueMapping("T1685","Disable or Modify Tools",Tactic.DEFENSE_EVASION,85,RiskTier.CRITICAL,"GuardDuty detector deleted"),
    "GetSecretValue": TechniqueMapping("T1552.001","Unsecured Credentials: Credentials in Files",Tactic.CREDENTIAL_ACCESS,35,RiskTier.MEDIUM,"Secrets Manager secret accessed"),
    "GetParameter": TechniqueMapping("T1552.001","Unsecured Credentials: Credentials in Files",Tactic.CREDENTIAL_ACCESS,20,RiskTier.LOW,"SSM parameter accessed"),
    "GetCallerIdentity": TechniqueMapping("T1078","Valid Accounts",Tactic.DISCOVERY,10,RiskTier.LOW,"Identity check - common first step after credential theft"),
    "DescribeInstances": TechniqueMapping("T1580","Cloud Infrastructure Discovery",Tactic.DISCOVERY,10,RiskTier.LOW,"EC2 enumeration"),
    "ListBuckets": TechniqueMapping("T1580","Cloud Infrastructure Discovery",Tactic.DISCOVERY,15,RiskTier.LOW,"S3 bucket enumeration - reconnaissance"),
    "ListUsers": TechniqueMapping("T1087.004","Account Discovery: Cloud Account",Tactic.DISCOVERY,15,RiskTier.LOW,"IAM user enumeration"),
    "ListRoles": TechniqueMapping("T1087.004","Account Discovery: Cloud Account",Tactic.DISCOVERY,15,RiskTier.LOW,"IAM role enumeration"),
    "UpdateFunctionCode20150331v2": TechniqueMapping("T1578","Modify Cloud Compute Infrastructure",Tactic.LATERAL_MOVEMENT,55,RiskTier.HIGH,"Lambda function code modified - potential code injection"),
    "GetObject": TechniqueMapping("T1530","Data from Cloud Storage",Tactic.COLLECTION,10,RiskTier.LOW,"S3 object read - watch for bulk download patterns"),
    "PutBucketAcl": TechniqueMapping("T1537","Transfer Data to Cloud Account",Tactic.EXFILTRATION,60,RiskTier.HIGH,"S3 bucket ACL changed - could expose data publicly"),
    "PutBucketPolicy": TechniqueMapping("T1537","Transfer Data to Cloud Account",Tactic.EXFILTRATION,60,RiskTier.HIGH,"S3 bucket policy changed - could grant external access"),
    "PutObjectAcl": TechniqueMapping("T1537","Transfer Data to Cloud Account",Tactic.EXFILTRATION,45,RiskTier.MEDIUM,"S3 object ACL changed"),
    "CopySnapshot": TechniqueMapping("T1537","Transfer Data to Cloud Account",Tactic.EXFILTRATION,55,RiskTier.HIGH,"EBS/RDS snapshot copied - check destination account"),
    "ModifySnapshotAttribute": TechniqueMapping("T1537","Transfer Data to Cloud Account",Tactic.EXFILTRATION,65,RiskTier.HIGH,"Snapshot permissions modified - could share to external account"),
    "DeleteBucket": TechniqueMapping("T1485","Data Destruction",Tactic.IMPACT,70,RiskTier.CRITICAL,"S3 bucket deleted"),
    "DeleteDBInstance": TechniqueMapping("T1485","Data Destruction",Tactic.IMPACT,75,RiskTier.CRITICAL,"RDS instance deleted"),
    "TerminateInstances": TechniqueMapping("T1485","Data Destruction",Tactic.IMPACT,50,RiskTier.HIGH,"EC2 instance(s) terminated"),

    # ---- Tier-1 expansion (2026-10-22, validated against MITRE ATT&CK enterprise-attack.json) ----
    # Persistence / credential theft
    "UpdateAccessKey": TechniqueMapping("T1098.001","Account Manipulation: Additional Cloud Credentials",Tactic.PERSISTENCE,40,RiskTier.HIGH,"Access key state changed - possible key re-enable"),
    "PutManagedPolicy": TechniqueMapping("T1098.003","Account Manipulation: Additional Cloud Roles",Tactic.PRIVILEGE_ESCALATION,50,RiskTier.HIGH,"Managed policy created - review permissions scope"),
    "CreateRole": TechniqueMapping("T1136.003","Create Account: Cloud Account",Tactic.PERSISTENCE,35,RiskTier.MEDIUM,"New IAM role created - check trust policy for external accounts"),
    "AddUserToGroup": TechniqueMapping("T1098","Account Manipulation",Tactic.PERSISTENCE,35,RiskTier.MEDIUM,"IAM user added to group - possible privilege grant"),
    "PutGroupPolicy": TechniqueMapping("T1098.003","Account Manipulation: Additional Cloud Roles",Tactic.PRIVILEGE_ESCALATION,45,RiskTier.HIGH,"Inline policy attached to group"),
    # Steal / reuse auth material
    "GetFederationToken": TechniqueMapping("T1552.001","Unsecured Credentials: Credentials in Files",Tactic.CREDENTIAL_ACCESS,40,RiskTier.MEDIUM,"Federated token issued - temporary credential minting"),
    "UpdateSAMLProvider": TechniqueMapping("T1556.009","Modify Authentication Process: SAML-related",Tactic.CREDENTIAL_ACCESS,70,RiskTier.CRITICAL,"SAML provider modified - identity-federation backdoor"),
    "CreateSAMLProvider": TechniqueMapping("T1556.009","Modify Authentication Process: SAML-related",Tactic.CREDENTIAL_ACCESS,65,RiskTier.CRITICAL,"New SAML provider created - possible rogue federation"),
    # Inhibit recovery / impact
    "DeleteDBCluster": TechniqueMapping("T1485","Data Destruction",Tactic.IMPACT,80,RiskTier.CRITICAL,"RDS cluster deleted"),
    "DeleteDBSnapshot": TechniqueMapping("T1490","Inhibit System Recovery",Tactic.DEFENSE_EVASION,75,RiskTier.CRITICAL,"DB snapshot deleted - destroying recovery points"),
    "DeregisterImage": TechniqueMapping("T1490","Inhibit System Recovery",Tactic.DEFENSE_EVASION,60,RiskTier.HIGH,"AMI deregistered - destroying recovery images"),
    "DeleteSnapshot": TechniqueMapping("T1490","Inhibit System Recovery",Tactic.DEFENSE_EVASION,65,RiskTier.HIGH,"EBS snapshot deleted - destroying recovery points"),
    "PutBucketLifecycleConfiguration": TechniqueMapping("T1490","Inhibit System Recovery",Tactic.DEFENSE_EVASION,45,RiskTier.MEDIUM,"Bucket lifecycle rule changed - could expire backups/logs"),
    # Execution / lateral movement
    "SendCommand": TechniqueMapping("T1651","Cloud Application Discovery",Tactic.EXECUTION,45,RiskTier.MEDIUM,"SSM command sent to instances - remote execution channel"),
    "AuthorizeSecurityGroupIngress": TechniqueMapping("T1578.005","Modify Cloud Compute Infrastructure",Tactic.DEFENSE_EVASION,55,RiskTier.HIGH,"Security group ingress opened - possible firewall weakening"),
    "RevokeSecurityGroupIngress": TechniqueMapping("T1578","Modify Cloud Compute Infrastructure",Tactic.DEFENSE_EVASION,25,RiskTier.LOW,"Security group ingress rule removed"),
    "ModifyInstanceAttribute": TechniqueMapping("T1578","Modify Cloud Compute Infrastructure",Tactic.LATERAL_MOVEMENT,40,RiskTier.MEDIUM,"EC2 instance attributes modified - e.g. userData injection"),
    # Exfiltration
    "PutBucketReplication": TechniqueMapping("T1537","Transfer Data to Cloud Account",Tactic.EXFILTRATION,60,RiskTier.HIGH,"Bucket replication configured - possible silent exfil to another account"),
    "CreateTrail": TechniqueMapping("T1685.002","Disable Cloud Logs",Tactic.DEFENSE_EVASION,40,RiskTier.MEDIUM,"New CloudTrail trail - attacker may redirect or duplicate logging"),
    "DeleteLogStream": TechniqueMapping("T1685.002","Disable Cloud Logs",Tactic.DEFENSE_EVASION,60,RiskTier.HIGH,"CloudWatch log stream deleted - log tampering"),
    "PutLogProfile": TechniqueMapping("T1685.002","Disable Cloud Logs",Tactic.DEFENSE_EVASION,50,RiskTier.HIGH,"Log profile modified"),
    "UpdateTrail": TechniqueMapping("T1685.002","Disable Cloud Logs",Tactic.DEFENSE_EVASION,70,RiskTier.CRITICAL,"Trail reconfigured - logging may point to attacker-controlled sink"),
    "PutBucketNotification": TechniqueMapping("T1537","Transfer Data to Cloud Account",Tactic.EXFILTRATION,50,RiskTier.HIGH,"Bucket event notifications changed - possible data-stealing trigger"),
    # Collection
    "HeadObject": TechniqueMapping("T1530","Data from Cloud Storage",Tactic.COLLECTION,5,RiskTier.LOW,"S3 object metadata read"),
}

DANGEROUS_MANAGED_POLICIES = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
}

def get_mapping(event_name):
    return EVENT_TECHNIQUE_MAP.get(event_name)

def mapped_technique_ids():
    """Distinct ATT&CK technique IDs used by EVENT_TECHNIQUE_MAP. Several event names
    can map to one technique (e.g. 60 event rows -> 22 techniques), so this is the
    number that means 'techniques covered'."""
    return sorted({m.technique_id for m in EVENT_TECHNIQUE_MAP.values()})


def all_tactics_summary():
    """Distinct technique IDs per tactic, for every Tactic (zero if uncovered).
    A technique listed under two tactics (e.g. T1078) counts once under each."""
    pairs = {(m.tactic.value, m.technique_id) for m in EVENT_TECHNIQUE_MAP.values()}
    summary = {t.value: 0 for t in Tactic}
    for tactic, _technique in pairs:
        summary[tactic] += 1
    return summary


def uncovered_tactics():
    """Tactics in the Tactic enum that no mapped event uses."""
    return [tactic for tactic, count in all_tactics_summary().items() if count == 0]


# Technique IDs that detectors hard-code OUTSIDE EVENT_TECHNIQUE_MAP (config_scanner,
# guardduty_ingest, playbooks, rule_engine). They are kept as-is so detection output
# does not change. Every entry must carry a reason; validate_single_source() fails on
# any other detector-emitted ID that is unknown to the catalog or revoked, and on any
# entry here that no longer appears in the code (stale).
DETECTOR_ID_EXCEPTIONS = {
    "T1562.008": "not in the vendored catalog. Mapping comments say MITRE revoked it and replaced it with T1685.002. Still emitted by config_scanner.py and guardduty_ingest.py. Changing it changes alert output, so it needs a decision.",
    "T1562.001": "not in the vendored catalog. Mapping comments say it was replaced by T1685. Still emitted by config_scanner.py.",
    "T1562":     "not in the vendored catalog (parent ID). Used as a key in rule_engine._infer_tactic.",
    "T1071":     "not in the vendored catalog. Emitted for GuardDuty Backdoor:EC2 findings (guardduty_ingest.py).",
    "T1561":     "not in the vendored catalog. playbooks.py key for instance termination.",
}


def validate_against_attack_catalog():
    """Cross-check EVENT_TECHNIQUE_MAP against the vendored ATT&CK catalog.
    Returns (unknown_ids, revoked_ids) — empty tuples mean we're in sync."""
    from detection.attack_catalog import ATTACK_CLOUD_INDEX
    unknown, revoked = set(), set()
    for m in EVENT_TECHNIQUE_MAP.values():
        entry = ATTACK_CLOUD_INDEX.get(m.technique_id)
        if entry is None:
            unknown.add(m.technique_id)
        elif entry.revoked:
            revoked.add(m.technique_id)
    return sorted(unknown), sorted(revoked)


def detector_technique_literals():
    """Map technique ID -> sorted list of 'file:line' where detection/*.py hard-codes it.
    Scans source text, so it also sees IDs that are not in EVENT_TECHNIQUE_MAP."""
    import re
    from pathlib import Path
    pattern = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
    found = {}
    root = Path(__file__).resolve().parent
    for path in sorted(root.glob("*.py")):
        if path.name == "attack_catalog.py":
            continue  # the vendored reference list, not detector code
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            for tid in pattern.findall(line):
                found.setdefault(tid, []).append(f"{path.name}:{lineno}")
    return {k: sorted(set(v)) for k, v in found.items()}


def validate_single_source():
    """Full single-source check used by CI and tests. Returns a dict of problems;
    all lists empty means the canonical map, catalog and detectors agree."""
    from detection.attack_catalog import ATTACK_CLOUD_INDEX
    unknown, revoked = validate_against_attack_catalog()
    literals = detector_technique_literals()
    unlisted_unknown, unlisted_revoked = [], []
    for tid in sorted(literals):
        if tid in DETECTOR_ID_EXCEPTIONS:
            continue
        entry = ATTACK_CLOUD_INDEX.get(tid)
        if entry is None:
            unlisted_unknown.append(f"{tid} at {', '.join(literals[tid])}")
        elif entry.revoked:
            unlisted_revoked.append(f"{tid} at {', '.join(literals[tid])}")
    stale = sorted(t for t in DETECTOR_ID_EXCEPTIONS if t not in literals)
    return {
        "unknown_mapped": unknown,
        "revoked_mapped": revoked,
        "unlisted_unknown_detector_ids": unlisted_unknown,
        "unlisted_revoked_detector_ids": unlisted_revoked,
        "stale_exceptions": stale,
    }
