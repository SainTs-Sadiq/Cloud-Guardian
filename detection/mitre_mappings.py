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
    "StopLogging": TechniqueMapping("T1562.008","Impair Defenses: Disable Cloud Logs",Tactic.DEFENSE_EVASION,80,RiskTier.CRITICAL,"CloudTrail logging stopped - classic attacker move"),
    "DeleteTrail": TechniqueMapping("T1562.008","Impair Defenses: Disable Cloud Logs",Tactic.DEFENSE_EVASION,85,RiskTier.CRITICAL,"CloudTrail trail deleted - destruction of audit evidence"),
    "DeleteFlowLogs": TechniqueMapping("T1562.008","Impair Defenses: Disable Cloud Logs",Tactic.DEFENSE_EVASION,70,RiskTier.CRITICAL,"VPC Flow Logs deleted"),
    "UpdateDetector": TechniqueMapping("T1562.001","Impair Defenses: Disable or Modify Tools",Tactic.DEFENSE_EVASION,75,RiskTier.CRITICAL,"GuardDuty detector modified"),
    "DeleteDetector": TechniqueMapping("T1562.001","Impair Defenses: Disable or Modify Tools",Tactic.DEFENSE_EVASION,85,RiskTier.CRITICAL,"GuardDuty detector deleted"),
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
    "TerminateInstances": TechniqueMapping("T1561","Disk Wipe",Tactic.IMPACT,50,RiskTier.HIGH,"EC2 instance(s) terminated"),
}

DANGEROUS_MANAGED_POLICIES = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
}

def get_mapping(event_name):
    return EVENT_TECHNIQUE_MAP.get(event_name)

def all_tactics_summary():
    summary = {t.value: 0 for t in Tactic}
    for m in EVENT_TECHNIQUE_MAP.values():
        summary[m.tactic.value] += 1
    return summary
