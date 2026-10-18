import logging
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from config.settings import AWS
from detection.cloudtrail_ingest import NormalizedEvent

logger = logging.getLogger("cloud_guardian.guardduty")

GUARDDUTY_MITRE_MAP = {
    "UnauthorizedAccess:IAMUser/ConsoleLogin": ("T1078", "Valid Accounts"),
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration": ("T1552.005", "Cloud Instance Metadata API"),
    "Recon:IAMUser/": ("T1580", "Cloud Infrastructure Discovery"),
    "Persistence:IAMUser/": ("T1098", "Account Manipulation"),
    "PrivilegeEscalation:IAMUser/": ("T1098.003", "Account Manipulation: Additional Cloud Roles"),
    "Stealth:IAMUser/LoggingConfigurationModified": ("T1562.008", "Impair Defenses: Disable Cloud Logs"),
    "Stealth:IAMUser/CloudTrailLoggingDisabled": ("T1562.008", "Impair Defenses: Disable Cloud Logs"),
    "Exfiltration:S3/": ("T1537", "Transfer Data to Cloud Account"),
    "Policy:IAMUser/": ("T1098.003", "Account Manipulation: Additional Cloud Roles"),
    "CryptoCurrency:EC2/": ("T1496", "Resource Hijacking"),
    "Backdoor:EC2/": ("T1071", "Application Layer Protocol"),
}

def _client(region=None):
    kwargs = {}
    if AWS.profile: kwargs["profile_name"] = AWS.profile
    return boto3.Session(**kwargs).client("guardduty", region_name=region or AWS.region)

def _map_finding(finding_type):
    for prefix, mapping in GUARDDUTY_MITRE_MAP.items():
        if finding_type.startswith(prefix): return mapping
    return None

def list_active_detectors(region=None):
    try: return _client(region).list_detectors().get("DetectorIds", [])
    except (NoCredentialsError, ClientError) as e:
        logger.error(f"GuardDuty list_detectors failed: {e}"); return []

def fetch_findings(region=None, severity_threshold=1.0, max_results=50):
    client = _client(region)
    detectors = list_active_detectors(region)
    if not detectors:
        logger.warning(f"No GuardDuty detector found in region {region or AWS.region}.")
        return []
    events = []
    for det in detectors:
        try:
            ids = client.list_findings(DetectorId=det,
                FindingCriteria={"Criterion": {"severity": {"Gte": severity_threshold}}},
                MaxResults=max_results).get("FindingIds", [])
            if not ids: continue
            for f in client.get_findings(DetectorId=det, FindingIds=ids).get("Findings", []):
                events.append(_normalize(f))
        except ClientError as e:
            logger.error(f"GuardDuty fetch failed for detector {det}: {e}")
    return events

def _normalize(finding):
    ftype = finding.get("Type", "")
    resource = finding.get("Resource", {})
    rtype = resource.get("ResourceType", "Unknown")
    actor_arn = ""
    if rtype == "AccessKey": actor_arn = resource.get("AccessKeyDetails", {}).get("UserName", "")
    elif rtype == "Instance": actor_arn = resource.get("InstanceDetails", {}).get("InstanceId", "")
    ts = finding.get("UpdatedAt") or finding.get("CreatedAt")
    try: t = datetime.fromisoformat(ts.replace("Z", "+00:00")) if ts else datetime.now(timezone.utc)
    except: t = datetime.now(timezone.utc)
    return NormalizedEvent({
        "event_id": finding.get("Id"), "source": "guardduty", "event_name": ftype, "event_time": t,
        "actor": {"type": rtype, "principal_id": actor_arn, "arn": actor_arn, "account_id": finding.get("AccountId","")},
        "source_ip": finding.get("Service",{}).get("Action",{}).get("NetworkConnectionAction",{}).get("RemoteIpDetails",{}).get("IpAddressV4"),
        "region": finding.get("Region", AWS.region), "resources": [{"type": rtype, "name": rtype}],
        "raw": finding, "_gd_severity": finding.get("Severity"), "_gd_mitre": _map_finding(ftype),
        "_gd_count": finding.get("Service",{}).get("Count",1),
    })
