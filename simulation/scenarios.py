"""Synthetic scenarios for validating detections without changing AWS resources.

These scenarios create normalized CloudTrail-like events in memory. They do not
call AWS APIs, create resources, disable logging, or perform remediation.
"""
from copy import deepcopy

SCENARIOS = [
    {
        "id": "iam-create-access-key",
        "name": "Unexpected IAM access-key creation",
        "description": "Synthetic persistence event; no access key is actually created.",
        "event_name": "CreateAccessKey",
        "expected_detection": True,
        "expected_technique_id": "T1098.001",
        "expected_tactic": "Persistence",
        "risk": "high",
        "raw": {"eventSource": "iam.amazonaws.com", "requestParameters": {"userName": "simulation-user"}},
    },
    {
        "id": "cloudtrail-stop-logging",
        "name": "CloudTrail logging tampering attempt",
        "description": "Synthetic defense-evasion event; CloudTrail is not modified.",
        "event_name": "StopLogging",
        "expected_detection": True,
        "expected_technique_id": "T1562.008",
        "expected_tactic": "Defense Evasion",
        "risk": "critical",
        "raw": {"eventSource": "cloudtrail.amazonaws.com", "requestParameters": {"name": "simulation-trail"}},
    },
    {
        "id": "s3-public-acl",
        "name": "S3 public ACL change attempt",
        "description": "Synthetic exposure event; no bucket ACL or policy is changed.",
        "event_name": "PutBucketAcl",
        "expected_detection": True,
        "expected_technique_id": "T1537",
        "expected_tactic": "Exfiltration",
        "risk": "high",
        "raw": {"eventSource": "s3.amazonaws.com", "requestParameters": {"AccessControlPolicy": "AllUsers public-read"}},
    },
    {
        "id": "console-login-failure",
        "name": "Failed console login",
        "description": "Synthetic failed login; no authentication attempt is sent to AWS.",
        "event_name": "ConsoleLogin",
        "expected_detection": True,
        "expected_technique_id": "T1078",
        "expected_tactic": "Initial Access",
        "risk": "medium",
        "raw": {"eventSource": "signin.amazonaws.com", "responseElements": {"ConsoleLogin": "Failure"},
                "additionalEventData": {"MFAUsed": "No"}},
    },
    {
        "id": "routine-instance-discovery",
        "name": "Routine EC2 inventory activity",
        "description": "Benign control event to measure false-positive behavior.",
        "event_name": "DescribeInstances",
        "expected_detection": False,
        "expected_technique_id": None,
        "expected_tactic": None,
        "risk": "benign",
        "raw": {"eventSource": "ec2.amazonaws.com", "requestParameters": {}},
    },
    {
        "id": "unmapped-privilege-escalation-probe",
        "name": "Unmapped privilege-escalation probe",
        "description": "Synthetic suspicious event intentionally outside the current mapping set to expose coverage gaps.",
        "event_name": "CreatePolicyVersion",
        "expected_detection": True,
        "expected_technique_id": "T1098.003",
        "expected_tactic": "Privilege Escalation",
        "risk": "high",
        "raw": {"eventSource": "iam.amazonaws.com", "requestParameters": {"setAsDefault": True}},
    },
]


def list_scenarios():
    """Return public scenario metadata without mutable internal dictionaries."""
    return [
        {k: deepcopy(v) for k, v in scenario.items() if k != "raw"}
        for scenario in SCENARIOS
    ]
