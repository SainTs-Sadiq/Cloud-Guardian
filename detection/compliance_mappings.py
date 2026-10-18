"""
Compliance framework mappings — maps each check's event_name to the
relevant CIS AWS Foundations Benchmark and AWS Foundational Security
Best Practices (FSBP) control IDs.

IMPORTANT CAVEAT: CIS AWS Foundations Benchmark control numbering has
shifted across versions (v1.2 -> v1.4 -> v1.5 -> v3.0). The IDs below
target the widely-used v1.4/v1.5 numbering scheme. Before using this for
an actual compliance attestation, validate the mapping against whichever
benchmark version your auditor expects — treat this as a strong starting
point, not a certified crosswalk.
"""

COMPLIANCE_MAP: dict[str, list[str]] = {
    # S3
    "S3BucketPublic": ["CIS-AWS 2.1.4", "AWS-FSBP S3.1", "AWS-FSBP S3.8"],
    "S3BucketUnencrypted": ["AWS-FSBP S3.4"],

    # IAM
    "RootAccountAccessKeysPresent": ["CIS-AWS 1.4"],
    "IAMUserNoMFA": ["CIS-AWS 1.19", "AWS-FSBP IAM.5"],
    "IAMUserAdminPolicyAttached": ["CIS-AWS 1.16", "AWS-FSBP IAM.1"],
    "IAMAccessKeyStale": ["CIS-AWS 1.12", "AWS-FSBP IAM.3"],

    # EC2 / networking
    "SecurityGroupSSHOpen": ["CIS-AWS 5.2", "AWS-FSBP EC2.13"],
    "SecurityGroupRDPOpen": ["CIS-AWS 5.3", "AWS-FSBP EC2.13"],
    "SecurityGroupAllPortsOpen": ["AWS-FSBP EC2.19"],
    "EBSVolumeUnencrypted": ["AWS-FSBP EC2.7"],

    # RDS
    "RDSInstancePublic": ["AWS-FSBP RDS.2"],
    "RDSInstanceUnencrypted": ["AWS-FSBP RDS.3"],

    # Secrets Manager
    "SecretRotationDisabled": ["AWS-FSBP SecretsManager.1"],

    # Account-level logging / posture tooling
    "CloudTrailDisabled": ["CIS-AWS 3.1", "AWS-FSBP CloudTrail.1"],
    "GuardDutyDisabled": ["AWS-FSBP GuardDuty.1"],
    "SecurityHubDisabled": ["AWS-FSBP SecurityHub.1"],
    "AWSConfigDisabled": ["CIS-AWS 3.5", "AWS-FSBP Config.1"],

    # Lambda
    "LambdaFunctionURLPublic": ["AWS-FSBP Lambda.1"],
    "LambdaFunctionPolicyPublic": ["AWS-FSBP Lambda.1"],
    "LambdaDeprecatedRuntime": ["AWS-FSBP Lambda.2"],

    # DynamoDB — lower confidence on exact control numbering here; see caveat above.
    "DynamoDBPITRDisabled": ["AWS-FSBP DynamoDB.2"],
    "DynamoDBDeletionProtectionDisabled": [],  # newer feature, no established control ID yet

    # ELB — no confident control ID for these two; left unmapped rather than guessed.
    "ELBNoHTTPSListener": [],
    "ELBAccessLogsDisabled": ["AWS-FSBP ELB.5"],

    # WAF — cross-service checks without an established single control ID.
    "ALBWithoutWAF": [],
    "WAFWebACLNoRules": [],
}


def compliance_for(event_name: str) -> list[str]:
    """Return the compliance control IDs mapped to a given check/event name, or [] if none."""
    return list(COMPLIANCE_MAP.get(event_name, []))
