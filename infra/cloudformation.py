"""
CloudFormation template generation for the AWS onboarding wizard.

Produces a ready-to-deploy JSON template that creates the
CloudGuardianDetectionRole with the trust policy and read-only detection
policy already filled in — no CloudFormation Parameters, no manual
editing. The customer downloads it, uploads it in their own
CloudFormation console, and copies the RoleArn out of the Stack Outputs
into the onboarding wizard.

We generate JSON (not YAML) so no extra dependency (PyYAML) is needed —
CloudFormation accepts JSON templates natively.
"""
import json
import pathlib
from pathlib import Path

_DETECTION_POLICY_PATH = Path(__file__).parent / "iam_policy_detection_readonly.json"


def _load_detection_policy() -> dict:
    return json.loads(_DETECTION_POLICY_PATH.read_text())


def _load_split_remediation_policies() -> tuple[dict, dict]:
    here = pathlib.Path(__file__).parent
    auto = json.loads((here / "iam_policy_auto_remediation.json").read_text())
    destr = json.loads((here / "iam_policy_destructive_remediation.json").read_text())
    return auto, destr

def generate_onboarding_template(
    cg_account_id: str,
    external_id: str,
    role_name: str = "CloudGuardianDetectionRole",
) -> dict:
    """
    Build the CloudFormation template as a JSON-serializable dict.

    Args:
        cg_account_id: Cloud Guardian's own AWS account ID (the trust
                       policy Principal — the account allowed to assume
                       this role).
        external_id:   Org-specific external ID, required on every
                       AssumeRole call to prevent confused-deputy attacks.
        role_name:     Name of the IAM role to create in the customer's
                       account. Must match what's registered via POST
                       /accounts.
    """
    detection_policy = _load_detection_policy()

    # If CG detection service runs under a specific IAM role, restrict trust
    # to that principal ARN instead of the whole account (any principal in
    # the CG account could otherwise assume customer roles with the ext ID).
    import os as _os
    _exact = _os.environ.get("CG_IAM_ROLE_ARN", "").strip()
    principal_arn_glob = _exact or f"arn:aws:iam::{cg_account_id}:root"
    auto_policy, destructive_policy = _load_split_remediation_policies()

    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": (
            "Cloud Guardian cross-account detection role. Grants read-only "
            "visibility (CloudTrail, GuardDuty, IAM, S3, EC2 metadata) via "
            f"sts:AssumeRole, scoped to external ID {external_id}. "
            "Cloud Guardian never stores long-lived AWS credentials — this "
            "role is assumed for the duration of each scan only."
        ),
        "Resources": {
            "CloudGuardianDetectionRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "Description": "Read-only role assumed by Cloud Guardian to run security scans.",
                    "MaxSessionDuration": 3600,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": f"arn:aws:iam::{cg_account_id}:root"},
                                "Action": "sts:AssumeRole",
                                "Condition": {
                                    "StringEquals": {"sts:ExternalId": external_id},
                                    # Restrict to the exact principal that should assume this
                                    # role, not the whole account root (defense in depth).
                                    "ArnLike": {"aws:PrincipalArn": principal_arn_glob}
                                },
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "CloudGuardianDetectionReadOnly",
                            "PolicyDocument": detection_policy,
                        }
                    ],
                    "Tags": [
                        {"Key": "ManagedBy", "Value": "CloudGuardian"},
                        {"Key": "Purpose", "Value": "SecurityScanning"},
                    ],
                },
            },
            "CloudGuardianAutoRemediationRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"{role_name}AutoRemediation",
                    "Description": "Low-risk auto-remediation role. Cannot perform destructive actions.",
                    "MaxSessionDuration": 3600,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"AWS": f"arn:aws:iam::{cg_account_id}:root"},
                            "Action": "sts:AssumeRole",
                            "Condition": {
                                "StringEquals": {"sts:ExternalId": external_id},
                                "ArnLike": {"aws:PrincipalArn": principal_arn_glob},
                            },
                        }],
                    },
                    "Policies": [{
                        "PolicyName": "CloudGuardianAutoRemediation",
                        "PolicyDocument": auto_policy,
                    }],
                    "Tags": [{"Key": "ManagedBy", "Value": "CloudGuardian"}],
                },
            },
            "CloudGuardianDestructiveRemediationRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"{role_name}DestructiveRemediation",
                    "Description": "Destructive remediation role — only used after explicit human approval per incident.",
                    "MaxSessionDuration": 3600,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"AWS": f"arn:aws:iam::{cg_account_id}:root"},
                            "Action": "sts:AssumeRole",
                            "Condition": {
                                "StringEquals": {"sts:ExternalId": external_id},
                                "ArnLike": {"aws:PrincipalArn": principal_arn_glob},
                            },
                        }],
                    },
                    "Policies": [{
                        "PolicyName": "CloudGuardianDestructiveRemediation",
                        "PolicyDocument": destructive_policy,
                    }],
                    "Tags": [{"Key": "ManagedBy", "Value": "CloudGuardian"}],
                },
            },
        },
        "Outputs": {
            "RoleArn": {
                "Description": "Copy this value into the Cloud Guardian onboarding wizard",
                "Value": {"Fn::GetAtt": ["CloudGuardianDetectionRole", "Arn"]},
            },
            "AutoRemediationRoleArn": {
                "Description": "Low-risk auto-remediation role (used by Celery auto-actions)",
                "Value": {"Fn::GetAtt": ["CloudGuardianAutoRemediationRole", "Arn"]},
            },
            "DestructiveRemediationRoleArn": {
                "Description": "Destructive remediation role (used only after human approval)",
                "Value": {"Fn::GetAtt": ["CloudGuardianDestructiveRemediationRole", "Arn"]},
            },
            "ExternalId": {
                "Description": "External ID used for this role (for reference only)",
                "Value": external_id,
            },
        },
    }
