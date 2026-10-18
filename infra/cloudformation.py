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
from pathlib import Path

_DETECTION_POLICY_PATH = Path(__file__).parent / "iam_policy_detection_readonly.json"


def _load_detection_policy() -> dict:
    return json.loads(_DETECTION_POLICY_PATH.read_text())


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
                                    "StringEquals": {"sts:ExternalId": external_id}
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
            }
        },
        "Outputs": {
            "RoleArn": {
                "Description": "Copy this value into the Cloud Guardian onboarding wizard",
                "Value": {"Fn::GetAtt": ["CloudGuardianDetectionRole", "Arn"]},
            },
            "ExternalId": {
                "Description": "External ID used for this role (for reference only)",
                "Value": external_id,
            },
        },
    }
