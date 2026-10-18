"""
Cross-account AWS session management.

Each customer registers an IAM role ARN in their AWSAccount record.
When we scan their account, we call sts:AssumeRole to get temporary
credentials — no long-lived keys ever stored.

Security hardening:
  - External ID prevents confused deputy attacks
    (https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html)
  - Sessions are cached per (role_arn, session_name) for up to 50 min
    to avoid hitting STS rate limits on frequent scans
  - Session name encodes the org + account for CloudTrail auditability
"""
import hashlib
import logging
import os
import time
from dataclasses import dataclass
from threading import Lock
from typing import Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

logger = logging.getLogger("cloud_guardian.aws_session")


CG_AWS_ACCOUNT_ID = os.environ.get("CG_AWS_ACCOUNT_ID", "")


@dataclass
class TemporaryCredentials:
    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration: float
    role_arn: str
    aws_account_id: str
    region: str

    def is_expired(self, buffer_seconds: int = 300) -> bool:
        """Return True if credentials expire within buffer_seconds."""
        return time.time() >= (self.expiration - buffer_seconds)

    def to_boto_kwargs(self) -> dict:
        return {
            "aws_access_key_id": self.access_key_id,
            "aws_secret_access_key": self.secret_access_key,
            "aws_session_token": self.session_token,
        }


class SessionCache:
    """
    Thread-safe in-process cache of assumed-role sessions.
    Keyed by (role_arn, region) — refreshed automatically when near expiry.
    """
    def __init__(self):
        self._cache: dict[str, TemporaryCredentials] = {}
        self._lock = Lock()

    def get(self, key: str) -> Optional[TemporaryCredentials]:
        with self._lock:
            creds = self._cache.get(key)
            if creds and not creds.is_expired():
                return creds
            return None

    def set(self, key: str, creds: TemporaryCredentials) -> None:
        with self._lock:
            self._cache[key] = creds

    def invalidate(self, key: str) -> None:
        with self._lock:
            self._cache.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


_session_cache = SessionCache()


def get_session_for_account(
    role_arn: str,
    external_id: Optional[str],
    region: str,
    org_id: str,
    aws_account_id: str,
) -> boto3.Session:
    """
    Return a boto3 Session authenticated as the customer's IAM role.

    Uses cached credentials when available (refreshes within 5 min of expiry).
    Falls back to the default credential chain if role_arn is empty
    (single-account mode for development).

    Args:
        role_arn:       Full ARN of the role to assume, e.g.
                        "arn:aws:iam::123456789012:role/CloudGuardianDetectionRole"
        external_id:    Optional external ID set in the role trust policy
        region:         AWS region for the returned clients
        org_id:         Cloud Guardian org ID — used in the session name for auditability
        aws_account_id: Customer's AWS account ID
    """
    if not role_arn:

        logger.debug("No role ARN — using default credential chain")
        return boto3.Session(region_name=region)

    cache_key = f"{role_arn}:{region}"
    cached = _session_cache.get(cache_key)
    if cached:
        return boto3.Session(region_name=region, **cached.to_boto_kwargs())


    org_short = org_id[:8].replace("-", "")
    session_name = f"cg-{org_short}-{aws_account_id}"[:64]

    sts = boto3.client("sts")
    assume_kwargs = {
        "RoleArn": role_arn,
        "RoleSessionName": session_name,
        "DurationSeconds": 3600,
    }
    if external_id:
        assume_kwargs["ExternalId"] = external_id

    try:
        response = sts.assume_role(**assume_kwargs)
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "AccessDenied":
            raise PermissionError(
                f"Could not assume role {role_arn}. "
                "Ensure the role trust policy allows sts:AssumeRole from Cloud Guardian's "
                f"AWS account ({CG_AWS_ACCOUNT_ID or 'CG_AWS_ACCOUNT_ID not set'}) "
                "and the external ID matches."
            ) from e
        raise
    except NoCredentialsError:
        raise PermissionError(
            "Cloud Guardian has no AWS credentials configured. "
            "Set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY or attach an IAM role to the host."
        )

    creds_data = response["Credentials"]
    creds = TemporaryCredentials(
        access_key_id=creds_data["AccessKeyId"],
        secret_access_key=creds_data["SecretAccessKey"],
        session_token=creds_data["SessionToken"],
        expiration=creds_data["Expiration"].timestamp(),
        role_arn=role_arn,
        aws_account_id=aws_account_id,
        region=region,
    )
    _session_cache.set(cache_key, creds)

    logger.info(f"Assumed role {role_arn} for account {aws_account_id} (session: {session_name})")
    return boto3.Session(region_name=region, **creds.to_boto_kwargs())


def validate_role_arn(role_arn: str) -> bool:
    """Basic ARN format validation before attempting assume-role."""
    if not role_arn.startswith("arn:aws:iam::"):
        return False
    parts = role_arn.split(":")
    return len(parts) == 6 and parts[5].startswith("role/")


def generate_external_id(org_id: str) -> str:
    """
    Generate a stable external ID for an org's role trust policy.
    Deterministic so it can be shown to the customer once and always matches.
    """
    return f"cg-{hashlib.sha256(org_id.encode()).hexdigest()[:16]}"
