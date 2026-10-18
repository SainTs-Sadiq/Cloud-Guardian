"""
Configuration scanner — point-in-time misconfiguration checks (CSPM-style).

Unlike cloudtrail_ingest/guardduty_ingest (which look at *events that already
happened*), these checks look at *current resource state*: is this bucket
public, is this security group open to the world, does this user have MFA,
etc. This is Phase 2/3 of the CSPM roadmap — "what's wrong right now",
complementing the event-based detections in rule_engine.py.

Each check function takes an already-authenticated boto3 Session (the
per-account assumed-role session from core.aws_session) and returns a list
of DetectedAlert — the same dataclass used by the event pipeline, so these
findings flow through the exact same persistence, dedup, alerting, and
remediation-approval path with no changes needed anywhere else.

Every finding carries the standardized fields (service, resource_id, title,
recommendation, compliance) so all findings — regardless of which scanner
produced them — share one consistent shape at the API layer.

Findings use a stable, deterministic event_id (derived from the resource
identifier + check type) so re-running a scan doesn't create duplicate
incidents for a misconfiguration that's still present — see
IncidentRepository.get_by_event_id.

All checks are individually wrapped so one failing/unauthorized API call
(e.g. a customer's role is missing a newly-added permission) degrades to a
logged warning rather than aborting the whole scan.
"""
import json
import logging
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from detection.mitre_mappings import Tactic, RiskTier, DANGEROUS_MANAGED_POLICIES
from detection.rule_engine import DetectedAlert
from detection.compliance_mappings import compliance_for

logger = logging.getLogger("cloud_guardian.config_scanner")


def _error_code(e: ClientError) -> str:
    return e.response.get("Error", {}).get("Code", "")


def _bucket_policy_is_public(s3, bucket_name: str) -> bool:
    """
    True if the bucket policy grants access to everyone ("*" principal,
    no further condition narrowing it down).

    We check the policy document directly rather than relying solely on
    GetBucketPolicyStatus's IsPublic flag, since that call's public-ness
    heuristic doesn't always agree across providers/emulators and we'd
    rather over-detect a real risk than miss one.
    """
    try:
        status = s3.get_bucket_policy_status(Bucket=bucket_name)
        if status.get("PolicyStatus", {}).get("IsPublic"):
            return True
    except ClientError as e:
        if _error_code(e) not in ("NoSuchBucketPolicy", "NoSuchBucket"):
            logger.warning(f"GetBucketPolicyStatus failed for {bucket_name}: {e}")

    try:
        raw = s3.get_bucket_policy(Bucket=bucket_name)["Policy"]
        policy = json.loads(raw)
    except ClientError as e:
        if _error_code(e) not in ("NoSuchBucketPolicy", "NoSuchBucket"):
            logger.warning(f"GetBucketPolicy failed for {bucket_name}: {e}")
        return False
    except (ValueError, KeyError):
        return False

    for stmt in policy.get("Statement", []):
        if stmt.get("Effect") != "Allow" or "Condition" in stmt:
            continue
        principal = stmt.get("Principal")
        if principal == "*":
            return True
        if isinstance(principal, dict):
            aws_principal = principal.get("AWS")
            if aws_principal == "*" or (isinstance(aws_principal, list) and "*" in aws_principal):
                return True
    return False


def _alert(event_id, event_name, technique_id, technique_name, tactic, severity,
           risk_tier, description, account_id, region, service, resource_id,
           recommendation, title=None, modifiers=None):
    return DetectedAlert(
        event_id=event_id,
        source="config_scan",
        event_name=event_name,
        event_time=datetime.now(timezone.utc),
        technique_id=technique_id,
        technique_name=technique_name,
        tactic=tactic.value if isinstance(tactic, Tactic) else tactic,
        severity=max(0, min(100, severity)),
        risk_tier=risk_tier.value if isinstance(risk_tier, RiskTier) else risk_tier,
        description=description,
        actor_arn="n/a (configuration check, not an actor event)",
        account_id=account_id,
        region=region,
        source_ip=None,
        modifiers=modifiers or [],
        raw_event={},
        service=service,
        resource_id=resource_id,
        title=title or event_name,
        recommendation=recommendation,
        compliance=compliance_for(event_name),
    )


# ─── S3 ──────────────────────────────────────────────────────────────────

def scan_s3(session, account_id) -> list[DetectedAlert]:
    """Public buckets and buckets without default encryption."""
    findings = []
    s3 = session.client("s3")

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        logger.warning(f"S3 ListBuckets failed for account {account_id}: {e}")
        return findings

    for b in buckets:
        name = b["Name"]

        # --- Public access ---
        block_all = False
        try:
            pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            block_all = all(pab.get(k, False) for k in (
                "BlockPublicAcls", "IgnorePublicAcls",
                "BlockPublicPolicy", "RestrictPublicBuckets",
            ))
        except ClientError as e:
            if _error_code(e) != "NoSuchPublicAccessBlockConfiguration":
                logger.warning(f"GetPublicAccessBlock failed for {name}: {e}")

        if not block_all:
            reasons = []
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl.get("Grants", []):
                    uri = grant.get("Grantee", {}).get("URI", "")
                    if uri.endswith("/AllUsers") or uri.endswith("/AuthenticatedUsers"):
                        who = "the public" if "AllUsers" in uri else "any authenticated AWS user"
                        reasons.append(f"bucket ACL grants {grant['Permission']} to {who}")
            except ClientError as e:
                logger.warning(f"GetBucketAcl failed for {name}: {e}")

            if _bucket_policy_is_public(s3, name):
                reasons.append("bucket policy grants public access")

            if reasons:
                findings.append(_alert(
                    event_id=f"config-s3-public-{account_id}-{name}",
                    event_name="S3BucketPublic",
                    technique_id="T1530", technique_name="Data from Cloud Storage Object",
                    tactic=Tactic.COLLECTION, severity=75, risk_tier=RiskTier.HIGH,
                    description=f"S3 bucket '{name}' is publicly accessible — {'; '.join(reasons)}.",
                    account_id=account_id, region="global", modifiers=reasons,
                    service="S3", resource_id=name, title="Public S3 bucket",
                    recommendation="Enable S3 Block Public Access on the bucket (or account-wide), "
                                   "and remove any public grants from the bucket ACL or policy.",
                ))

        # --- Default encryption ---
        try:
            s3.get_bucket_encryption(Bucket=name)
        except ClientError as e:
            if _error_code(e) == "ServerSideEncryptionConfigurationNotFoundError":
                findings.append(_alert(
                    event_id=f"config-s3-unencrypted-{account_id}-{name}",
                    event_name="S3BucketUnencrypted",
                    technique_id="T1530", technique_name="Data from Cloud Storage Object",
                    tactic=Tactic.COLLECTION, severity=35, risk_tier=RiskTier.MEDIUM,
                    description=f"S3 bucket '{name}' has no default (server-side) encryption configured.",
                    account_id=account_id, region="global",
                    service="S3", resource_id=name, title="S3 bucket without default encryption",
                    recommendation="Enable default server-side encryption (SSE-S3 or SSE-KMS) on the bucket.",
                ))
            else:
                logger.warning(f"GetBucketEncryption failed for {name}: {e}")

    return findings


# ─── IAM ─────────────────────────────────────────────────────────────────

def scan_iam(session, account_id) -> list[DetectedAlert]:
    """Users without MFA, directly-attached admin policies, root access keys, stale keys."""
    findings = []
    iam = session.client("iam")

    try:
        summary = iam.get_account_summary().get("SummaryMap", {})
        if summary.get("AccountAccessKeysPresent", 0) == 1:
            findings.append(_alert(
                event_id=f"config-iam-root-keys-{account_id}",
                event_name="RootAccountAccessKeysPresent",
                technique_id="T1078", technique_name="Valid Accounts",
                tactic=Tactic.INITIAL_ACCESS, severity=85, risk_tier=RiskTier.CRITICAL,
                description="The AWS account root user has active access keys. "
                            "Root should never have long-lived access keys — delete them "
                            "and use IAM users/roles instead.",
                account_id=account_id, region="global",
                service="IAM", resource_id="root", title="Root account has active access keys",
                recommendation="Delete the root user's access keys from the IAM console. "
                               "Use IAM users/roles with least-privilege permissions instead.",
            ))
    except ClientError as e:
        logger.warning(f"GetAccountSummary failed for account {account_id}: {e}")

    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                username = user["UserName"]
                _check_user_mfa(iam, username, account_id, findings)
                _check_user_admin_policy(iam, username, account_id, findings)
                _check_user_stale_access_keys(iam, username, account_id, findings)
    except ClientError as e:
        logger.warning(f"ListUsers failed for account {account_id}: {e}")

    return findings


_STALE_KEY_DAYS = 90


def _check_user_stale_access_keys(iam, username, account_id, findings):
    try:
        keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
        now = datetime.now(timezone.utc)
        for key in keys:
            if key.get("Status") != "Active":
                continue
            key_id = key["AccessKeyId"]
            create_date = key.get("CreateDate")
            reference_date = create_date
            try:
                last_used = iam.get_access_key_last_used(AccessKeyId=key_id)
                used_date = last_used.get("AccessKeyLastUsed", {}).get("LastUsedDate")
                if used_date:
                    reference_date = used_date
            except ClientError as e:
                logger.warning(f"GetAccessKeyLastUsed failed for {username}/{key_id}: {e}")

            if reference_date is None:
                continue
            age_days = (now - reference_date).days
            if age_days > _STALE_KEY_DAYS:
                findings.append(_alert(
                    event_id=f"config-iam-stale-key-{account_id}-{username}-{key_id}",
                    event_name="IAMAccessKeyStale",
                    technique_id="T1078", technique_name="Valid Accounts",
                    tactic=Tactic.INITIAL_ACCESS, severity=35, risk_tier=RiskTier.MEDIUM,
                    description=f"Access key {key_id} for user '{username}' hasn't been used "
                                f"in {age_days} days. Rotate or deactivate long-unused keys.",
                    account_id=account_id, region="global",
                    service="IAM", resource_id=f"{username}/{key_id}", title="Stale IAM access key",
                    recommendation="Rotate or deactivate this access key if it's no longer needed.",
                ))
    except ClientError as e:
        logger.warning(f"Access-key check failed for user {username}: {e}")


def _check_user_mfa(iam, username, account_id, findings):
    try:
        has_password = True
        try:
            iam.get_login_profile(UserName=username)
        except ClientError as e:
            if _error_code(e) == "NoSuchEntity":
                has_password = False
        if not has_password:
            return  # API-only users don't need console MFA

        mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
        if not mfa_devices:
            findings.append(_alert(
                event_id=f"config-iam-no-mfa-{account_id}-{username}",
                event_name="IAMUserNoMFA",
                technique_id="T1078", technique_name="Valid Accounts",
                tactic=Tactic.INITIAL_ACCESS, severity=45, risk_tier=RiskTier.MEDIUM,
                description=f"IAM user '{username}' has console access but no MFA device enrolled.",
                account_id=account_id, region="global",
                service="IAM", resource_id=username, title="IAM user without MFA",
                recommendation="Enroll a virtual or hardware MFA device for this user.",
            ))
    except ClientError as e:
        logger.warning(f"MFA check failed for user {username}: {e}")


def _check_user_admin_policy(iam, username, account_id, findings):
    try:
        attached = iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])
        for pol in attached:
            if pol["PolicyArn"] in DANGEROUS_MANAGED_POLICIES:
                findings.append(_alert(
                    event_id=f"config-iam-admin-policy-{account_id}-{username}-{pol['PolicyName']}",
                    event_name="IAMUserAdminPolicyAttached",
                    technique_id="T1098.003", technique_name="Account Manipulation: Additional Cloud Roles",
                    tactic=Tactic.PRIVILEGE_ESCALATION, severity=50, risk_tier=RiskTier.HIGH,
                    description=f"IAM user '{username}' has the high-privilege managed policy "
                                f"'{pol['PolicyName']}' attached directly. Prefer scoped, "
                                f"role-based access over standing admin grants.",
                    account_id=account_id, region="global",
                    service="IAM", resource_id=username, title="Admin policy attached directly to user",
                    recommendation=f"Detach '{pol['PolicyName']}' and replace it with a scoped, "
                                   f"least-privilege policy — ideally granted via a role, not a user.",
                ))
    except ClientError as e:
        logger.warning(f"Attached-policy check failed for user {username}: {e}")


# ─── EC2 ─────────────────────────────────────────────────────────────────

_SENSITIVE_PORTS = {22: "SSH", 3389: "RDP"}

def scan_security_groups(session, region, account_id) -> list[DetectedAlert]:
    """Security groups exposing SSH/RDP (or all ports) to the entire internet."""
    findings = []
    ec2 = session.client("ec2", region_name=region)

    try:
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                _check_sg_ingress(sg, account_id, region, findings)
    except ClientError as e:
        logger.warning(f"DescribeSecurityGroups failed for {account_id}/{region}: {e}")

    return findings


def _check_sg_ingress(sg, account_id, region, findings):
    sg_id, sg_name = sg["GroupId"], sg.get("GroupName", sg["GroupId"])
    for perm in sg.get("IpPermissions", []):
        open_to_world = any(
            r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", [])
        ) or any(
            r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", [])
        )
        if not open_to_world:
            continue

        from_port, to_port, protocol = perm.get("FromPort"), perm.get("ToPort"), perm.get("IpProtocol")

        if protocol == "-1" or (from_port is None and to_port is None):
            findings.append(_alert(
                event_id=f"config-sg-allports-{account_id}-{sg_id}",
                event_name="SecurityGroupAllPortsOpen",
                technique_id="T1190", technique_name="Exploit Public-Facing Application",
                tactic=Tactic.INITIAL_ACCESS, severity=85, risk_tier=RiskTier.CRITICAL,
                description=f"Security group '{sg_name}' ({sg_id}) allows ALL traffic from 0.0.0.0/0.",
                account_id=account_id, region=region,
                service="EC2", resource_id=sg_id, title="Security group allows all traffic from the internet",
                recommendation="Restrict the security group's ingress rules to specific, known IP ranges "
                               "and only the ports actually needed.",
            ))
            continue

        for port, label in _SENSITIVE_PORTS.items():
            if from_port is not None and to_port is not None and from_port <= port <= to_port:
                findings.append(_alert(
                    event_id=f"config-sg-{label.lower()}-{account_id}-{sg_id}",
                    event_name=f"SecurityGroup{label}Open",
                    technique_id="T1190", technique_name="Exploit Public-Facing Application",
                    tactic=Tactic.INITIAL_ACCESS, severity=70, risk_tier=RiskTier.HIGH,
                    description=f"Security group '{sg_name}' ({sg_id}) allows {label} "
                                f"(port {port}) from anywhere on the internet (0.0.0.0/0).",
                    account_id=account_id, region=region,
                    service="EC2", resource_id=sg_id, title=f"{label} open to the internet",
                    recommendation=f"Restrict port {port} ingress to specific, trusted IP ranges "
                                   f"instead of 0.0.0.0/0 — use a bastion host or VPN for {label} access.",
                ))


def scan_ebs_encryption(session, region, account_id) -> list[DetectedAlert]:
    """EBS volumes without encryption at rest."""
    findings = []
    ec2 = session.client("ec2", region_name=region)

    try:
        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate():
            for vol in page.get("Volumes", []):
                if not vol.get("Encrypted", False):
                    findings.append(_alert(
                        event_id=f"config-ebs-unencrypted-{account_id}-{vol['VolumeId']}",
                        event_name="EBSVolumeUnencrypted",
                        technique_id="T1530", technique_name="Data from Cloud Storage Object",
                        tactic=Tactic.COLLECTION, severity=30, risk_tier=RiskTier.MEDIUM,
                        description=f"EBS volume {vol['VolumeId']} ({vol.get('Size')} GiB) is not encrypted.",
                        account_id=account_id, region=region,
                        service="EC2", resource_id=vol["VolumeId"], title="Unencrypted EBS volume",
                        recommendation="Enable EBS encryption by default for the account/region, or "
                                       "create an encrypted snapshot/copy and migrate to it.",
                    ))
    except ClientError as e:
        logger.warning(f"DescribeVolumes failed for {account_id}/{region}: {e}")

    return findings


# ─── RDS ─────────────────────────────────────────────────────────────────

def scan_rds(session, region, account_id) -> list[DetectedAlert]:
    """Publicly accessible RDS instances and instances without storage encryption."""
    findings = []
    rds = session.client("rds", region_name=region)

    try:
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                db_id = db["DBInstanceIdentifier"]

                if db.get("PubliclyAccessible"):
                    findings.append(_alert(
                        event_id=f"config-rds-public-{account_id}-{db_id}",
                        event_name="RDSInstancePublic",
                        technique_id="T1190", technique_name="Exploit Public-Facing Application",
                        tactic=Tactic.INITIAL_ACCESS, severity=80, risk_tier=RiskTier.CRITICAL,
                        description=f"RDS instance '{db_id}' is publicly accessible from the internet.",
                        account_id=account_id, region=region,
                        service="RDS", resource_id=db_id, title="Publicly accessible RDS instance",
                        recommendation="Set PubliclyAccessible to false, and use a VPN, bastion host, "
                                       "or VPC peering for access instead.",
                    ))

                if not db.get("StorageEncrypted", False):
                    findings.append(_alert(
                        event_id=f"config-rds-unencrypted-{account_id}-{db_id}",
                        event_name="RDSInstanceUnencrypted",
                        technique_id="T1530", technique_name="Data from Cloud Storage Object",
                        tactic=Tactic.COLLECTION, severity=35, risk_tier=RiskTier.MEDIUM,
                        description=f"RDS instance '{db_id}' does not have storage encryption enabled.",
                        account_id=account_id, region=region,
                        service="RDS", resource_id=db_id, title="RDS instance without storage encryption",
                        recommendation="Storage encryption can't be toggled on an existing instance — "
                                       "create an encrypted snapshot and restore to a new instance.",
                    ))
    except ClientError as e:
        logger.warning(f"DescribeDBInstances failed for {account_id}/{region}: {e}")

    return findings


# ─── Secrets Manager ────────────────────────────────────────────────────────

def scan_secrets_manager(session, region, account_id) -> list[DetectedAlert]:
    """Secrets without automatic rotation enabled."""
    findings = []
    sm = session.client("secretsmanager", region_name=region)

    try:
        paginator = sm.get_paginator("list_secrets")
        for page in paginator.paginate():
            for secret in page.get("SecretList", []):
                if not secret.get("RotationEnabled", False):
                    findings.append(_alert(
                        event_id=f"config-secret-no-rotation-{account_id}-{secret['Name']}",
                        event_name="SecretRotationDisabled",
                        technique_id="T1552", technique_name="Unsecured Credentials",
                        tactic=Tactic.CREDENTIAL_ACCESS, severity=30, risk_tier=RiskTier.LOW,
                        description=f"Secret '{secret['Name']}' does not have automatic rotation enabled.",
                        account_id=account_id, region=region,
                        service="SecretsManager", resource_id=secret["Name"],
                        title="Secret without automatic rotation",
                        recommendation="Enable automatic rotation with an appropriate rotation Lambda function.",
                    ))
    except ClientError as e:
        logger.warning(f"ListSecrets failed for {account_id}/{region}: {e}")

    return findings


# ─── Lambda ──────────────────────────────────────────────────────────────

# Runtimes AWS has formally deprecated (no longer patched). Conservative
# list of ones that have been end-of-life for a while — not exhaustive,
# and worth revisiting periodically as more runtimes reach EOL.
_DEPRECATED_LAMBDA_RUNTIMES = {
    "python2.7", "python3.6", "python3.7",
    "nodejs10.x", "nodejs8.10", "nodejs12.x", "nodejs14.x",
    "dotnetcore2.1", "dotnetcore3.1",
    "ruby2.5", "ruby2.7",
    "go1.x",
}


def scan_lambda(session, region, account_id) -> list[DetectedAlert]:
    """Public function URLs, public resource policies, and deprecated runtimes."""
    findings = []
    lam = session.client("lambda", region_name=region)

    try:
        paginator = lam.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                name = fn["FunctionName"]

                if fn.get("Runtime") in _DEPRECATED_LAMBDA_RUNTIMES:
                    findings.append(_alert(
                        event_id=f"config-lambda-deprecated-runtime-{account_id}-{name}",
                        event_name="LambdaDeprecatedRuntime",
                        technique_id="T1190", technique_name="Exploit Public-Facing Application",
                        tactic=Tactic.INITIAL_ACCESS, severity=40, risk_tier=RiskTier.MEDIUM,
                        description=f"Lambda function '{name}' uses runtime "
                                    f"'{fn.get('Runtime')}', which AWS has deprecated "
                                    f"and no longer patches.",
                        account_id=account_id, region=region,
                        service="Lambda", resource_id=name, title="Lambda function on deprecated runtime",
                        recommendation="Migrate the function to a currently-supported runtime version.",
                    ))

                try:
                    url_cfg = lam.get_function_url_config(FunctionName=name)
                    if url_cfg.get("AuthType") == "NONE":
                        findings.append(_alert(
                            event_id=f"config-lambda-url-public-{account_id}-{name}",
                            event_name="LambdaFunctionURLPublic",
                            technique_id="T1190", technique_name="Exploit Public-Facing Application",
                            tactic=Tactic.INITIAL_ACCESS, severity=80, risk_tier=RiskTier.CRITICAL,
                            description=f"Lambda function '{name}' has a Function URL "
                                        f"with AuthType=NONE — anyone on the internet can invoke it.",
                            account_id=account_id, region=region,
                            service="Lambda", resource_id=name, title="Lambda Function URL publicly invocable",
                            recommendation="Set AuthType to AWS_IAM, or front the function with "
                                           "API Gateway and proper authorization.",
                        ))
                except ClientError as e:
                    if _error_code(e) != "ResourceNotFoundException":
                        logger.warning(f"GetFunctionUrlConfig failed for {name}: {e}")

                try:
                    policy_doc = json.loads(lam.get_policy(FunctionName=name)["Policy"])
                    for stmt in policy_doc.get("Statement", []):
                        principal = stmt.get("Principal")
                        is_public = principal == "*" or (
                            isinstance(principal, dict) and principal.get("AWS") == "*"
                        )
                        if stmt.get("Effect") == "Allow" and is_public and "Condition" not in stmt:
                            findings.append(_alert(
                                event_id=f"config-lambda-policy-public-{account_id}-{name}",
                                event_name="LambdaFunctionPolicyPublic",
                                technique_id="T1190", technique_name="Exploit Public-Facing Application",
                                tactic=Tactic.INITIAL_ACCESS, severity=75, risk_tier=RiskTier.HIGH,
                                description=f"Lambda function '{name}' has a resource policy "
                                            f"allowing invocation by anyone (Principal: *).",
                                account_id=account_id, region=region,
                                service="Lambda", resource_id=name,
                                title="Lambda resource policy allows public invocation",
                                recommendation="Scope the resource policy's Principal to specific "
                                               "accounts/services, or add a Condition to restrict it.",
                            ))
                            break
                except ClientError as e:
                    if _error_code(e) != "ResourceNotFoundException":
                        logger.warning(f"GetPolicy failed for {name}: {e}")
    except ClientError as e:
        logger.warning(f"ListFunctions failed for {account_id}/{region}: {e}")

    return findings


# ─── DynamoDB ────────────────────────────────────────────────────────────

def scan_dynamodb(session, region, account_id) -> list[DetectedAlert]:
    """Tables without point-in-time recovery or deletion protection."""
    findings = []
    ddb = session.client("dynamodb", region_name=region)

    try:
        paginator = ddb.get_paginator("list_tables")
        for page in paginator.paginate():
            for table_name in page.get("TableNames", []):
                try:
                    desc = ddb.describe_table(TableName=table_name)["Table"]
                    if not desc.get("DeletionProtectionEnabled", False):
                        findings.append(_alert(
                            event_id=f"config-ddb-deletion-protection-{account_id}-{table_name}",
                            event_name="DynamoDBDeletionProtectionDisabled",
                            technique_id="T1485", technique_name="Data Destruction",
                            tactic=Tactic.IMPACT, severity=35, risk_tier=RiskTier.MEDIUM,
                            description=f"DynamoDB table '{table_name}' does not have "
                                        f"deletion protection enabled.",
                            account_id=account_id, region=region,
                            service="DynamoDB", resource_id=table_name,
                            title="DynamoDB table without deletion protection",
                            recommendation="Enable DeletionProtectionEnabled on the table.",
                        ))
                except ClientError as e:
                    logger.warning(f"DescribeTable failed for {table_name}: {e}")

                try:
                    backups = ddb.describe_continuous_backups(TableName=table_name)
                    pitr_status = backups["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"]["PointInTimeRecoveryStatus"]
                    if pitr_status != "ENABLED":
                        findings.append(_alert(
                            event_id=f"config-ddb-pitr-{account_id}-{table_name}",
                            event_name="DynamoDBPITRDisabled",
                            technique_id="T1485", technique_name="Data Destruction",
                            tactic=Tactic.IMPACT, severity=30, risk_tier=RiskTier.MEDIUM,
                            description=f"DynamoDB table '{table_name}' does not have "
                                        f"point-in-time recovery enabled.",
                            account_id=account_id, region=region,
                            service="DynamoDB", resource_id=table_name,
                            title="DynamoDB table without point-in-time recovery",
                            recommendation="Enable point-in-time recovery so the table can be "
                                           "restored to any second in the last 35 days.",
                        ))
                except ClientError as e:
                    logger.warning(f"DescribeContinuousBackups failed for {table_name}: {e}")
    except ClientError as e:
        logger.warning(f"ListTables failed for {account_id}/{region}: {e}")

    return findings


# ─── ELB ─────────────────────────────────────────────────────────────────

def scan_elb(session, region, account_id) -> list[DetectedAlert]:
    """Load balancers without an HTTPS listener, or with access logging disabled."""
    findings = []
    elbv2 = session.client("elbv2", region_name=region)

    try:
        paginator = elbv2.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            for lb in page.get("LoadBalancers", []):
                lb_arn, lb_name = lb["LoadBalancerArn"], lb["LoadBalancerName"]

                if lb.get("Scheme") == "internet-facing":
                    try:
                        listeners = elbv2.describe_listeners(LoadBalancerArn=lb_arn).get("Listeners", [])
                        has_tls = any(l.get("Protocol") in ("HTTPS", "TLS") for l in listeners)
                        if not has_tls:
                            findings.append(_alert(
                                event_id=f"config-elb-no-https-{account_id}-{lb_name}",
                                event_name="ELBNoHTTPSListener",
                                technique_id="T1040", technique_name="Network Sniffing",
                                tactic=Tactic.CREDENTIAL_ACCESS, severity=60, risk_tier=RiskTier.HIGH,
                                description=f"Internet-facing load balancer '{lb_name}' has no "
                                            f"HTTPS/TLS listener — traffic is unencrypted in transit.",
                                account_id=account_id, region=region,
                                service="ELB", resource_id=lb_name, title="Internet-facing LB without HTTPS",
                                recommendation="Add an HTTPS (or TLS) listener with a valid ACM "
                                               "certificate, and redirect HTTP to HTTPS.",
                            ))
                    except ClientError as e:
                        logger.warning(f"DescribeListeners failed for {lb_name}: {e}")

                try:
                    attrs = {a["Key"]: a["Value"] for a in
                             elbv2.describe_load_balancer_attributes(LoadBalancerArn=lb_arn).get("Attributes", [])}
                    logs_enabled = (attrs.get("access_logs.s3.enabled", "").lower() == "true"
                                     or bool(attrs.get("access_logs.s3.bucket")))
                    if not logs_enabled:
                        findings.append(_alert(
                            event_id=f"config-elb-access-logs-{account_id}-{lb_name}",
                            event_name="ELBAccessLogsDisabled",
                            technique_id="T1562.008", technique_name="Impair Defenses: Disable Cloud Logs",
                            tactic=Tactic.DEFENSE_EVASION, severity=40, risk_tier=RiskTier.MEDIUM,
                            description=f"Load balancer '{lb_name}' does not have access logging enabled.",
                            account_id=account_id, region=region,
                            service="ELB", resource_id=lb_name, title="Load balancer access logs disabled",
                            recommendation="Enable access logs to an S3 bucket for this load balancer.",
                        ))
                except ClientError as e:
                    logger.warning(f"DescribeLoadBalancerAttributes failed for {lb_name}: {e}")
    except ClientError as e:
        logger.warning(f"DescribeLoadBalancers failed for {account_id}/{region}: {e}")

    return findings


# ─── WAF ─────────────────────────────────────────────────────────────────

def scan_waf(session, region, account_id) -> list[DetectedAlert]:
    """Internet-facing ALBs without a WAF Web ACL attached, and Web ACLs with zero rules."""
    findings = []
    elbv2 = session.client("elbv2", region_name=region)
    waf = session.client("wafv2", region_name=region)

    try:
        paginator = elbv2.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            for lb in page.get("LoadBalancers", []):
                if lb.get("Scheme") != "internet-facing" or lb.get("Type") != "application":
                    continue
                lb_arn, lb_name = lb["LoadBalancerArn"], lb["LoadBalancerName"]
                try:
                    assoc = waf.get_web_acl_for_resource(ResourceArn=lb_arn)
                    if not assoc.get("WebACL"):
                        findings.append(_alert(
                            event_id=f"config-waf-missing-{account_id}-{lb_name}",
                            event_name="ALBWithoutWAF",
                            technique_id="T1190", technique_name="Exploit Public-Facing Application",
                            tactic=Tactic.INITIAL_ACCESS, severity=65, risk_tier=RiskTier.HIGH,
                            description=f"Internet-facing ALB '{lb_name}' has no WAF Web ACL attached.",
                            account_id=account_id, region=region,
                            service="WAF", resource_id=lb_name, title="Internet-facing ALB without WAF",
                            recommendation="Associate a WAF Web ACL with this load balancer with rules "
                                           "appropriate for the application (managed rule groups are a "
                                           "good starting point).",
                        ))
                except ClientError as e:
                    logger.warning(f"GetWebACLForResource failed for {lb_name}: {e}")
    except ClientError as e:
        logger.warning(f"DescribeLoadBalancers failed for {account_id}/{region} (WAF check): {e}")

    try:
        for scope in ("REGIONAL",):
            acls = waf.list_web_acls(Scope=scope).get("WebACLs", [])
            for acl_summary in acls:
                try:
                    detail = waf.get_web_acl(
                        Name=acl_summary["Name"], Scope=scope, Id=acl_summary["Id"],
                    )["WebACL"]
                    if not detail.get("Rules"):
                        findings.append(_alert(
                            event_id=f"config-waf-no-rules-{account_id}-{acl_summary['Id']}",
                            event_name="WAFWebACLNoRules",
                            technique_id="T1190", technique_name="Exploit Public-Facing Application",
                            tactic=Tactic.INITIAL_ACCESS, severity=35, risk_tier=RiskTier.MEDIUM,
                            description=f"WAF Web ACL '{acl_summary['Name']}' has no rules configured "
                                        f"— it isn't actually blocking anything.",
                            account_id=account_id, region=region,
                            service="WAF", resource_id=acl_summary["Name"], title="Empty WAF Web ACL",
                            recommendation="Add managed or custom rule groups to this Web ACL, or "
                                           "remove it if it's not meant to be in use.",
                        ))
                except ClientError as e:
                    logger.warning(f"GetWebACL failed for {acl_summary.get('Name')}: {e}")
    except ClientError as e:
        logger.warning(f"ListWebACLs failed for {account_id}/{region}: {e}")

    return findings


# ─── Account-level logging ─────────────────────────────────────────────────

def scan_account_logging(session, region, account_id) -> list[DetectedAlert]:
    """CloudTrail, GuardDuty, Security Hub, and Config disabled — the classic 'lights off' attacker move."""
    findings = []

    ct = session.client("cloudtrail", region_name=region)
    try:
        trails = ct.describe_trails().get("trailList", [])
        any_logging = False
        for t in trails:
            try:
                status = ct.get_trail_status(Name=t["TrailARN"])
                if status.get("IsLogging"):
                    any_logging = True
                    break
            except ClientError as e:
                logger.warning(f"GetTrailStatus failed for {t.get('TrailARN')}: {e}")
        if not any_logging:
            findings.append(_alert(
                event_id=f"config-cloudtrail-disabled-{account_id}-{region}",
                event_name="CloudTrailDisabled",
                technique_id="T1562.008", technique_name="Impair Defenses: Disable Cloud Logs",
                tactic=Tactic.DEFENSE_EVASION, severity=70, risk_tier=RiskTier.CRITICAL,
                description=f"No actively-logging CloudTrail trail found in {region}. "
                            f"Without CloudTrail, most other detections in Cloud Guardian go blind.",
                account_id=account_id, region=region,
                service="CloudTrail", resource_id=region, title="CloudTrail not logging",
                recommendation="Create a multi-region CloudTrail trail and ensure logging is started.",
            ))
    except ClientError as e:
        logger.warning(f"DescribeTrails failed for {account_id}/{region}: {e}")

    gd = session.client("guardduty", region_name=region)
    try:
        detector_ids = gd.list_detectors().get("DetectorIds", [])
        any_enabled = False
        for d in detector_ids:
            try:
                if gd.get_detector(DetectorId=d).get("Status") == "ENABLED":
                    any_enabled = True
                    break
            except ClientError as e:
                logger.warning(f"GetDetector failed for {d}: {e}")
        if not any_enabled:
            findings.append(_alert(
                event_id=f"config-guardduty-disabled-{account_id}-{region}",
                event_name="GuardDutyDisabled",
                technique_id="T1562.001", technique_name="Impair Defenses: Disable or Modify Tools",
                tactic=Tactic.DEFENSE_EVASION, severity=60, risk_tier=RiskTier.HIGH,
                description=f"GuardDuty is not enabled (or has no active detector) in {region}.",
                account_id=account_id, region=region,
                service="GuardDuty", resource_id=region, title="GuardDuty not enabled",
                recommendation="Enable GuardDuty in this region (and every region you operate in).",
            ))
    except ClientError as e:
        logger.warning(f"ListDetectors failed for {account_id}/{region}: {e}")

    sh = session.client("securityhub", region_name=region)
    try:
        sh.describe_hub()
        # No exception -> Security Hub is subscribed/enabled in this region.
    except ClientError as e:
        if _error_code(e) in ("InvalidAccessException", "ResourceNotFoundException"):
            findings.append(_alert(
                event_id=f"config-securityhub-disabled-{account_id}-{region}",
                event_name="SecurityHubDisabled",
                technique_id="T1562.001", technique_name="Impair Defenses: Disable or Modify Tools",
                tactic=Tactic.DEFENSE_EVASION, severity=55, risk_tier=RiskTier.HIGH,
                description=f"AWS Security Hub is not enabled in {region}, losing the "
                            f"aggregated view of findings across GuardDuty, Inspector, "
                            f"Macie, and AWS Foundational Security Best Practices checks.",
                account_id=account_id, region=region,
                service="SecurityHub", resource_id=region, title="Security Hub not enabled",
                recommendation="Enable AWS Security Hub in this region to aggregate findings "
                               "across GuardDuty, Inspector, Macie, and FSBP checks.",
            ))
        else:
            logger.warning(f"DescribeHub failed for {account_id}/{region}: {e}")

    cfg = session.client("config", region_name=region)
    try:
        recorders = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
        any_recording = False
        if recorders:
            statuses = cfg.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
            any_recording = any(s.get("recording") for s in statuses)
        if not any_recording:
            findings.append(_alert(
                event_id=f"config-awsconfig-disabled-{account_id}-{region}",
                event_name="AWSConfigDisabled",
                technique_id="T1562.001", technique_name="Impair Defenses: Disable or Modify Tools",
                tactic=Tactic.DEFENSE_EVASION, severity=50, risk_tier=RiskTier.MEDIUM,
                description=f"AWS Config has no active configuration recorder in {region}, "
                            f"so resource configuration drift and history aren't tracked.",
                account_id=account_id, region=region,
                service="Config", resource_id=region, title="AWS Config not recording",
                recommendation="Set up an AWS Config configuration recorder and delivery channel, "
                               "then start recording.",
            ))
    except ClientError as e:
        logger.warning(f"DescribeConfigurationRecorders failed for {account_id}/{region}: {e}")

    return findings


# ─── Asset discovery ────────────────────────────────────────────────────────

def discover_assets(session, region, account_id) -> list[dict]:
    """
    Lightweight resource inventory — every resource this scanner looks at,
    not just ones with findings. Feeds GET /dashboard/assets.

    Kept as its own pass (rather than folded into each scan_* function) so
    inventory logic stays simple and each check function keeps its single
    responsibility. Costs a handful of duplicate list/describe calls per
    scan, which is a fine trade for the isolation.

    Returns dicts shaped for db.repositories.asset_repo.AssetRepository.upsert:
      {"service", "resource_type", "resource_id", "region", "metadata"}
    """
    assets: list[dict] = []

    try:
        s3 = session.client("s3")
        for b in s3.list_buckets().get("Buckets", []):
            assets.append({
                "service": "S3", "resource_type": "Bucket", "resource_id": b["Name"],
                "region": "global", "metadata": {},
            })
    except ClientError as e:
        logger.warning(f"Asset discovery (S3) failed for {account_id}: {e}")

    try:
        iam = session.client("iam")
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                assets.append({
                    "service": "IAM", "resource_type": "User", "resource_id": user["UserName"],
                    "region": "global", "metadata": {},
                })
    except ClientError as e:
        logger.warning(f"Asset discovery (IAM) failed for {account_id}: {e}")

    try:
        ec2 = session.client("ec2", region_name=region)
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                assets.append({
                    "service": "EC2", "resource_type": "SecurityGroup", "resource_id": sg["GroupId"],
                    "region": region, "metadata": {"name": sg.get("GroupName")},
                })
        vol_paginator = ec2.get_paginator("describe_volumes")
        for page in vol_paginator.paginate():
            for vol in page.get("Volumes", []):
                assets.append({
                    "service": "EC2", "resource_type": "Volume", "resource_id": vol["VolumeId"],
                    "region": region, "metadata": {"size_gb": vol.get("Size")},
                })
    except ClientError as e:
        logger.warning(f"Asset discovery (EC2) failed for {account_id}/{region}: {e}")

    try:
        rds = session.client("rds", region_name=region)
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                assets.append({
                    "service": "RDS", "resource_type": "DBInstance",
                    "resource_id": db["DBInstanceIdentifier"], "region": region,
                    "metadata": {"engine": db.get("Engine")},
                })
    except ClientError as e:
        logger.warning(f"Asset discovery (RDS) failed for {account_id}/{region}: {e}")

    try:
        sm = session.client("secretsmanager", region_name=region)
        paginator = sm.get_paginator("list_secrets")
        for page in paginator.paginate():
            for secret in page.get("SecretList", []):
                assets.append({
                    "service": "SecretsManager", "resource_type": "Secret",
                    "resource_id": secret["Name"], "region": region, "metadata": {},
                })
    except ClientError as e:
        logger.warning(f"Asset discovery (Secrets Manager) failed for {account_id}/{region}: {e}")

    try:
        lam = session.client("lambda", region_name=region)
        paginator = lam.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                assets.append({
                    "service": "Lambda", "resource_type": "Function",
                    "resource_id": fn["FunctionName"], "region": region,
                    "metadata": {"runtime": fn.get("Runtime")},
                })
    except ClientError as e:
        logger.warning(f"Asset discovery (Lambda) failed for {account_id}/{region}: {e}")

    try:
        ddb = session.client("dynamodb", region_name=region)
        paginator = ddb.get_paginator("list_tables")
        for page in paginator.paginate():
            for table_name in page.get("TableNames", []):
                assets.append({
                    "service": "DynamoDB", "resource_type": "Table",
                    "resource_id": table_name, "region": region, "metadata": {},
                })
    except ClientError as e:
        logger.warning(f"Asset discovery (DynamoDB) failed for {account_id}/{region}: {e}")

    try:
        elbv2 = session.client("elbv2", region_name=region)
        paginator = elbv2.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            for lb in page.get("LoadBalancers", []):
                assets.append({
                    "service": "ELB", "resource_type": "LoadBalancer",
                    "resource_id": lb["LoadBalancerName"], "region": region,
                    "metadata": {"scheme": lb.get("Scheme")},
                })
    except ClientError as e:
        logger.warning(f"Asset discovery (ELB) failed for {account_id}/{region}: {e}")

    return assets


# ─── Orchestration ──────────────────────────────────────────────────────────

def run_config_scan(session, region, account_id) -> list[DetectedAlert]:
    """
    Run every configuration check for one account/region and return the
    combined findings. Each category is isolated — a failure in one
    (e.g. a missing permission) doesn't stop the others from running.
    """
    findings: list[DetectedAlert] = []

    for label, fn, args in (
        ("S3", scan_s3, (session, account_id)),
        ("IAM", scan_iam, (session, account_id)),
        ("Security Groups", scan_security_groups, (session, region, account_id)),
        ("EBS encryption", scan_ebs_encryption, (session, region, account_id)),
        ("RDS", scan_rds, (session, region, account_id)),
        ("Secrets Manager", scan_secrets_manager, (session, region, account_id)),
        ("Lambda", scan_lambda, (session, region, account_id)),
        ("DynamoDB", scan_dynamodb, (session, region, account_id)),
        ("ELB", scan_elb, (session, region, account_id)),
        ("WAF", scan_waf, (session, region, account_id)),
        ("Account logging", scan_account_logging, (session, region, account_id)),
    ):
        try:
            findings.extend(fn(*args))
        except Exception as e:
            logger.error(f"Config scan category '{label}' failed for {account_id}/{region}: {e}",
                         exc_info=True)

    return findings
