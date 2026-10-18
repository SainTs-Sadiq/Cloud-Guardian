"""
Tests for detection/config_scanner.py — the point-in-time misconfiguration
checks (S3, IAM, Security Groups, EBS, account logging).

Uses moto to simulate real AWS API responses rather than hand-rolled mocks,
so these tests exercise the actual boto3 call shapes the scanner depends on.
"""
import os
os.environ.setdefault("MOTO_IAM_LOAD_MANAGED_POLICIES", "True")  # so AdministratorAccess etc. are attachable

import boto3
import pytest
from moto import mock_aws

from detection.config_scanner import (
    scan_s3, scan_iam, scan_security_groups, scan_ebs_encryption,
    scan_rds, scan_secrets_manager, scan_account_logging, run_config_scan,
    scan_lambda, scan_dynamodb, scan_elb, scan_waf,
)

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


def _event_names(findings):
    return {f.event_name for f in findings}


# ─── S3 ──────────────────────────────────────────────────────────────────

class TestScanS3:
    @mock_aws
    def test_bucket_public_via_acl_flagged(self):
        session = boto3.Session(region_name=REGION)
        s3 = session.client("s3")
        s3.create_bucket(Bucket="my-public-bucket")
        s3.put_bucket_acl(Bucket="my-public-bucket", AccessControlPolicy={
            "Owner": {"ID": "owner"},
            "Grants": [{
                "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                "Permission": "READ",
            }],
        })
        findings = scan_s3(session, ACCOUNT_ID)
        assert "S3BucketPublic" in _event_names(findings)
        public = [f for f in findings if f.event_name == "S3BucketPublic"][0]
        assert public.technique_id == "T1530"
        assert public.risk_tier == "high"
        assert public.event_id == f"config-s3-public-{ACCOUNT_ID}-my-public-bucket"

    @mock_aws
    def test_bucket_public_via_policy_flagged(self):
        import json
        session = boto3.Session(region_name=REGION)
        s3 = session.client("s3")
        s3.create_bucket(Bucket="policy-public-bucket")
        s3.put_bucket_policy(Bucket="policy-public-bucket", Policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow", "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::policy-public-bucket/*",
            }],
        }))
        findings = scan_s3(session, ACCOUNT_ID)
        assert "S3BucketPublic" in _event_names(findings)

    @mock_aws
    def test_private_bucket_not_flagged(self):
        session = boto3.Session(region_name=REGION)
        s3 = session.client("s3")
        s3.create_bucket(Bucket="private-bucket")
        findings = scan_s3(session, ACCOUNT_ID)
        assert "S3BucketPublic" not in _event_names(findings)

    @mock_aws
    def test_block_public_access_suppresses_finding_even_with_public_acl_attempt(self):
        session = boto3.Session(region_name=REGION)
        s3 = session.client("s3")
        s3.create_bucket(Bucket="blocked-bucket")
        s3.put_public_access_block(Bucket="blocked-bucket", PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        })
        findings = scan_s3(session, ACCOUNT_ID)
        assert "S3BucketPublic" not in _event_names(findings)

    @mock_aws
    def test_unencrypted_bucket_flagged(self):
        session = boto3.Session(region_name=REGION)
        s3 = session.client("s3")
        s3.create_bucket(Bucket="unencrypted-bucket")
        findings = scan_s3(session, ACCOUNT_ID)
        assert "S3BucketUnencrypted" in _event_names(findings)
        enc = [f for f in findings if f.event_name == "S3BucketUnencrypted"][0]
        assert enc.risk_tier == "medium"

    @mock_aws
    def test_encrypted_bucket_not_flagged(self):
        session = boto3.Session(region_name=REGION)
        s3 = session.client("s3")
        s3.create_bucket(Bucket="encrypted-bucket")
        s3.put_bucket_encryption(Bucket="encrypted-bucket", ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        })
        findings = scan_s3(session, ACCOUNT_ID)
        assert "S3BucketUnencrypted" not in _event_names(findings)

    @mock_aws
    def test_no_buckets_returns_empty(self):
        session = boto3.Session(region_name=REGION)
        findings = scan_s3(session, ACCOUNT_ID)
        assert findings == []

    @mock_aws
    def test_event_id_is_deterministic_across_repeated_scans(self):
        session = boto3.Session(region_name=REGION)
        s3 = session.client("s3")
        s3.create_bucket(Bucket="unencrypted-bucket")
        first = scan_s3(session, ACCOUNT_ID)
        second = scan_s3(session, ACCOUNT_ID)
        assert {f.event_id for f in first} == {f.event_id for f in second}


# ─── IAM ─────────────────────────────────────────────────────────────────

class TestScanIAM:
    @mock_aws
    def test_console_user_without_mfa_flagged(self):
        session = boto3.Session(region_name=REGION)
        iam = session.client("iam")
        iam.create_user(UserName="alice")
        iam.create_login_profile(UserName="alice", Password="Sup3rSecret!23")
        findings = scan_iam(session, ACCOUNT_ID)
        assert "IAMUserNoMFA" in _event_names(findings)

    @mock_aws
    def test_console_user_with_mfa_not_flagged(self):
        session = boto3.Session(region_name=REGION)
        iam = session.client("iam")
        iam.create_user(UserName="bob")
        iam.create_login_profile(UserName="bob", Password="Sup3rSecret!23")
        mfa = iam.create_virtual_mfa_device(VirtualMFADeviceName="bob-mfa")["VirtualMFADevice"]
        iam.enable_mfa_device(
            UserName="bob", SerialNumber=mfa["SerialNumber"],
            AuthenticationCode1="123456", AuthenticationCode2="654321",
        )
        findings = scan_iam(session, ACCOUNT_ID)
        assert "IAMUserNoMFA" not in _event_names(findings)

    @mock_aws
    def test_api_only_user_without_login_profile_not_flagged_for_mfa(self):
        session = boto3.Session(region_name=REGION)
        iam = session.client("iam")
        iam.create_user(UserName="ci-bot")  # no login profile — API-only
        findings = scan_iam(session, ACCOUNT_ID)
        assert "IAMUserNoMFA" not in _event_names(findings)

    @mock_aws
    def test_admin_policy_attached_flagged(self):
        session = boto3.Session(region_name=REGION)
        iam = session.client("iam")
        iam.create_user(UserName="over-privileged")
        iam.attach_user_policy(
            UserName="over-privileged",
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
        )
        findings = scan_iam(session, ACCOUNT_ID)
        assert "IAMUserAdminPolicyAttached" in _event_names(findings)
        admin_finding = [f for f in findings if f.event_name == "IAMUserAdminPolicyAttached"][0]
        assert admin_finding.risk_tier == "high"
        assert admin_finding.tactic == "Privilege Escalation"

    @mock_aws
    def test_scoped_policy_not_flagged_as_admin(self):
        session = boto3.Session(region_name=REGION)
        iam = session.client("iam")
        iam.create_user(UserName="scoped-user")
        iam.attach_user_policy(
            UserName="scoped-user",
            PolicyArn="arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
        )
        findings = scan_iam(session, ACCOUNT_ID)
        assert "IAMUserAdminPolicyAttached" not in _event_names(findings)

    @mock_aws
    def test_no_root_access_keys_by_default(self):
        session = boto3.Session(region_name=REGION)
        findings = scan_iam(session, ACCOUNT_ID)
        assert "RootAccountAccessKeysPresent" not in _event_names(findings)

    @mock_aws
    def test_no_users_returns_no_iam_findings(self):
        session = boto3.Session(region_name=REGION)
        findings = scan_iam(session, ACCOUNT_ID)
        assert findings == []

    @mock_aws
    def test_recently_used_access_key_not_flagged(self):
        session = boto3.Session(region_name=REGION)
        iam = session.client("iam")
        iam.create_user(UserName="active-user")
        iam.create_access_key(UserName="active-user")
        findings = scan_iam(session, ACCOUNT_ID)
        assert "IAMAccessKeyStale" not in _event_names(findings)

    @mock_aws
    def test_stale_access_key_flagged(self):
        from datetime import datetime, timedelta, timezone

        class _SessionWithOldKeyUsage:
            """boto3.Session wrapper that reports a 200-day-old last-used
            date for access keys, so the staleness check has something
            deterministic to trigger on (moto always reports keys as
            freshly created, never "used" long ago)."""
            def __init__(self, real_session):
                self._real = real_session

            def client(self, service_name, *a, **kw):
                c = self._real.client(service_name, *a, **kw)
                if service_name == "iam":
                    old_date = datetime.now(timezone.utc) - timedelta(days=200)
                    c.get_access_key_last_used = lambda **kw: {
                        "AccessKeyLastUsed": {"LastUsedDate": old_date}
                    }
                return c

        session = _SessionWithOldKeyUsage(boto3.Session(region_name=REGION))
        iam = session.client("iam")
        iam.create_user(UserName="stale-user")
        iam.create_access_key(UserName="stale-user")

        findings = scan_iam(session, ACCOUNT_ID)
        assert "IAMAccessKeyStale" in _event_names(findings)


# ─── RDS ─────────────────────────────────────────────────────────────────

class TestScanRDS:
    @mock_aws
    def test_public_instance_flagged(self):
        session = boto3.Session(region_name=REGION)
        rds = session.client("rds", region_name=REGION)
        rds.create_db_instance(
            DBInstanceIdentifier="public-db", DBInstanceClass="db.t3.micro",
            Engine="postgres", MasterUsername="admin", MasterUserPassword="SuperSecret123",
            AllocatedStorage=20, PubliclyAccessible=True, StorageEncrypted=True,
        )
        findings = scan_rds(session, REGION, ACCOUNT_ID)
        assert "RDSInstancePublic" in _event_names(findings)
        f = [x for x in findings if x.event_name == "RDSInstancePublic"][0]
        assert f.risk_tier == "critical"

    @mock_aws
    def test_private_encrypted_instance_not_flagged(self):
        session = boto3.Session(region_name=REGION)
        rds = session.client("rds", region_name=REGION)
        rds.create_db_instance(
            DBInstanceIdentifier="private-db", DBInstanceClass="db.t3.micro",
            Engine="postgres", MasterUsername="admin", MasterUserPassword="SuperSecret123",
            AllocatedStorage=20, PubliclyAccessible=False, StorageEncrypted=True,
        )
        findings = scan_rds(session, REGION, ACCOUNT_ID)
        assert findings == []

    @mock_aws
    def test_unencrypted_instance_flagged(self):
        session = boto3.Session(region_name=REGION)
        rds = session.client("rds", region_name=REGION)
        rds.create_db_instance(
            DBInstanceIdentifier="unencrypted-db", DBInstanceClass="db.t3.micro",
            Engine="postgres", MasterUsername="admin", MasterUserPassword="SuperSecret123",
            AllocatedStorage=20, PubliclyAccessible=False, StorageEncrypted=False,
        )
        findings = scan_rds(session, REGION, ACCOUNT_ID)
        assert "RDSInstanceUnencrypted" in _event_names(findings)

    @mock_aws
    def test_no_instances_returns_empty(self):
        session = boto3.Session(region_name=REGION)
        findings = scan_rds(session, REGION, ACCOUNT_ID)
        assert findings == []


# ─── Secrets Manager ─────────────────────────────────────────────────────

class TestScanSecretsManager:
    @mock_aws
    def test_secret_without_rotation_flagged(self):
        session = boto3.Session(region_name=REGION)
        sm = session.client("secretsmanager", region_name=REGION)
        sm.create_secret(Name="db-password", SecretString="hunter2")
        findings = scan_secrets_manager(session, REGION, ACCOUNT_ID)
        assert "SecretRotationDisabled" in _event_names(findings)
        f = [x for x in findings if x.event_name == "SecretRotationDisabled"][0]
        assert f.tactic == "Credential Access"

    @mock_aws
    def test_secret_with_rotation_not_flagged(self):
        session = boto3.Session(region_name=REGION)
        sm = session.client("secretsmanager", region_name=REGION)
        sm.create_secret(Name="rotated-password", SecretString="hunter2")
        sm.rotate_secret(SecretId="rotated-password", RotationRules={"AutomaticallyAfterDays": 30})
        findings = scan_secrets_manager(session, REGION, ACCOUNT_ID)
        assert "SecretRotationDisabled" not in _event_names(findings)

    @mock_aws
    def test_no_secrets_returns_empty(self):
        session = boto3.Session(region_name=REGION)
        findings = scan_secrets_manager(session, REGION, ACCOUNT_ID)
        assert findings == []


# ─── EC2 security groups ────────────────────────────────────────────────

class TestScanSecurityGroups:
    @mock_aws
    def test_ssh_open_to_world_flagged(self):
        session = boto3.Session(region_name=REGION)
        ec2 = session.client("ec2", region_name=REGION)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        sg = ec2.create_security_group(GroupName="ssh-open", Description="test", VpcId=vpc)["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg, IpPermissions=[{
                "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )
        findings = scan_security_groups(session, REGION, ACCOUNT_ID)
        assert "SecurityGroupSSHOpen" in _event_names(findings)
        f = [x for x in findings if x.event_name == "SecurityGroupSSHOpen"][0]
        assert f.risk_tier == "high"
        assert sg in f.event_id

    @mock_aws
    def test_rdp_open_to_world_flagged(self):
        session = boto3.Session(region_name=REGION)
        ec2 = session.client("ec2", region_name=REGION)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        sg = ec2.create_security_group(GroupName="rdp-open", Description="test", VpcId=vpc)["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg, IpPermissions=[{
                "IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )
        findings = scan_security_groups(session, REGION, ACCOUNT_ID)
        assert "SecurityGroupRDPOpen" in _event_names(findings)

    @mock_aws
    def test_all_traffic_open_flagged_as_critical(self):
        session = boto3.Session(region_name=REGION)
        ec2 = session.client("ec2", region_name=REGION)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        sg = ec2.create_security_group(GroupName="wide-open", Description="test", VpcId=vpc)["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg, IpPermissions=[{
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )
        findings = scan_security_groups(session, REGION, ACCOUNT_ID)
        assert "SecurityGroupAllPortsOpen" in _event_names(findings)
        f = [x for x in findings if x.event_name == "SecurityGroupAllPortsOpen"][0]
        assert f.risk_tier == "critical"

    @mock_aws
    def test_restricted_cidr_not_flagged(self):
        session = boto3.Session(region_name=REGION)
        ec2 = session.client("ec2", region_name=REGION)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        sg = ec2.create_security_group(GroupName="restricted", Description="test", VpcId=vpc)["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg, IpPermissions=[{
                "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                "IpRanges": [{"CidrIp": "203.0.113.5/32"}],
            }],
        )
        findings = scan_security_groups(session, REGION, ACCOUNT_ID)
        assert findings == []

    @mock_aws
    def test_other_port_open_to_world_not_flagged_as_ssh_or_rdp(self):
        session = boto3.Session(region_name=REGION)
        ec2 = session.client("ec2", region_name=REGION)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        sg = ec2.create_security_group(GroupName="http-open", Description="test", VpcId=vpc)["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg, IpPermissions=[{
                "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )
        findings = scan_security_groups(session, REGION, ACCOUNT_ID)
        assert _event_names(findings) == set()


# ─── EBS ─────────────────────────────────────────────────────────────────

class TestScanEBS:
    @mock_aws
    def test_unencrypted_volume_flagged(self):
        session = boto3.Session(region_name=REGION)
        ec2 = session.client("ec2", region_name=REGION)
        ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=8, Encrypted=False)
        findings = scan_ebs_encryption(session, REGION, ACCOUNT_ID)
        assert "EBSVolumeUnencrypted" in _event_names(findings)

    @mock_aws
    def test_encrypted_volume_not_flagged(self):
        session = boto3.Session(region_name=REGION)
        ec2 = session.client("ec2", region_name=REGION)
        ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=8, Encrypted=True)
        findings = scan_ebs_encryption(session, REGION, ACCOUNT_ID)
        assert "EBSVolumeUnencrypted" not in _event_names(findings)


# ─── Account logging ─────────────────────────────────────────────────────

class TestScanAccountLogging:
    @mock_aws
    def test_no_trail_flags_cloudtrail_disabled(self):
        session = boto3.Session(region_name=REGION)
        findings = scan_account_logging(session, REGION, ACCOUNT_ID)
        assert "CloudTrailDisabled" in _event_names(findings)

    @mock_aws
    def test_active_trail_suppresses_cloudtrail_finding(self):
        session = boto3.Session(region_name=REGION)
        s3 = session.client("s3")
        s3.create_bucket(Bucket="trail-bucket")
        s3.put_bucket_policy(Bucket="trail-bucket", Policy="""{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::trail-bucket/*"
            }]
        }""")
        ct = session.client("cloudtrail", region_name=REGION)
        trail = ct.create_trail(Name="main-trail", S3BucketName="trail-bucket")
        ct.start_logging(Name=trail["Name"])
        findings = scan_account_logging(session, REGION, ACCOUNT_ID)
        assert "CloudTrailDisabled" not in _event_names(findings)

    @mock_aws
    def test_no_detector_flags_guardduty_disabled(self):
        session = boto3.Session(region_name=REGION)
        findings = scan_account_logging(session, REGION, ACCOUNT_ID)
        assert "GuardDutyDisabled" in _event_names(findings)

    @mock_aws
    def test_enabled_detector_suppresses_guardduty_finding(self):
        session = boto3.Session(region_name=REGION)
        gd = session.client("guardduty", region_name=REGION)
        gd.create_detector(Enable=True)
        findings = scan_account_logging(session, REGION, ACCOUNT_ID)
        assert "GuardDutyDisabled" not in _event_names(findings)

    @mock_aws
    def test_security_hub_not_subscribed_flagged(self):
        session = boto3.Session(region_name=REGION)
        findings = scan_account_logging(session, REGION, ACCOUNT_ID)
        assert "SecurityHubDisabled" in _event_names(findings)

    @mock_aws
    def test_security_hub_enabled_suppresses_finding(self):
        session = boto3.Session(region_name=REGION)
        sh = session.client("securityhub", region_name=REGION)
        sh.enable_security_hub()
        findings = scan_account_logging(session, REGION, ACCOUNT_ID)
        assert "SecurityHubDisabled" not in _event_names(findings)

    @mock_aws
    def test_no_config_recorder_flagged(self):
        session = boto3.Session(region_name=REGION)
        findings = scan_account_logging(session, REGION, ACCOUNT_ID)
        assert "AWSConfigDisabled" in _event_names(findings)

    @mock_aws
    def test_active_config_recorder_suppresses_finding(self):
        session = boto3.Session(region_name=REGION)
        s3 = session.client("s3")
        s3.create_bucket(Bucket="config-delivery-bucket")
        cfg = session.client("config", region_name=REGION)
        cfg.put_configuration_recorder(ConfigurationRecorder={
            "name": "default", "roleARN": f"arn:aws:iam::{ACCOUNT_ID}:role/config-role",
            "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": True},
        })
        cfg.put_delivery_channel(DeliveryChannel={"name": "default", "s3BucketName": "config-delivery-bucket"})
        cfg.start_configuration_recorder(ConfigurationRecorderName="default")
        findings = scan_account_logging(session, REGION, ACCOUNT_ID)
        assert "AWSConfigDisabled" not in _event_names(findings)


# ─── Orchestration ──────────────────────────────────────────────────────────

class TestRunConfigScan:
    @mock_aws
    def test_combines_all_categories(self):
        session = boto3.Session(region_name=REGION)
        s3 = session.client("s3")
        s3.create_bucket(Bucket="combo-bucket")  # unencrypted -> 1 finding
        rds = session.client("rds", region_name=REGION)
        rds.create_db_instance(
            DBInstanceIdentifier="combo-db", DBInstanceClass="db.t3.micro",
            Engine="postgres", MasterUsername="admin", MasterUserPassword="SuperSecret123",
            AllocatedStorage=20, PubliclyAccessible=True, StorageEncrypted=False,
        )
        sm = session.client("secretsmanager", region_name=REGION)
        sm.create_secret(Name="combo-secret", SecretString="shh")

        findings = run_config_scan(session, REGION, ACCOUNT_ID)
        names = _event_names(findings)

        assert "S3BucketUnencrypted" in names
        assert "RDSInstancePublic" in names
        assert "RDSInstanceUnencrypted" in names
        assert "SecretRotationDisabled" in names
        assert "CloudTrailDisabled" in names
        assert "GuardDutyDisabled" in names
        assert "SecurityHubDisabled" in names
        assert "AWSConfigDisabled" in names

    @mock_aws
    def test_one_failing_category_does_not_block_others(self, monkeypatch):
        import detection.config_scanner as cs

        def boom(*a, **kw):
            raise RuntimeError("simulated failure")

        monkeypatch.setattr(cs, "scan_s3", boom)
        findings = run_config_scan(session=boto3.Session(region_name=REGION),
                                    region=REGION, account_id=ACCOUNT_ID)
        # S3 blew up, but CloudTrail/GuardDuty checks should still have run.
        assert "CloudTrailDisabled" in _event_names(findings)
        assert "GuardDutyDisabled" in _event_names(findings)

    @mock_aws
    def test_clean_account_still_flags_missing_logging(self):
        """Even a 'clean' account with no resources should flag disabled CloudTrail/GuardDuty."""
        session = boto3.Session(region_name=REGION)
        findings = run_config_scan(session, REGION, ACCOUNT_ID)
        names = _event_names(findings)
        assert "CloudTrailDisabled" in names
        assert "GuardDutyDisabled" in names

    @mock_aws
    def test_all_findings_have_required_fields(self):
        session = boto3.Session(region_name=REGION)
        findings = run_config_scan(session, REGION, ACCOUNT_ID)
        for f in findings:
            assert f.source == "config_scan"
            assert f.account_id == ACCOUNT_ID
            assert 0 <= f.severity <= 100
            assert f.risk_tier in ("low", "medium", "high", "critical")
            assert f.event_id  # non-empty, used for dedup


# ─── Lambda ──────────────────────────────────────────────────────────────

def _lambda_role(iam):
    import json
    return iam.create_role(RoleName="lambda-role", AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }))["Role"]["Arn"]


class TestScanLambda:
    @mock_aws
    def test_public_function_url_flagged(self):
        session = boto3.Session(region_name=REGION)
        iam = session.client("iam")
        role = _lambda_role(iam)
        lam = session.client("lambda", region_name=REGION)
        lam.create_function(FunctionName="public-url-fn", Runtime="python3.12", Role=role,
                            Handler="index.handler", Code={"ZipFile": b"x"})
        lam.create_function_url_config(FunctionName="public-url-fn", AuthType="NONE")

        findings = scan_lambda(session, REGION, ACCOUNT_ID)
        assert "LambdaFunctionURLPublic" in _event_names(findings)
        f = [x for x in findings if x.event_name == "LambdaFunctionURLPublic"][0]
        assert f.risk_tier == "critical"

    @mock_aws
    def test_iam_auth_function_url_not_flagged(self):
        session = boto3.Session(region_name=REGION)
        iam = session.client("iam")
        role = _lambda_role(iam)
        lam = session.client("lambda", region_name=REGION)
        lam.create_function(FunctionName="private-url-fn", Runtime="python3.12", Role=role,
                            Handler="index.handler", Code={"ZipFile": b"x"})
        lam.create_function_url_config(FunctionName="private-url-fn", AuthType="AWS_IAM")

        findings = scan_lambda(session, REGION, ACCOUNT_ID)
        assert "LambdaFunctionURLPublic" not in _event_names(findings)

    @mock_aws
    def test_no_function_url_not_flagged(self):
        session = boto3.Session(region_name=REGION)
        iam = session.client("iam")
        role = _lambda_role(iam)
        lam = session.client("lambda", region_name=REGION)
        lam.create_function(FunctionName="no-url-fn", Runtime="python3.12", Role=role,
                            Handler="index.handler", Code={"ZipFile": b"x"})

        findings = scan_lambda(session, REGION, ACCOUNT_ID)
        assert "LambdaFunctionURLPublic" not in _event_names(findings)

    @mock_aws
    def test_public_resource_policy_flagged(self):
        session = boto3.Session(region_name=REGION)
        iam = session.client("iam")
        role = _lambda_role(iam)
        lam = session.client("lambda", region_name=REGION)
        lam.create_function(FunctionName="public-policy-fn", Runtime="python3.12", Role=role,
                            Handler="index.handler", Code={"ZipFile": b"x"})
        lam.add_permission(FunctionName="public-policy-fn", StatementId="public-invoke",
                           Action="lambda:InvokeFunction", Principal="*")

        findings = scan_lambda(session, REGION, ACCOUNT_ID)
        assert "LambdaFunctionPolicyPublic" in _event_names(findings)

    @mock_aws
    def test_scoped_resource_policy_not_flagged(self):
        session = boto3.Session(region_name=REGION)
        iam = session.client("iam")
        role = _lambda_role(iam)
        lam = session.client("lambda", region_name=REGION)
        lam.create_function(FunctionName="scoped-policy-fn", Runtime="python3.12", Role=role,
                            Handler="index.handler", Code={"ZipFile": b"x"})
        lam.add_permission(FunctionName="scoped-policy-fn", StatementId="scoped-invoke",
                           Action="lambda:InvokeFunction", Principal="123456789012")

        findings = scan_lambda(session, REGION, ACCOUNT_ID)
        assert "LambdaFunctionPolicyPublic" not in _event_names(findings)

    @mock_aws
    def test_deprecated_runtime_flagged(self):
        session = boto3.Session(region_name=REGION)
        iam = session.client("iam")
        role = _lambda_role(iam)
        lam = session.client("lambda", region_name=REGION)
        lam.create_function(FunctionName="old-fn", Runtime="python3.7", Role=role,
                            Handler="index.handler", Code={"ZipFile": b"x"})

        findings = scan_lambda(session, REGION, ACCOUNT_ID)
        assert "LambdaDeprecatedRuntime" in _event_names(findings)

    @mock_aws
    def test_current_runtime_not_flagged(self):
        session = boto3.Session(region_name=REGION)
        iam = session.client("iam")
        role = _lambda_role(iam)
        lam = session.client("lambda", region_name=REGION)
        lam.create_function(FunctionName="new-fn", Runtime="python3.12", Role=role,
                            Handler="index.handler", Code={"ZipFile": b"x"})

        findings = scan_lambda(session, REGION, ACCOUNT_ID)
        assert "LambdaDeprecatedRuntime" not in _event_names(findings)

    @mock_aws
    def test_no_functions_returns_empty(self):
        session = boto3.Session(region_name=REGION)
        findings = scan_lambda(session, REGION, ACCOUNT_ID)
        assert findings == []


# ─── DynamoDB ────────────────────────────────────────────────────────────

class TestScanDynamoDB:
    @mock_aws
    def test_defaults_flag_pitr_and_deletion_protection(self):
        session = boto3.Session(region_name=REGION)
        ddb = session.client("dynamodb", region_name=REGION)
        ddb.create_table(
            TableName="default-table",
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        findings = scan_dynamodb(session, REGION, ACCOUNT_ID)
        names = _event_names(findings)
        assert "DynamoDBPITRDisabled" in names
        assert "DynamoDBDeletionProtectionDisabled" in names

    @mock_aws
    def test_secured_table_not_flagged(self):
        session = boto3.Session(region_name=REGION)
        ddb = session.client("dynamodb", region_name=REGION)
        ddb.create_table(
            TableName="secure-table",
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
            DeletionProtectionEnabled=True,
        )
        ddb.update_continuous_backups(
            TableName="secure-table",
            PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True},
        )
        findings = scan_dynamodb(session, REGION, ACCOUNT_ID)
        names = _event_names(findings)
        assert "DynamoDBPITRDisabled" not in names
        assert "DynamoDBDeletionProtectionDisabled" not in names

    @mock_aws
    def test_no_tables_returns_empty(self):
        session = boto3.Session(region_name=REGION)
        findings = scan_dynamodb(session, REGION, ACCOUNT_ID)
        assert findings == []


# ─── ELB ─────────────────────────────────────────────────────────────────

def _make_alb(session, name, scheme="internet-facing"):
    ec2 = session.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    s1 = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24", AvailabilityZone=f"{REGION}a")["Subnet"]["SubnetId"]
    s2 = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.2.0/24", AvailabilityZone=f"{REGION}b")["Subnet"]["SubnetId"]
    elbv2 = session.client("elbv2", region_name=REGION)
    lb = elbv2.create_load_balancer(
        Name=name, Subnets=[s1, s2], Scheme=scheme, Type="application",
    )["LoadBalancers"][0]
    tg = elbv2.create_target_group(Name=f"{name}-tg", Protocol="HTTP", Port=80, VpcId=vpc)["TargetGroups"][0]
    return lb, tg, elbv2


class TestScanELB:
    @mock_aws
    def test_internet_facing_http_only_flagged(self):
        session = boto3.Session(region_name=REGION)
        lb, tg, elbv2 = _make_alb(session, "http-only-alb")
        elbv2.create_listener(LoadBalancerArn=lb["LoadBalancerArn"], Protocol="HTTP", Port=80,
                             DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}])

        findings = scan_elb(session, REGION, ACCOUNT_ID)
        assert "ELBNoHTTPSListener" in _event_names(findings)

    @mock_aws
    def test_internet_facing_with_https_not_flagged_for_tls(self):
        session = boto3.Session(region_name=REGION)
        acm = session.client("acm", region_name=REGION)
        cert_arn = acm.request_certificate(DomainName="example.com")["CertificateArn"]
        lb, tg, elbv2 = _make_alb(session, "https-alb")
        elbv2.create_listener(LoadBalancerArn=lb["LoadBalancerArn"], Protocol="HTTPS", Port=443,
                             DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}],
                             Certificates=[{"CertificateArn": cert_arn}])

        findings = scan_elb(session, REGION, ACCOUNT_ID)
        assert "ELBNoHTTPSListener" not in _event_names(findings)

    @mock_aws
    def test_internal_lb_not_flagged_for_https(self):
        session = boto3.Session(region_name=REGION)
        lb, tg, elbv2 = _make_alb(session, "internal-alb", scheme="internal")
        elbv2.create_listener(LoadBalancerArn=lb["LoadBalancerArn"], Protocol="HTTP", Port=80,
                             DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}])

        findings = scan_elb(session, REGION, ACCOUNT_ID)
        assert "ELBNoHTTPSListener" not in _event_names(findings)

    @mock_aws
    def test_access_logs_disabled_by_default(self):
        session = boto3.Session(region_name=REGION)
        lb, tg, elbv2 = _make_alb(session, "no-logs-alb")
        findings = scan_elb(session, REGION, ACCOUNT_ID)
        assert "ELBAccessLogsDisabled" in _event_names(findings)

    @mock_aws
    def test_access_logs_enabled_not_flagged(self):
        session = boto3.Session(region_name=REGION)
        s3 = session.client("s3")
        s3.create_bucket(Bucket="lb-logs-bucket")
        lb, tg, elbv2 = _make_alb(session, "with-logs-alb")
        elbv2.modify_load_balancer_attributes(LoadBalancerArn=lb["LoadBalancerArn"], Attributes=[
            {"Key": "access_logs.s3.enabled", "Value": "true"},
            {"Key": "access_logs.s3.bucket", "Value": "lb-logs-bucket"},
        ])
        findings = scan_elb(session, REGION, ACCOUNT_ID)
        assert "ELBAccessLogsDisabled" not in _event_names(findings)

    @mock_aws
    def test_no_load_balancers_returns_empty(self):
        session = boto3.Session(region_name=REGION)
        findings = scan_elb(session, REGION, ACCOUNT_ID)
        assert findings == []


# ─── WAF ─────────────────────────────────────────────────────────────────

class TestScanWAF:
    @mock_aws
    def test_internet_facing_alb_without_waf_flagged(self):
        session = boto3.Session(region_name=REGION)
        _make_alb(session, "unprotected-alb")
        findings = scan_waf(session, REGION, ACCOUNT_ID)
        assert "ALBWithoutWAF" in _event_names(findings)

    @mock_aws
    def test_internet_facing_alb_with_waf_not_flagged(self):
        session = boto3.Session(region_name=REGION)
        lb, tg, elbv2 = _make_alb(session, "protected-alb")
        waf = session.client("wafv2", region_name=REGION)
        acl = waf.create_web_acl(
            Name="protect-acl", Scope="REGIONAL", DefaultAction={"Allow": {}},
            VisibilityConfig={"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": "m"},
            Rules=[],
        )["Summary"]
        waf.associate_web_acl(WebACLArn=acl["ARN"], ResourceArn=lb["LoadBalancerArn"])

        findings = scan_waf(session, REGION, ACCOUNT_ID)
        assert "ALBWithoutWAF" not in _event_names(findings)

    @mock_aws
    def test_internal_alb_not_flagged_for_missing_waf(self):
        session = boto3.Session(region_name=REGION)
        _make_alb(session, "internal-noattach-alb", scheme="internal")
        findings = scan_waf(session, REGION, ACCOUNT_ID)
        assert "ALBWithoutWAF" not in _event_names(findings)

    @mock_aws
    def test_web_acl_with_no_rules_flagged(self):
        session = boto3.Session(region_name=REGION)
        waf = session.client("wafv2", region_name=REGION)
        waf.create_web_acl(
            Name="empty-acl", Scope="REGIONAL", DefaultAction={"Allow": {}},
            VisibilityConfig={"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": "m"},
            Rules=[],
        )
        findings = scan_waf(session, REGION, ACCOUNT_ID)
        assert "WAFWebACLNoRules" in _event_names(findings)

    @mock_aws
    def test_web_acl_with_rules_not_flagged(self):
        session = boto3.Session(region_name=REGION)
        waf = session.client("wafv2", region_name=REGION)
        waf.create_web_acl(
            Name="rules-acl", Scope="REGIONAL", DefaultAction={"Allow": {}},
            VisibilityConfig={"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": "m"},
            Rules=[{
                "Name": "block-bad-bots", "Priority": 0,
                "Action": {"Block": {}},
                "Statement": {"ByteMatchStatement": {
                    "SearchString": "bad-bot", "FieldToMatch": {"SingleHeader": {"Name": "user-agent"}},
                    "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                    "PositionalConstraint": "CONTAINS",
                }},
                "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": "r1"},
            }],
        )
        findings = scan_waf(session, REGION, ACCOUNT_ID)
        assert "WAFWebACLNoRules" not in _event_names(findings)

    @mock_aws
    def test_no_resources_returns_empty(self):
        session = boto3.Session(region_name=REGION)
        findings = scan_waf(session, REGION, ACCOUNT_ID)
        assert findings == []
