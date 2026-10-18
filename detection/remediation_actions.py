"""Concrete boto3 remediation action implementations."""
import json
import logging
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError
from config.settings import AWS

logger = logging.getLogger("cloud_guardian.remediation_actions")

def _client(service, region=None):
    kwargs = {}
    if AWS.profile: kwargs["profile_name"] = AWS.profile
    return boto3.Session(**kwargs).client(service, region_name=region or AWS.region)

def _username_from_arn(arn):
    if not arn or ":user/" not in arn: return None
    return arn.split(":user/")[-1]

def disable_access_key(alert):
    username = _username_from_arn(alert.actor_arn)
    key_id = alert.raw_event.get("responseElements", {}).get("accessKey", {}).get("accessKeyId")
    if not key_id or not username:
        return False, f"Could not determine access key ID / username. actor_arn={alert.actor_arn}"
    try:
        _client("iam").update_access_key(UserName=username, AccessKeyId=key_id, Status="Inactive")
        return True, (f"Disabled access key {key_id} for user {username}. "
                      f"Reverse: aws iam update-access-key --user-name {username} --access-key-id {key_id} --status Active")
    except ClientError as e:
        return False, f"Failed to disable access key {key_id}: {e}"

def detach_dangerous_policy(alert):
    params = alert.raw_event.get("requestParameters", {})
    policy_arn = params.get("policyArn")
    target_user = params.get("userName")
    target_role = params.get("roleName")
    if not policy_arn or not (target_user or target_role):
        return False, f"Could not determine policy ARN / target. params keys={list(params.keys())}"
    iam = _client("iam")
    try:
        if target_user:
            iam.detach_user_policy(UserName=target_user, PolicyArn=policy_arn)
            return True, f"Detached {policy_arn} from user {target_user}."
        else:
            iam.detach_role_policy(RoleName=target_role, PolicyArn=policy_arn)
            return True, f"Detached {policy_arn} from role {target_role}."
    except ClientError as e:
        return False, f"Failed to detach policy {policy_arn}: {e}"

def block_public_s3_access(alert):
    bucket = None
    for res in (alert.raw_event.get("resources") or []):
        if "S3" in str(res.get("type","")) or "S3" in str(res.get("ResourceType","")):
            bucket = res.get("name") or res.get("ResourceName"); break
    if not bucket:
        bucket = alert.raw_event.get("requestParameters", {}).get("bucketName")
    if not bucket:
        return False, "Could not determine S3 bucket name from event."
    try:
        _client("s3").put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
        return True, f"Applied S3 Block Public Access to bucket '{bucket}'."
    except ClientError as e:
        return False, f"Failed to block public access on '{bucket}': {e}"

def revoke_session_token(alert):
    username = _username_from_arn(alert.actor_arn)
    if not username:
        return False, f"Could not extract IAM username from '{alert.actor_arn}' (may be a role)."
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*",
        "Condition": {"DateLessThan": {"aws:TokenIssueTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}}}]}
    try:
        _client("iam").put_user_policy(UserName=username, PolicyName="CloudGuardianSessionRevocation",
                                       PolicyDocument=json.dumps(policy))
        return True, f"Applied session revocation policy to user {username}."
    except ClientError as e:
        return False, f"Failed to revoke sessions for {username}: {e}"

def isolate_ec2_instance(alert):
    instance_id = None
    for res in (alert.raw_event.get("resources") or []):
        if "Instance" in str(res.get("type","")) or "Instance" in str(res.get("ResourceType","")):
            instance_id = res.get("name") or res.get("ResourceName"); break
    if not instance_id:
        items = alert.raw_event.get("responseElements", {}).get("instancesSet", {}).get("items", [])
        if items: instance_id = items[0].get("instanceId")
    if not instance_id:
        return False, "Could not determine EC2 instance ID from event."
    ec2 = _client("ec2", region=alert.region)
    try:
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        if not resp.get("Reservations"):
            return False, f"Instance {instance_id} not found."
        inst = resp["Reservations"][0]["Instances"][0]
        vpc_id = inst.get("VpcId")
        original_sgs = [sg["GroupId"] for sg in inst.get("SecurityGroups", [])]
        if not vpc_id:
            return False, f"Instance {instance_id} has no VPC."
        iso_sg = _get_or_create_isolation_sg(ec2, vpc_id)
        ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[iso_sg])
        return True, (f"Isolated instance {instance_id} into SG {iso_sg}. "
                      f"Original SGs: {original_sgs}. "
                      f"Reverse: aws ec2 modify-instance-attribute --instance-id {instance_id} --groups {' '.join(original_sgs)}")
    except ClientError as e:
        return False, f"Failed to isolate instance {instance_id}: {e}"

def _get_or_create_isolation_sg(ec2, vpc_id):
    name = "cloud-guardian-isolation"
    existing = ec2.describe_security_groups(Filters=[{"Name":"group-name","Values":[name]},{"Name":"vpc-id","Values":[vpc_id]}])
    if existing.get("SecurityGroups"):
        return existing["SecurityGroups"][0]["GroupId"]
    sg_id = ec2.create_security_group(GroupName=name, Description="Cloud Guardian: isolated instances", VpcId=vpc_id)["GroupId"]
    try:
        ec2.revoke_security_group_egress(GroupId=sg_id, IpPermissions=[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}])
    except ClientError as e:
        logger.warning(f"Could not revoke default egress on {sg_id}: {e}")
    return sg_id

def disable_lambda_function(alert):
    name = alert.raw_event.get("requestParameters", {}).get("functionName")
    if not name:
        for res in (alert.raw_event.get("resources") or []):
            if "lambda" in str(res.get("type","")).lower() or "lambda" in str(res.get("ResourceType","")).lower():
                name = res.get("name") or res.get("ResourceName"); break
    if not name:
        return False, "Could not determine Lambda function name from event."
    try:
        _client("lambda", region=alert.region).put_function_concurrency(FunctionName=name, ReservedConcurrentExecutions=0)
        return True, (f"Set reserved concurrency to 0 for Lambda '{name}' (disables invocation). "
                      f"Reverse: aws lambda delete-function-concurrency --function-name {name}")
    except ClientError as e:
        return False, f"Failed to disable Lambda '{name}': {e}"

def restore_cloudtrail_logging(alert):
    trail = alert.raw_event.get("requestParameters", {}).get("name")
    if alert.event_name == "StopLogging" and trail:
        try:
            _client("cloudtrail", region=alert.region).start_logging(Name=trail)
            return True, f"Restarted CloudTrail logging for trail '{trail}'."
        except ClientError as e:
            return False, f"Failed to restart logging for '{trail}': {e}"
    return False, (f"Event '{alert.event_name}' indicates infrastructure was deleted/modified beyond simple restart. "
                   "Requires manual investigation and possible infra re-deployment.")

def notify_only(alert):
    return True, "Notification sent (no automated action taken for this event type)."
