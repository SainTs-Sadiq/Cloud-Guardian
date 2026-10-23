"""
AWS Account onboarding and management routes.

POST /accounts                  Connect a new AWS account
GET  /accounts                  List connected accounts
GET  /accounts/{id}             Account detail + status
DELETE /accounts/{id}           Remove an account
POST /accounts/{id}/verify      Test role assumption (validates setup)
GET  /accounts/{id}/setup-guide Return IAM role setup instructions for this account
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from core.audit import audit_log
from core.auth import CurrentUser, get_current_user, require_min_role, require_role
from core.aws_session import (
    generate_external_id, validate_role_arn, get_session_for_account, CG_AWS_ACCOUNT_ID,
)
from db.engine import get_db
from db.models.aws_account import AWSAccount, AccountStatus
from infra.cloudformation import generate_onboarding_template

import asyncio
import logging
logger = logging.getLogger("cloud_guardian.api.accounts")

router = APIRouter(prefix="/accounts", tags=["AWS Accounts"])


class ConnectAccountRequest(BaseModel):
    aws_account_id: str = Field(..., min_length=12, max_length=12,
                                 pattern=r"^\d{12}$", description="12-digit AWS account ID")
    display_name: str = Field(..., min_length=1, max_length=255)
    role_arn: str = Field(..., pattern=r"^arn:aws:iam::\d{12}:role/[A-Za-z0-9+=,.@_-]{1,128}$",
                          description="ARN of the read-only detection role Cloud Guardian should assume")
    auto_remediation_role_arn: Optional[str] = Field(default=None,
        pattern=r"^arn:aws:iam::\d{12}:role/[A-Za-z0-9+=,.@_-]{1,128}$",
        description="Low-risk auto-remediation role; must not grant destructive permissions")
    destructive_remediation_role_arn: Optional[str] = Field(default=None,
        pattern=r"^arn:aws:iam::\d{12}:role/[A-Za-z0-9+=,.@_-]{1,128}$",
        description="Destructive remediation role; used only for explicitly approved actions")
    primary_region: str = Field(default="us-east-1", pattern=r"^[a-z]{2}(-gov)?-[a-z]+-\d{1}$")
    additional_regions: Optional[list[str]] = Field(default=None,
        description="Extra regions; each must be a valid AWS region name")

class AccountResponse(BaseModel):
    id: str
    aws_account_id: str
    display_name: str
    role_arn: str
    auto_remediation_role_arn: Optional[str] = None
    destructive_remediation_role_arn: Optional[str] = None
    primary_region: str
    additional_regions: Optional[list[str]]
    status: str
    last_scan_at: Optional[str]
    last_error: Optional[str]
    guardduty_enabled: bool
    cloudtrail_enabled: bool
    created_at: str

class SetupGuideResponse(BaseModel):
    aws_account_id: str
    external_id: str
    cg_aws_account_id: str
    role_name: str
    trust_policy: dict
    inline_policy_url: str
    instructions: list[str]

class CloudFormationTemplateResponse(BaseModel):
    aws_account_id: str
    external_id: str
    role_name: str
    filename: str
    template: dict
    console_create_stack_url: str


def _to_response(account: AWSAccount) -> AccountResponse:
    return AccountResponse(
        id=account.id, aws_account_id=account.aws_account_id,
        display_name=account.display_name, role_arn=account.role_arn,
        auto_remediation_role_arn=account.auto_remediation_role_arn,
        destructive_remediation_role_arn=account.destructive_remediation_role_arn,
        primary_region=account.primary_region,
        additional_regions=account.additional_regions,
        status=account.status,
        last_scan_at=account.last_scan_at.isoformat() if account.last_scan_at else None,
        last_error=account.last_error,
        guardduty_enabled=account.guardduty_enabled,
        cloudtrail_enabled=account.cloudtrail_enabled,
        created_at=account.created_at.isoformat(),
    )


@router.get("/setup-guide", response_model=SetupGuideResponse)
async def get_setup_guide(
    aws_account_id: str,
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Return the IAM role setup instructions for connecting an AWS account.

    The customer deploys this role in their account, then calls POST /accounts.
    Includes the trust policy JSON with our AWS account ID and a unique external ID.
    """
    cg_account_id = CG_AWS_ACCOUNT_ID or "<YOUR_CG_ACCOUNT_ID>"
    external_id = generate_external_id(current_user.organization_id)
    role_name = "CloudGuardianDetectionRole"

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{cg_account_id}:root"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"sts:ExternalId": external_id}},
        }],
    }

    return SetupGuideResponse(
        aws_account_id=aws_account_id,
        external_id=external_id,
        cg_aws_account_id=cg_account_id,
        role_name=role_name,
        trust_policy=trust_policy,
        inline_policy_url="https://docs.cloudguardian.io/iam-policy",
        instructions=[
            f"1. In your AWS account ({aws_account_id}), go to IAM → Roles → Create Role",
            f"2. Select 'Another AWS account' and enter: {cg_account_id}",
            f"3. Check 'Require external ID' and enter: {external_id}",
            "4. Attach the CloudGuardianDetection managed policy (see inline_policy_url)",
            f"5. Name the role: {role_name}",
            f"6. Copy the role ARN and use it in POST /accounts",
            "7. Call POST /accounts/{id}/verify to confirm the connection",
        ],
    )


@router.get("/cloudformation-template", response_model=CloudFormationTemplateResponse)
async def get_cloudformation_template(
    aws_account_id: str,
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Generate a ready-to-deploy CloudFormation template for the
    CloudGuardianDetectionRole — trust policy, external ID, and the
    read-only detection policy are already filled in, so the customer
    just uploads it in their own CloudFormation console.

    Uses the same deterministic external ID as GET /setup-guide, so
    either path (CloudFormation or manual IAM console) lands on a role
    that Cloud Guardian can actually assume.
    """
    import os
    cg_account_id = CG_AWS_ACCOUNT_ID or "<YOUR_CG_ACCOUNT_ID>"
    external_id = generate_external_id(current_user.organization_id)
    role_name = "CloudGuardianDetectionRole"

    template = generate_onboarding_template(
        cg_account_id=cg_account_id, external_id=external_id, role_name=role_name,
    )

    return CloudFormationTemplateResponse(
        aws_account_id=aws_account_id,
        external_id=external_id,
        role_name=role_name,
        filename=f"cloud-guardian-{aws_account_id}.template.json",
        template=template,
        console_create_stack_url="https://console.aws.amazon.com/cloudformation/home#/stacks/create/review",
    )


@router.post("", response_model=AccountResponse, status_code=201)
async def connect_account(
    request: Request,
    body: ConnectAccountRequest,
    current_user: CurrentUser = Depends(require_min_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    """
    Connect a new AWS account to the org.
    Requires admin or owner role.
    Validates role ARN format; actual role assumption tested via POST /accounts/{id}/verify.
    """
    if body.additional_regions and len(body.additional_regions) > 10:
        raise HTTPException(status_code=422, detail="At most 10 additional regions")

    if not validate_role_arn(body.role_arn):
        raise HTTPException(status_code=422,
                            detail="Invalid role ARN format. Expected: arn:aws:iam::<account_id>:role/<name>")


    dup_result = await db.execute(
        select(AWSAccount).where(
            AWSAccount.organization_id == current_user.organization_id,
            AWSAccount.aws_account_id == body.aws_account_id,
        )
    )
    if dup_result.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409,
                            detail=f"AWS account {body.aws_account_id} is already connected")


    result = await db.execute(
        select(AWSAccount).where(AWSAccount.organization_id == current_user.organization_id)
    )
    existing = list(result.scalars().all())


    from db.models.organization import Organization
    org = await db.get(Organization, current_user.organization_id)
    if org and len(existing) >= org.max_aws_accounts:
        raise HTTPException(
            status_code=402,
            detail=f"Your plan allows {org.max_aws_accounts} AWS account(s). "
                   f"Upgrade your plan to connect more accounts."
        )

    external_id = generate_external_id(current_user.organization_id)
    account = AWSAccount(
        organization_id=current_user.organization_id,
        aws_account_id=body.aws_account_id,
        display_name=body.display_name,
        role_arn=body.role_arn,
        auto_remediation_role_arn=body.auto_remediation_role_arn,
        destructive_remediation_role_arn=body.destructive_remediation_role_arn,
        external_id=external_id,
        primary_region=body.primary_region,
        additional_regions=body.additional_regions,
        status=AccountStatus.pending,
    )
    db.add(account)
    await db.flush()
    await db.commit()

    logger.info(f"Account connected: {body.aws_account_id} for org {current_user.organization_id}")
    await audit_log(db, organization_id=current_user.organization_id, user_id=current_user.id,
        action="account.connected", resource_type="aws_account", resource_id=str(account.id),
        detail=f"aws_account_id={body.aws_account_id} role={body.role_arn}",
        ip_address=request.client.host if request.client else None,
        user_agent=(request.headers.get("user-agent") or "")[:255], commit=True)
    return _to_response(account)


@router.get("", response_model=list[AccountResponse])
async def list_accounts(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all AWS accounts connected to the org."""
    result = await db.execute(
        select(AWSAccount).where(AWSAccount.organization_id == current_user.organization_id)
    )
    return [_to_response(a) for a in result.scalars().all()]


@router.get("/{account_id}", response_model=AccountResponse)
async def get_account(
    account_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(AWSAccount).where(
            AWSAccount.id == account_id,
            AWSAccount.organization_id == current_user.organization_id,
        )
    )
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    return _to_response(account)


@router.post("/{account_id}/verify", response_model=dict)
async def verify_account(
    account_id: str,
    current_user: CurrentUser = Depends(require_min_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    """
    Verify the IAM role can be assumed successfully.
    Updates account status to 'active' or 'error' accordingly.
    """
    result = await db.execute(
        select(AWSAccount).where(
            AWSAccount.id == account_id,
            AWSAccount.organization_id == current_user.organization_id,
        )
    )
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    def _verify_sync():
        """Synchronous AWS checks — run via to_thread so the event loop is not blocked."""
        session = get_session_for_account(
            role_arn=account.role_arn,
            external_id=account.external_id,
            region=account.primary_region,
            org_id=current_user.organization_id,
            aws_account_id=account.aws_account_id,
        )
        sts = session.client("sts")
        identity = sts.get_caller_identity()

        ct = session.client("cloudtrail", region_name=account.primary_region)
        ct.lookup_events(MaxResults=1)

        guardduty_enabled = False
        try:
            gd = session.client("guardduty", region_name=account.primary_region)
            detectors = gd.list_detectors().get("DetectorIds", [])
            guardduty_enabled = len(detectors) > 0
        except Exception:
            guardduty_enabled = False
        return {
            "guardduty_enabled": guardduty_enabled,
            "aws_account_id": identity.get("Account"),
            "assumed_arn": identity.get("Arn"),
        }

    try:
        verify_result = await asyncio.to_thread(_verify_sync)
        account.cloudtrail_enabled = True
        account.guardduty_enabled = verify_result["guardduty_enabled"]
        account.status = AccountStatus.active
        account.last_error = None
        identity = {
            "Account": verify_result["aws_account_id"],
            "Arn": verify_result["assumed_arn"],
        }
        await db.commit()

        # Kick off the first scan automatically now that the role is live.
        # Best-effort: a scan-dispatch hiccup shouldn't fail verification,
        # since the role itself has already been confirmed working.
        scan_outcome = {"status": "skipped", "reason": "dispatch_error"}
        try:
            from api.routes.scan import dispatch_scan_for_org
            scan_outcome = await dispatch_scan_for_org(
                org_id=current_user.organization_id, db=db, minutes=60, use_ml=True,
                trigger="verification",
            )
        except Exception as e:
            logger.warning(f"Could not auto-dispatch first scan for account {account_id}: {e}")

        return {
            "status": "verified",
            "aws_account_id": identity.get("Account"),
            "assumed_arn": identity.get("Arn"),
            "cloudtrail_accessible": True,
            "guardduty_enabled": account.guardduty_enabled,
            "first_scan": scan_outcome,
        }

    except PermissionError as e:
        account.status = AccountStatus.error
        account.last_error = str(e)
        await db.commit()
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        account.status = AccountStatus.error
        account.last_error = str(e)
        await db.commit()
        raise HTTPException(status_code=500, detail=f"Verification failed: {e}")


@router.delete("/{account_id}", status_code=204)
async def remove_account(
    account_id: str,
    current_user: CurrentUser = Depends(require_role("owner")),
    db: AsyncSession = Depends(get_db),
):
    """Remove an AWS account. Requires owner role. Does not delete historical incidents."""
    result = await db.execute(
        select(AWSAccount).where(
            AWSAccount.id == account_id,
            AWSAccount.organization_id == current_user.organization_id,
        )
    )
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    await db.delete(account)
    await db.commit()
