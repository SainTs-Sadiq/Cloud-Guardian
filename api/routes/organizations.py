"""
Organization settings — scheduler configuration (scan cadence) and
notifications (webhook URL). Read available to any authenticated member;
changes require admin or owner.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from core.auth import CurrentUser, get_current_user, require_min_role
from db.engine import get_db
from db.models.organization import Organization, ScanFrequency
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter(prefix="/organizations", tags=["Organizations"])


class OrgSettingsResponse(BaseModel):
    id: str
    name: str
    plan: str
    scan_frequency: str
    notification_webhook_url: Optional[str] = None


class OrgSettingsUpdateRequest(BaseModel):
    scan_frequency: Optional[str] = Field(
        default=None, description="manual | daily | hourly",
    )
    notification_webhook_url: Optional[str] = Field(
        default=None, description="Webhook URL for scan-completion notifications. "
                                   "Pass an empty string to clear it.",
    )


@router.get("/settings", response_model=OrgSettingsResponse)
async def get_org_settings(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org = await db.get(Organization, current_user.organization_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return OrgSettingsResponse(
        id=org.id, name=org.name, plan=org.plan,
        scan_frequency=org.scan_frequency,
        notification_webhook_url=org.notification_webhook_url,
    )


@router.patch("/settings", response_model=OrgSettingsResponse)
async def update_org_settings(
    request: OrgSettingsUpdateRequest,
    current_user: CurrentUser = Depends(require_min_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    """Update scan cadence and/or notification webhook. Requires admin or owner."""
    org = await db.get(Organization, current_user.organization_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    if request.scan_frequency is not None:
        if request.scan_frequency not in (f.value for f in ScanFrequency):
            raise HTTPException(
                status_code=422,
                detail=f"scan_frequency must be one of: {[f.value for f in ScanFrequency]}",
            )
        org.scan_frequency = request.scan_frequency

    if request.notification_webhook_url is not None:
        org.notification_webhook_url = request.notification_webhook_url or None

    await db.commit()
    return OrgSettingsResponse(
        id=org.id, name=org.name, plan=org.plan,
        scan_frequency=org.scan_frequency,
        notification_webhook_url=org.notification_webhook_url,
    )
