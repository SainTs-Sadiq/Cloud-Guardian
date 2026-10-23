"""Audit logging helper — one call per security-sensitive action."""
import logging
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("cloud_guardian.audit")

async def audit_log(
    db: AsyncSession,
    *,
    organization_id: str,
    user_id: str | None,
    action: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
    detail: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    commit: bool = False,
):
    """Append an AuditLog row. Never raises — a logging failure must not
    fail the user's action (we log the error instead)."""
    from db.models.audit import AuditLog
    try:
        db.add(AuditLog(
            organization_id=organization_id, user_id=user_id, action=action,
            resource_type=resource_type, resource_id=resource_id, detail=detail,
            ip_address=ip_address, user_agent=user_agent,
        ))
        if commit:
            await db.commit()
    except Exception:
        logger.exception(f"audit_log failed for action={action}")
        try:
            await db.rollback()
        except Exception:
            pass
