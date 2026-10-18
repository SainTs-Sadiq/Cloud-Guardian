"""
get_current_user dependency — the central auth gate for every protected route.

Supports two authentication methods:
  1. JWT Bearer token  (Authorization: Bearer <token>)
  2. API key           (X-API-Key: cg_live_<...>)

Usage in routes:
    @router.get("/something")
    async def my_route(current_user: CurrentUser = Depends(get_current_user)):
        # current_user.id, current_user.organization_id, current_user.role all available
        ...

Role-gating via require_role():
    @router.post("/admin-only")
    async def admin_route(current_user: CurrentUser = Depends(require_role("admin", "owner"))):
        ...
"""
import logging
from datetime import datetime, timezone
from typing import Optional
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, APIKeyHeader
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.security import decode_token, verify_api_key
from db.engine import get_db
from db.models.user import APIKey, User, UserRole

logger = logging.getLogger("cloud_guardian.auth")


bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


@dataclass
class CurrentUser:
    """
    Authenticated user context injected into route handlers.
    Carries everything routes need without extra DB queries.
    """
    id: str
    organization_id: str
    email: str
    full_name: str
    role: str
    is_active: bool


async def get_current_user(
    bearer: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
    api_key: Optional[str] = Security(api_key_header),
    db: AsyncSession = Depends(get_db),
) -> CurrentUser:
    """
    Authenticate the request via JWT or API key.

    Raises HTTP 401 if neither credential is present or both are invalid.
    Raises HTTP 403 if the user's account is deactivated.
    """

    if bearer and bearer.credentials:
        return await _auth_via_jwt(bearer.credentials, db)


    if api_key:
        return await _auth_via_api_key(api_key, db)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Provide a Bearer token or X-API-Key header.",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_user_optional(
    bearer: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
    api_key: Optional[str] = Security(api_key_header),
    db: AsyncSession = Depends(get_db),
) -> Optional[CurrentUser]:
    """
    Like get_current_user but returns None instead of raising 401.
    Use for routes that work both authenticated and unauthenticated.
    """
    try:
        return await get_current_user(bearer=bearer, api_key=api_key, db=db)
    except HTTPException:
        return None


ROLE_HIERARCHY = {
    UserRole.viewer:   0,
    UserRole.analyst:  1,
    UserRole.admin:    2,
    UserRole.owner:    3,
}


def require_role(*allowed_roles: str):
    """
    Dependency factory — gates a route to users with specific roles.

    Usage:
        Depends(require_role("admin", "owner"))   # either admin or owner
        Depends(require_role("analyst"))           # analyst or above
    """
    async def _check(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This action requires one of: {', '.join(allowed_roles)}. "
                       f"Your role is '{current_user.role}'.",
            )
        return current_user
    return _check


def require_min_role(min_role: str):
    """
    Dependency factory — gates a route to users at or above a minimum role level.

    Usage:
        Depends(require_min_role("analyst"))  # analyst, admin, or owner
    """
    min_rank = ROLE_HIERARCHY.get(UserRole(min_role), 0)

    async def _check(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        user_rank = ROLE_HIERARCHY.get(UserRole(current_user.role), 0)
        if user_rank < min_rank:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This action requires '{min_role}' role or above. "
                       f"Your role is '{current_user.role}'.",
            )
        return current_user
    return _check


CurrentUser_t = CurrentUser


async def _auth_via_jwt(token: str, db: AsyncSession) -> CurrentUser:
    """Validate JWT and return the authenticated user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token. Please log in again.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_token(token)
        if payload.get("type") != "access":
            raise credentials_exception
        user_id: str = payload.get("sub")
        organization_id: str = payload.get("org")
        if not user_id or not organization_id:
            raise credentials_exception
    except JWTError:
        raise credentials_exception


    result = await db.execute(
        select(User).where(User.id == user_id, User.organization_id == organization_id)
    )
    user = result.scalar_one_or_none()

    if user is None:
        raise credentials_exception

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account has been deactivated. Contact your organization admin.",
        )

    return CurrentUser(
        id=user.id,
        organization_id=user.organization_id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        is_active=user.is_active,
    )


async def _auth_via_api_key(raw_key: str, db: AsyncSession) -> CurrentUser:
    """Validate an API key and return the authenticated user."""
    invalid_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not raw_key.startswith("cg_live_"):
        raise invalid_exception


    prefix = raw_key[:12]
    result = await db.execute(
        select(APIKey).where(APIKey.key_prefix == prefix, APIKey.is_active == True)
    )
    candidates = result.scalars().all()

    matched_key = None
    for candidate in candidates:
        if verify_api_key(raw_key, candidate.hashed_key):
            matched_key = candidate
            break

    if not matched_key:
        raise invalid_exception


    if matched_key.expires_at and matched_key.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key has expired.",
        )


    try:
        matched_key.last_used_at = datetime.now(timezone.utc)
        await db.flush()
    except Exception as e:
        logger.warning(f"Failed to update API key last_used_at: {e}")


    result = await db.execute(
        select(User).where(User.id == matched_key.user_id)
    )
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API key owner account is deactivated.",
        )

    return CurrentUser(
        id=user.id,
        organization_id=user.organization_id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        is_active=user.is_active,
    )
