"""
Auth routes — register, login, token refresh, API key management.

POST /auth/register         Create a new org + owner user
POST /auth/login            Email/password -> access + refresh tokens
POST /auth/refresh          Refresh token -> new access token
POST /auth/api-keys         Create a new API key
GET  /auth/api-keys         List API keys for current user
DELETE /auth/api-keys/{id}  Revoke an API key
"""
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Request
from jose import JWTError
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.ext.asyncio import AsyncSession

from core.audit import audit_log
from core.security import (
    create_access_token, create_refresh_token, decode_token,
    generate_api_key, hash_password, validate_password_strength, verify_password,
)
from db.engine import get_db
from db.models.user import APIKey, UserRole
from db.repositories.organization_repo import OrganizationRepository
from db.repositories.user_repo import UserRepository

import logging
logger = logging.getLogger("cloud_guardian.api.auth")

router = APIRouter(prefix="/auth", tags=["Auth"])


class RegisterRequest(BaseModel):
    org_name: str = Field(..., min_length=2, max_length=255)
    org_slug: str = Field(..., min_length=2, max_length=100, pattern=r"^[a-z0-9-]+$")
    email: EmailStr
    full_name: str = Field(..., min_length=2, max_length=255)
    password: str = Field(..., min_length=10)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 1800


class RefreshRequest(BaseModel):
    refresh_token: str


class APIKeyCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100,
                      description="Human-readable name e.g. 'github-actions'")


class APIKeyResponse(BaseModel):
    id: str
    name: str
    key_prefix: str
    created_at: str
    raw_key: Optional[str] = None


@router.post("/register", response_model=TokenResponse, status_code=201)
async def register(body: RegisterRequest, db: AsyncSession = Depends(get_db)):
    """
    Create a new organization and its first owner user.

    The org slug must be globally unique (e.g. "acme-corp"). Used
    in future multi-tenant API path scoping.
    """
    errors = validate_password_strength(body.password)
    if errors:
        raise HTTPException(status_code=422, detail={"password_errors": errors})

    org_repo = OrganizationRepository(db)
    user_repo = UserRepository(db)


    existing_org = await org_repo.get_by_slug(body.org_slug)
    if existing_org:
        raise HTTPException(status_code=409, detail=f"Slug '{body.org_slug}' is already taken")


    existing_user = await user_repo.get_by_email(body.email)
    if existing_user:
        raise HTTPException(status_code=409, detail="An account with this email already exists")

    org = await org_repo.create(
        name=body.org_name, slug=body.org_slug, billing_email=body.email,
    )
    user = await user_repo.create(
        organization_id=org.id, email=body.email, full_name=body.full_name,
        hashed_password=hash_password(body.password), role=UserRole.owner,
    )

    logger.info(f"New org registered: {org.slug} (owner: {user.email})")
    await audit_log(db, organization_id=org.id, user_id=user.id,
        action="auth.register", resource_type="organization", resource_id=org.id,
        detail=f"org slug={org.slug}", commit=True)

    return TokenResponse(
        access_token=create_access_token(user.id, org.id, user.role),
        refresh_token=create_refresh_token(user.id),
    )


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    user_repo = UserRepository(db)
    user = await user_repo.get_by_email(body.email)

    if not user or not verify_password(body.password, user.hashed_password):
        if user:  # correct email, wrong password — worth an audit row
            await audit_log(db, organization_id=user.organization_id, user_id=user.id,
                action="auth.login_failed", resource_type="user", resource_id=user.id,
                detail="Incorrect password", ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"), commit=True)
        raise HTTPException(
            status_code=401,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is deactivated")

    await user_repo.update_last_login(user.id)
    await audit_log(db, organization_id=user.organization_id, user_id=user.id,
        action="auth.login", resource_type="user", resource_id=user.id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"), commit=True)

    return TokenResponse(
        access_token=create_access_token(user.id, user.organization_id, user.role),
        refresh_token=create_refresh_token(user.id),
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(body: RefreshRequest, db: AsyncSession = Depends(get_db)):
    try:
        payload = decode_token(body.refresh_token)
        if payload.get("type") != "refresh":
            raise JWTError("Not a refresh token")
        user_id = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")


    from sqlalchemy import select
    from db.models.user import User
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or deactivated")

    return TokenResponse(
        access_token=create_access_token(user.id, user.organization_id, user.role),
        refresh_token=create_refresh_token(user.id),
    )


@router.post("/api-keys", response_model=APIKeyResponse, status_code=201)
async def create_api_key(
    body: APIKeyCreateRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(lambda: None),
):
    """
    Create a new API key for the current user.
    The raw key is returned ONCE — store it securely, it cannot be retrieved again.
    """
    raise HTTPException(
        status_code=501,
        detail="API key creation requires auth middleware — implement get_current_user dependency first"
    )


@router.get("/api-keys", response_model=list[APIKeyResponse])
async def list_api_keys(db: AsyncSession = Depends(get_db)):
    """List API keys for the current authenticated user (prefixes only, never raw keys)."""
    raise HTTPException(status_code=501, detail="Requires auth middleware")


@router.delete("/api-keys/{key_id}", status_code=204)
async def revoke_api_key(key_id: str, db: AsyncSession = Depends(get_db)):
    """Revoke an API key — immediately invalidates all requests using it."""
    raise HTTPException(status_code=501, detail="Requires auth middleware")
