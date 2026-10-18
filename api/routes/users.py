"""
User + API key management routes.

GET    /users/me                   Current user profile
PUT    /users/me                   Update own profile
GET    /users                      List org users (admin/owner)
DELETE /users/{id}                 Deactivate user (owner only)

POST   /users/me/api-keys          Create API key
GET    /users/me/api-keys          List own API keys (prefixes only)
DELETE /users/me/api-keys/{key_id} Revoke an API key
"""
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.auth import CurrentUser, get_current_user, require_role, require_min_role
from core.security import generate_api_key, hash_password, validate_password_strength
from db.engine import get_db
from db.models.user import APIKey, User, UserRole
from db.repositories.user_repo import UserRepository

router = APIRouter(prefix="/users", tags=["Users"])


class UserProfile(BaseModel):
    id: str
    email: str
    full_name: str
    role: str
    organization_id: str
    is_active: bool
    last_login_at: Optional[str] = None
    created_at: str

class UpdateProfileRequest(BaseModel):
    full_name: Optional[str] = None
    current_password: Optional[str] = None
    new_password: Optional[str] = None

class APIKeyOut(BaseModel):
    id: str
    name: str
    key_prefix: str
    created_at: str
    last_used_at: Optional[str] = None
    expires_at: Optional[str] = None
    raw_key: Optional[str] = None

class CreateAPIKeyRequest(BaseModel):
    name: str


@router.get("/me", response_model=UserProfile)
async def get_me(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return the authenticated user's full profile."""
    result = await db.execute(select(User).where(User.id == current_user.id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return UserProfile(
        id=user.id, email=user.email, full_name=user.full_name,
        role=user.role, organization_id=user.organization_id,
        is_active=user.is_active,
        last_login_at=user.last_login_at.isoformat() if user.last_login_at else None,
        created_at=user.created_at.isoformat(),
    )


@router.put("/me", response_model=UserProfile)
async def update_me(
    body: UpdateProfileRequest,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update own profile — name and/or password."""
    from core.security import verify_password
    result = await db.execute(select(User).where(User.id == current_user.id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if body.full_name:
        user.full_name = body.full_name

    if body.new_password:
        if not body.current_password:
            raise HTTPException(status_code=400, detail="current_password required to set new_password")
        if not verify_password(body.current_password, user.hashed_password):
            raise HTTPException(status_code=401, detail="Current password is incorrect")
        errors = validate_password_strength(body.new_password)
        if errors:
            raise HTTPException(status_code=422, detail={"password_errors": errors})
        user.hashed_password = hash_password(body.new_password)

    await db.flush()

    return UserProfile(
        id=user.id, email=user.email, full_name=user.full_name,
        role=user.role, organization_id=user.organization_id,
        is_active=user.is_active,
        last_login_at=user.last_login_at.isoformat() if user.last_login_at else None,
        created_at=user.created_at.isoformat(),
    )


@router.get("", response_model=list[UserProfile])
async def list_users(
    current_user: CurrentUser = Depends(require_min_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    """List all active users in the organization (admin/owner only)."""
    repo = UserRepository(db)
    users = await repo.list_by_org(current_user.organization_id)
    return [UserProfile(
        id=u.id, email=u.email, full_name=u.full_name, role=u.role,
        organization_id=u.organization_id, is_active=u.is_active,
        last_login_at=u.last_login_at.isoformat() if u.last_login_at else None,
        created_at=u.created_at.isoformat(),
    ) for u in users]


@router.delete("/{user_id}", status_code=204)
async def deactivate_user(
    user_id: str,
    current_user: CurrentUser = Depends(require_role("owner")),
    db: AsyncSession = Depends(get_db),
):
    """Deactivate a user (owner only). Cannot deactivate yourself."""
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")
    repo = UserRepository(db)
    success = await repo.deactivate(user_id, current_user.organization_id)
    if not success:
        raise HTTPException(status_code=404, detail="User not found in your organization")


@router.post("/me/api-keys", response_model=APIKeyOut, status_code=201)
async def create_api_key(
    body: CreateAPIKeyRequest,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Create a new API key for the current user.
    The raw key is returned ONCE — store it securely. It cannot be retrieved again.
    """
    raw_key, prefix, hashed = generate_api_key()
    key = APIKey(
        organization_id=current_user.organization_id,
        user_id=current_user.id,
        name=body.name,
        key_prefix=prefix,
        hashed_key=hashed,
    )
    db.add(key)
    await db.flush()

    return APIKeyOut(
        id=key.id, name=key.name, key_prefix=key.key_prefix,
        created_at=key.created_at.isoformat(),
        raw_key=raw_key,
    )


@router.get("/me/api-keys", response_model=list[APIKeyOut])
async def list_api_keys(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List API keys for the current user. Raw keys are never returned."""
    result = await db.execute(
        select(APIKey).where(
            APIKey.user_id == current_user.id,
            APIKey.is_active == True,
        )
    )
    keys = result.scalars().all()
    return [APIKeyOut(
        id=k.id, name=k.name, key_prefix=k.key_prefix,
        created_at=k.created_at.isoformat(),
        last_used_at=k.last_used_at.isoformat() if k.last_used_at else None,
        expires_at=k.expires_at.isoformat() if k.expires_at else None,
    ) for k in keys]


@router.delete("/me/api-keys/{key_id}", status_code=204)
async def revoke_api_key(
    key_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Revoke an API key — immediately invalidates all requests using it."""
    result = await db.execute(
        select(APIKey).where(
            APIKey.id == key_id,
            APIKey.user_id == current_user.id,
            APIKey.is_active == True,
        )
    )
    key = result.scalar_one_or_none()
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")
    key.is_active = False
    await db.flush()
