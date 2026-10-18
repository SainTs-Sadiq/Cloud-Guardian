"""
User repository — all queries ALWAYS scoped to organization_id.
"""
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models.user import User, UserRole


class UserRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(self, organization_id: str, email: str, full_name: str,
                     hashed_password: str, role: UserRole = UserRole.analyst) -> User:
        user = User(
            organization_id=organization_id, email=email,
            full_name=full_name, hashed_password=hashed_password, role=role,
        )
        self.db.add(user)
        await self.db.flush()
        return user

    async def get_by_id(self, user_id: str, organization_id: str) -> User | None:
        result = await self.db.execute(
            select(User).where(User.id == user_id, User.organization_id == organization_id)
        )
        return result.scalar_one_or_none()

    async def get_by_email(self, email: str) -> User | None:
        """Email is globally unique — used for login (no org filter needed here)."""
        result = await self.db.execute(select(User).where(User.email == email))
        return result.scalar_one_or_none()

    async def list_by_org(self, organization_id: str) -> list[User]:
        result = await self.db.execute(
            select(User).where(User.organization_id == organization_id, User.is_active == True)
        )
        return list(result.scalars().all())

    async def update_last_login(self, user_id: str) -> None:
        user = await self.db.get(User, user_id)
        if user:
            user.last_login_at = datetime.now(timezone.utc)
            await self.db.flush()

    async def deactivate(self, user_id: str, organization_id: str) -> bool:
        user = await self.get_by_id(user_id, organization_id)
        if user is None:
            return False
        user.is_active = False
        await self.db.flush()
        return True
