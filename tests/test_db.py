"""
Database model + repository tests using SQLite in-memory.
No PostgreSQL required — exact same SQLAlchemy ORM, different engine.

Run: python -m pytest tests/test_db.py -v
"""
import os
import pytest
import pytest_asyncio
from datetime import datetime, timezone


os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from db.engine import Base
from db.models import Organization, User, AWSAccount, Incident, AuditLog, PlanTier, UserRole, AccountStatus
from db.repositories.organization_repo import OrganizationRepository
from db.repositories.user_repo import UserRepository
from db.repositories.incident_repo import IncidentRepository
from core.security import (
    hash_password, verify_password, create_access_token, decode_token,
    generate_api_key, verify_api_key, validate_password_strength,
)


@pytest.fixture(scope="session")
def event_loop_policy():
    import asyncio
    return asyncio.DefaultEventLoopPolicy()


@pytest_asyncio.fixture
async def db_session():
    """Fresh in-memory SQLite DB for each test."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", connect_args={"check_same_thread": False})
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


class TestOrganizationRepository:
    @pytest.mark.asyncio
    async def test_create_organization(self, db_session):
        repo = OrganizationRepository(db_session)
        org = await repo.create("Acme Corp", "acme-corp", "billing@acme.com")
        await db_session.commit()
        assert org.id is not None
        assert org.name == "Acme Corp"
        assert org.slug == "acme-corp"
        assert org.plan == PlanTier.free
        assert org.max_aws_accounts == 1

    @pytest.mark.asyncio
    async def test_get_by_slug(self, db_session):
        repo = OrganizationRepository(db_session)
        await repo.create("Acme Corp", "acme-corp", "b@acme.com")
        await db_session.commit()
        found = await repo.get_by_slug("acme-corp")
        assert found is not None
        assert found.name == "Acme Corp"

    @pytest.mark.asyncio
    async def test_get_by_slug_not_found(self, db_session):
        repo = OrganizationRepository(db_session)
        assert await repo.get_by_slug("nonexistent") is None

    @pytest.mark.asyncio
    async def test_update_plan_upgrades_limits(self, db_session):
        repo = OrganizationRepository(db_session)
        org = await repo.create("Acme", "acme", "b@acme.com")
        await db_session.commit()
        updated = await repo.update_plan(org.id, PlanTier.pro)
        assert updated.plan == PlanTier.pro
        assert updated.max_aws_accounts == 10
        assert updated.max_monthly_alerts == 10_000

    @pytest.mark.asyncio
    async def test_list_all(self, db_session):
        repo = OrganizationRepository(db_session)
        await repo.create("Org A", "org-a", "a@a.com")
        await repo.create("Org B", "org-b", "b@b.com")
        await db_session.commit()
        orgs = await repo.list_all()
        assert len(orgs) == 2


class TestUserRepository:
    @pytest_asyncio.fixture
    async def org(self, db_session):
        repo = OrganizationRepository(db_session)
        org = await repo.create("Test Org", "test-org", "admin@test.com")
        await db_session.commit()
        return org

    @pytest.mark.asyncio
    async def test_create_user(self, db_session, org):
        repo = UserRepository(db_session)
        user = await repo.create(
            organization_id=org.id, email="alice@test.com",
            full_name="Alice Smith", hashed_password=hash_password("SecurePass123"),
        )
        await db_session.commit()
        assert user.id is not None
        assert user.email == "alice@test.com"
        assert user.organization_id == org.id
        assert user.role == UserRole.analyst

    @pytest.mark.asyncio
    async def test_get_by_email(self, db_session, org):
        repo = UserRepository(db_session)
        await repo.create(org.id, "bob@test.com", "Bob Jones", hash_password("Pass123456"))
        await db_session.commit()
        user = await repo.get_by_email("bob@test.com")
        assert user is not None and user.email == "bob@test.com"

    @pytest.mark.asyncio
    async def test_get_by_id_wrong_org_returns_none(self, db_session, org):
        """Critical isolation test — can't read another org's users by ID."""
        repo = UserRepository(db_session)
        user = await repo.create(org.id, "carol@test.com", "Carol", hash_password("Pass123456"))
        await db_session.commit()
        result = await repo.get_by_id(user.id, organization_id="other-org-id")
        assert result is None

    @pytest.mark.asyncio
    async def test_list_by_org_only_returns_own_users(self, db_session):
        org_repo = OrganizationRepository(db_session)
        user_repo = UserRepository(db_session)
        org1 = await org_repo.create("Org1", "org-1", "a@1.com")
        org2 = await org_repo.create("Org2", "org-2", "a@2.com")
        await user_repo.create(org1.id, "u1@org1.com", "U1", hash_password("Pass123456"))
        await user_repo.create(org1.id, "u2@org1.com", "U2", hash_password("Pass123456"))
        await user_repo.create(org2.id, "u3@org2.com", "U3", hash_password("Pass123456"))
        await db_session.commit()
        org1_users = await user_repo.list_by_org(org1.id)
        assert len(org1_users) == 2
        assert all(u.organization_id == org1.id for u in org1_users)


def _now():
    return datetime.now(timezone.utc)


class TestIncidentRepository:
    @pytest_asyncio.fixture
    async def setup(self, db_session):
        org_repo = OrganizationRepository(db_session)
        org = await org_repo.create("SecCorp", "seccorp", "sec@corp.com")
        account = AWSAccount(
            organization_id=org.id, aws_account_id="123456789012",
            display_name="Prod", role_arn="arn:aws:iam::123:role/CG",
            status=AccountStatus.active,
        )
        db_session.add(account)
        await db_session.commit()
        return org, account

    @pytest.mark.asyncio
    async def test_create_incident(self, db_session, setup):
        org, account = setup
        repo = IncidentRepository(db_session)
        incident = await repo.create(
            organization_id=org.id, aws_account_db_id=account.id,
            event_id="evt-001", source="cloudtrail", event_name="CreateAccessKey",
            event_time=_now(), technique_id="T1098.001",
            technique_name="Account Manipulation", tactic="Persistence",
            severity=75, risk_tier="high", description="New key created",
            actor_arn="arn:aws:iam::123:user/alice", aws_region="us-east-1",
            modifiers=["Root account used"], ml_anomaly_score=0.82,
        )
        await db_session.commit()
        assert incident.id is not None
        assert incident.technique_id == "T1098.001"
        assert incident.organization_id == org.id

    @pytest.mark.asyncio
    async def test_list_with_filters(self, db_session, setup):
        org, account = setup
        repo = IncidentRepository(db_session)
        kwargs = dict(aws_account_db_id=account.id, event_time=_now(),
                      technique_name="Test", description="d", actor_arn="arn:a", aws_region="us-east-1")
        await repo.create(org.id, event_id="e1", source="cloudtrail",
                          event_name="CreateAccessKey", technique_id="T1098.001",
                          tactic="Persistence", severity=80, risk_tier="critical", **kwargs)
        await repo.create(org.id, event_id="e2", source="guardduty",
                          event_name="UnauthorizedAccess", technique_id="T1078",
                          tactic="Initial Access", severity=40, risk_tier="medium", **kwargs)
        await db_session.commit()


        results, total = await repo.list_for_org(org.id, severity_min=70)
        assert total == 1 and results[0].severity == 80


        results, total = await repo.list_for_org(org.id, risk_tier="medium")
        assert total == 1


        results, total = await repo.list_for_org(org.id, tactic="Persistence")
        assert total == 1

    @pytest.mark.asyncio
    async def test_tenant_isolation_in_list(self, db_session):
        """Org A cannot see Org B's incidents."""
        org_repo = OrganizationRepository(db_session)
        orgA = await org_repo.create("OrgA", "org-a", "a@a.com")
        orgB = await org_repo.create("OrgB", "org-b", "b@b.com")

        accA = AWSAccount(organization_id=orgA.id, aws_account_id="111111111111",
                          display_name="A", role_arn="arn:a", status=AccountStatus.active)
        accB = AWSAccount(organization_id=orgB.id, aws_account_id="222222222222",
                          display_name="B", role_arn="arn:b", status=AccountStatus.active)
        db_session.add_all([accA, accB])
        await db_session.commit()

        repo = IncidentRepository(db_session)
        kw = dict(description="d", actor_arn="arn:a", aws_region="us-east-1",
                  severity=50, risk_tier="medium")
        await repo.create(orgA.id, accA.id, "eA1", "cloudtrail", "CreateUser", _now(), "T1136", "Create Account", "Persistence", **kw)
        await repo.create(orgA.id, accA.id, "eA2", "cloudtrail", "CreateUser", _now(), "T1136", "Create Account", "Persistence", **kw)
        await repo.create(orgB.id, accB.id, "eB1", "cloudtrail", "CreateUser", _now(), "T1136", "Create Account", "Persistence", **kw)
        await db_session.commit()

        a_incidents, a_total = await repo.list_for_org(orgA.id)
        b_incidents, b_total = await repo.list_for_org(orgB.id)

        assert a_total == 2
        assert b_total == 1
        assert all(i.organization_id == orgA.id for i in a_incidents)

    @pytest.mark.asyncio
    async def test_update_status(self, db_session, setup):
        org, account = setup
        repo = IncidentRepository(db_session)
        incident = await repo.create(
            org.id, account.id, "e1", "cloudtrail", "StopLogging",
            _now(), "T1562.008", "Impair Defenses", "Defense Evasion",
            80, "critical", "Logging disabled", "arn:a", "us-east-1",
        )
        await db_session.commit()
        from db.models.incident import IncidentStatus
        updated = await repo.update_status(incident.id, org.id, IncidentStatus.remediated,
                                           resolved_at=_now())
        assert updated.status == IncidentStatus.remediated
        assert updated.resolved_at is not None

    @pytest.mark.asyncio
    async def test_count_by_tactic(self, db_session, setup):
        org, account = setup
        repo = IncidentRepository(db_session)
        kw = dict(description="d", actor_arn="arn:a", aws_region="us-east-1",
                  severity=50, risk_tier="medium")
        await repo.create(org.id, account.id, "e1", "cloudtrail", "E1", _now(), "T1", "Technique", "Persistence", **kw)
        await repo.create(org.id, account.id, "e2", "cloudtrail", "E2", _now(), "T2", "Technique", "Persistence", **kw)
        await repo.create(org.id, account.id, "e3", "cloudtrail", "E3", _now(), "T3", "Technique", "Exfiltration", **kw)
        await db_session.commit()
        counts = await repo.count_by_tactic(org.id)
        assert counts.get("Persistence") == 2
        assert counts.get("Exfiltration") == 1


class TestSecurity:
    def test_password_hash_and_verify(self):
        h = hash_password("MySecurePass123")
        assert verify_password("MySecurePass123", h)
        assert not verify_password("WrongPass", h)

    def test_jwt_encode_decode(self):
        token = create_access_token("user-1", "org-1", "admin")
        payload = decode_token(token)
        assert payload["sub"] == "user-1"
        assert payload["org"] == "org-1"
        assert payload["role"] == "admin"
        assert payload["type"] == "access"

    def test_expired_token_raises(self):
        from jose import JWTError
        from datetime import timedelta
        import os
        os.environ["ACCESS_TOKEN_EXPIRE_MINUTES"] = "0"

        from jose import jwt
        from core.security import SECRET_KEY, ALGORITHM
        expired_payload = {
            "sub": "user-1", "org": "org-1", "role": "admin",
            "exp": datetime(2020, 1, 1, tzinfo=timezone.utc),
        }
        token = jwt.encode(expired_payload, SECRET_KEY, algorithm=ALGORITHM)
        with pytest.raises(JWTError):
            decode_token(token)

    def test_api_key_generation_and_verification(self):
        raw_key, prefix, hashed = generate_api_key()
        assert raw_key.startswith("cg_live_")
        assert prefix == raw_key[:12]
        assert verify_api_key(raw_key, hashed)
        assert not verify_api_key("wrong-key", hashed)

    def test_api_key_unique_each_call(self):
        raw1, _, _ = generate_api_key()
        raw2, _, _ = generate_api_key()
        assert raw1 != raw2

    def test_password_strength_validation(self):
        errors = validate_password_strength("weak")
        assert len(errors) > 0

        errors = validate_password_strength("StrongPass123")
        assert errors == []

        errors = validate_password_strength("alllowercase1")
        assert any("uppercase" in e for e in errors)

        errors = validate_password_strength("ALLUPPERCASE1")
        assert any("lowercase" in e for e in errors)

        errors = validate_password_strength("NoDigitsHere!")
        assert any("digit" in e for e in errors)


class TestAuthAPI:
    """Auth API tests — uses auth_client fixture from conftest.py."""

    REG = {"org_name": "Test Corp", "org_slug": "test-corp",
           "email": "owner@testcorp.com", "full_name": "Test Owner", "password": "SecurePass123"}

    def test_register_creates_org_and_user(self, auth_client):
        r = auth_client.post("/auth/register", json=self.REG)
        assert r.status_code == 201, r.text
        data = r.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

    def test_register_duplicate_slug_returns_409(self, auth_client):
        auth_client.post("/auth/register", json=self.REG)
        r = auth_client.post("/auth/register", json={**self.REG, "email": "other@test.com"})
        assert r.status_code == 409

    def test_register_duplicate_email_returns_409(self, auth_client):
        auth_client.post("/auth/register", json=self.REG)
        r = auth_client.post("/auth/register", json={**self.REG, "org_slug": "other-slug"})
        assert r.status_code == 409

    def test_register_weak_password_returns_422(self, auth_client):
        r = auth_client.post("/auth/register", json={**self.REG, "password": "weak"})
        assert r.status_code == 422

    def test_login_valid_credentials(self, auth_client):
        auth_client.post("/auth/register", json=self.REG)
        r = auth_client.post("/auth/login", json={"email": self.REG["email"], "password": self.REG["password"]})
        assert r.status_code == 200
        assert "access_token" in r.json()

    def test_login_wrong_password_returns_401(self, auth_client):
        auth_client.post("/auth/register", json=self.REG)
        r = auth_client.post("/auth/login", json={"email": self.REG["email"], "password": "WrongPass999"})
        assert r.status_code == 401

    def test_login_unknown_email_returns_401(self, auth_client):
        r = auth_client.post("/auth/login", json={"email": "nobody@nowhere.com", "password": "SecurePass123"})
        assert r.status_code == 401

    def test_invalid_slug_format_returns_422(self, auth_client):
        r = auth_client.post("/auth/register", json={**self.REG, "org_slug": "Bad Slug!!", "email": "u@bad.com"})
        assert r.status_code == 422


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])