"""
Security utilities — password hashing, JWT tokens, API key generation.

JWT strategy:
  - Access token: short-lived (30 min), contains user_id + org_id + role
  - Refresh token: longer-lived (7 days), used only to issue new access tokens
  - All tokens signed with HS256 + SECRET_KEY from environment

API key strategy:
  - Format: cg_live_{32-char random hex}
  - Stored as bcrypt hash (same as passwords)
  - First 12 chars shown to user as "prefix" for identification
  - Never logged or returned after initial creation
"""
import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from passlib.context import CryptContext

SECRET_KEY = os.environ.get("SECRET_KEY", "CHANGE_THIS_IN_PRODUCTION_USE_OPENSSL_RAND_HEX_32")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.environ.get("REFRESH_TOKEN_EXPIRE_DAYS", "7"))


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(user_id: str, organization_id: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "org": organization_id,
        "role": role,
        "type": "access",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "type": "refresh",
        "exp": datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    """
    Decode and validate a JWT. Raises JWTError on invalid/expired tokens.
    Callers should catch JWTError and raise HTTP 401.
    """
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])


API_KEY_PREFIX = "cg_live_"


def generate_api_key() -> tuple[str, str, str]:
    """
    Generate a new API key.

    Returns (raw_key, prefix, hashed_key):
      raw_key    — shown to user ONCE on creation, never stored
      prefix     — first 12 chars of raw_key, stored for identification
      hashed_key — bcrypt hash, stored in DB
    """
    random_part = secrets.token_hex(32)
    raw_key = f"{API_KEY_PREFIX}{random_part}"
    prefix = raw_key[:12]
    hashed_key = pwd_context.hash(raw_key)
    return raw_key, prefix, hashed_key


def verify_api_key(raw_key: str, hashed_key: str) -> bool:
    return pwd_context.verify(raw_key, hashed_key)


def validate_password_strength(password: str) -> list[str]:
    """
    Return a list of validation errors. Empty list = password is acceptable.
    """
    errors = []
    if len(password) < 10:
        errors.append("Password must be at least 10 characters")
    if not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter")
    if not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter")
    if not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one digit")
    return errors
