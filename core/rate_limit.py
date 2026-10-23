"""
Sliding-window rate limiter middleware.

Uses Redis when REDIS_URL is set (multi-worker safe), falls back to an
in-process store for dev/single-process deployments.
"""
import os
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware

# Test suites (TestClient) share one IP and fire hundreds of requests per
# minute — allow overriding for tests/other environments.
GLOBAL_LIMIT = int(os.environ.get("CG_RATE_LIMIT_GLOBAL", "120"))   # req / min / IP
AUTH_LIMIT = int(os.environ.get("CG_RATE_LIMIT_AUTH", "10"))        # auth / min / IP
AUTH_PATHS = ("/auth/login", "/auth/register", "/auth/refresh")

REDIS_URL = os.environ.get("REDIS_URL", "").strip()


class _InProcessStore:
    """Single-process fallback. Good for dev; NOT shared across workers."""

    def __init__(self):
        self._hits: dict[tuple[str, str], deque] = defaultdict(deque)

    def count(self, key: tuple[str, str], now: float) -> int:
        bucket = self._hits[key]
        while bucket and now - bucket[0] > 60:
            bucket.popleft()
        bucket.append(now)
        return len(bucket)


class _RedisStore:
    """Atomic sliding window shared by every worker behind REDIS_URL."""

    def __init__(self, url: str):
        import redis  # imported lazily — optional dependency
        self._r = redis.Redis.from_url(url, decode_responses=True)

    def count(self, key: tuple[str, str], now: float) -> int:
        # Unique member per request: same-microsecond requests must not
        # collide and understate the count.
        import uuid
        member = f"{now:.6f}:{uuid.uuid4().hex}"
        name = f"cg:rl:{key[0]}:{key[1]}"
        pipe = self._r.pipeline()
        pipe.zremrangebyscore(name, 0, now - 60)
        pipe.zadd(name, {member: now})
        pipe.zcard(name)
        pipe.expire(name, 120)
        try:
            _, _, n, _ = pipe.execute()
            return int(n)
        except Exception:
            # Redis failed mid-flight: fail OPEN to the in-process store so a
            # Redis outage never becomes an API outage (and never a 500).
            import logging
            logging.getLogger("cloud_guardian.rate_limit").warning(
                "Redis unavailable during rate limit; using in-process fallback")
            return _FALLBACK_STORE.count(key, now)


_FALLBACK_STORE = _InProcessStore()


def _make_store():
    if REDIS_URL:
        try:
            return _RedisStore(REDIS_URL)
        except Exception as e:  # Redis down at import — fall back, warn
            import logging
            logging.getLogger("cloud_guardian.rate_limit").warning(
                f"REDIS_URL set but Redis unavailable ({e}); using in-process limiter")
    return _InProcessStore()


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self._store = _make_store()

    async def dispatch(self, request: Request, call_next):
        ip = request.client.host if request.client else "unknown"
        now = time.time()

        is_auth = request.url.path in AUTH_PATHS
        limit = AUTH_LIMIT if is_auth else GLOBAL_LIMIT
        used = self._store.count((ip, "auth" if is_auth else "global"), now)
        if used > limit:
            raise HTTPException(status_code=429, detail="Too many requests, slow down")
        return await call_next(request)
