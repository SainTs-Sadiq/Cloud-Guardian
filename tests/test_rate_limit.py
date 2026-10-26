"""Redis rate limiter reliability tests."""
import time
from unittest.mock import MagicMock

from core import rate_limit


def test_unique_members_in_same_microsecond():
    """Prove two calls in the same microsecond produce distinct member names."""
    store = rate_limit._RedisStore.__new__(rate_limit._RedisStore)
    mock_r = MagicMock()
    pipe = MagicMock()
    pipe.execute.return_value = [0, 1, 2, True]
    mock_r.pipeline.return_value = pipe
    store._r = mock_r

    now = 1700000000.123456
    store.count(("127.0.0.1", "auth"), now)
    call1_zadd = pipe.zadd.call_args[0][1]

    pipe.reset_mock()
    store.count(("127.0.0.1", "auth"), now)
    call2_zadd = pipe.zadd.call_args[0][1]

    m1 = list(call1_zadd.keys())[0]
    m2 = list(call2_zadd.keys())[0]
    assert m1 != m2, "member names must not collide in the same microsecond"


def test_redis_failure_falls_back_to_in_process():
    """A Redis outage during count() must fall back safely, not raise."""
    store = rate_limit._RedisStore.__new__(rate_limit._RedisStore)
    mock_r = MagicMock()
    pipe = MagicMock()
    pipe.execute.side_effect = ConnectionError("Redis down")
    mock_r.pipeline.return_value = pipe
    store._r = mock_r

    count = store.count(("10.0.0.1", "global"), time.time())
    assert isinstance(count, int)
    assert count >= 1
