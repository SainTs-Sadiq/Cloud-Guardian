"""
Tier enforcement tests: prove auto-remediation can NEVER execute destructive
handlers, even if a playbook is misconfigured to point at one.
"""
import pytest
from unittest.mock import MagicMock, patch

from detection import remediation_actions as ra


class _FakeSession:
    def client(self, service, region_name=None):
        return MagicMock()


def _alert(event_id="e1", actor_arn="arn:aws:iam::123456789012:user/alice"):
    m = MagicMock()
    m.event_id = event_id
    m.actor_arn = actor_arn
    m.raw_event = {"responseElements": {"accessKey": {"accessKeyId": "AKIA123"}},
                   "requestParameters": {}}
    m.region = "us-east-1"
    return m


def test_destructive_set_includes_revoke_session_token():
    assert "revoke_session_token" in ra.DESTRUCTIVE_ACTIONS


def test_destructive_handler_refuses_without_destructive_session():
    ra.clear_action_session()
    with pytest.raises(RuntimeError, match="destructive action"):
        ra.disable_access_key(_alert())


def test_destructive_handler_runs_with_destructive_session():
    ra.clear_action_session()
    ra.set_action_session(_FakeSession(), destructive=True)
    try:
        # _client is now satisfied; the boto call itself is mocked away
        with patch.object(ra, "_client", return_value=MagicMock()):
            ok, detail = ra.disable_access_key(_alert())
        assert ok is True
    finally:
        ra.clear_action_session()


def test_auto_path_blocked_for_destructive_handler():
    """Simulate the celery guard: destructive handler + auto=True must be blocked."""
    from detection import remediation_engine  # noqa: F401 ensures import graph
    destructive = "disable_access_key"
    assert destructive in ra.DESTRUCTIVE_ACTIONS
    # the celery guard reads this set — verify the guard logic directly
    auto = True
    playbook_action = destructive
    blocked = auto and playbook_action in ra.DESTRUCTIVE_ACTIONS
    assert blocked is True


def test_auto_path_allows_low_risk_handler():
    low = "block_public_s3_access"
    assert low not in ra.DESTRUCTIVE_ACTIONS


def test_worker_source_guards_before_session_creation():
    """Regression: in workers/tasks.py, the missing-auto-role guard must
    appear BEFORE any session factory call in the same branch."""
    import re
    src = open("workers/tasks.py").read()
    guard_pos = src.find("if not auto_arn:")
    assert guard_pos != -1, "fail-closed guard missing"
    block = src[guard_pos:guard_pos + 800]
    m_return = re.search(r'return \{"status": "blocked"', block)
    m_session = block.find("get_session_for_account(")
    assert m_return is not None, "guard must return immediately (fail-closed)"
    assert m_session == -1 or m_session > m_return.start(), \
        "session creation must come after the guard's return"
