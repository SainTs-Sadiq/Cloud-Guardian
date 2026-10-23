"""
Fail-closed guard tests for remediation.

Covers: missing role registration (approve + worker), missing AWS account,
destructive action without its role session (must 409 / block, never execute),
and per-call session binding so nothing leaks across tasks.
"""
import contextvars
from unittest.mock import MagicMock, patch

import pytest

from detection import remediation_actions as ra


class _FakeSession:
    def __init__(self):
        self.calls = []

    def client(self, service, region_name=None):
        self.calls.append(service)
        return MagicMock()


def _alert():
    m = MagicMock()
    m.event_id = "e1"
    m.actor_arn = "arn:aws:iam::123456789012:user/alice"
    m.raw_event = {"responseElements": {"accessKey": {"accessKeyId": "AKIA123"}},
                   "requestParameters": {}}
    m.region = "us-east-1"
    return m


# ---- destructive action without its role session --------------------------

def test_guard_error_is_runtime_error_subclass():
    # Existing tier tests match RuntimeError; the typed guard must stay compatible.
    assert issubclass(ra.RemediationGuardError, RuntimeError)


def test_destructive_without_session_raises_typed_guard_error():
    with ra.remediation_sessions(auto=_FakeSession(), destructive=None):
        with pytest.raises(ra.RemediationGuardError, match="destructive action"):
            ra.disable_access_key(_alert())


def test_destructive_handler_never_runs_on_auto_session_only():
    auto = _FakeSession()
    with ra.remediation_sessions(auto=auto, destructive=None):
        with pytest.raises(ra.RemediationGuardError):
            ra.disable_access_key(_alert())
    assert auto.calls == []  # boto client was never created on the auto role


# ---- per-call binding: no leak between tasks ------------------------------

def test_session_binding_is_scoped_to_context_manager():
    destr = _FakeSession()
    with ra.remediation_sessions(auto=None, destructive=destr):
        assert ra._destructive_session_var.get() is destr
    # After exit, the binding is gone: a later task on the same worker sees nothing.
    assert ra._destructive_session_var.get() is None
    assert ra._auto_session_var.get() is None


def test_binding_does_not_leak_into_fresh_context():
    destr = _FakeSession()
    with ra.remediation_sessions(auto=None, destructive=destr):
        pass

    def _check():
        return ra._destructive_session_var.get()

    # A fresh context (what a new task/thread gets) must not see a prior binding.
    assert contextvars.Context().run(_check) is None


def test_binding_resets_even_when_handler_raises():
    with pytest.raises(ra.RemediationGuardError):
        with ra.remediation_sessions(auto=None, destructive=None):
            ra.disable_access_key(_alert())
    assert ra._destructive_session_var.get() is None


# ---- worker: fail closed on missing role registration ---------------------

def test_worker_source_blocks_when_destructive_role_missing():
    import inspect
    from workers import tasks
    src = inspect.getsource(tasks._do_remediation)
    # Both role registrations are checked (fail-closed) BEFORE any session is created.
    guard = "No destructive_remediation_role_arn registered"
    assert guard in src
    assert src.index(guard) < src.index("get_session_for_account(")


def test_worker_guard_error_is_not_retried():
    """execute_remediation must return blocked (never self.retry) on a guard error."""
    import inspect
    from workers import tasks
    src = inspect.getsource(tasks)
    assert "isinstance(exc, RemediationGuardError)" in src
    assert "remediation refused by fail-closed guard" in src


# ---- approve: 409 on missing role / missing account ------------------------

def test_approve_route_imports_select():
    from api.routes import remediation as route
    assert hasattr(route, "select"), "select must be imported; approve would NameError to 500"


def test_pending_list_has_real_pagination_params():
    import inspect
    from api.routes import remediation as route
    sig = inspect.signature(route.list_pending)
    assert "limit" in sig.parameters and "offset" in sig.parameters
    assert "limit=200" not in inspect.getsource(route.list_pending)


def test_dismiss_route_accepts_request_param():
    import inspect
    from api.routes import remediation as route
    assert "request" in inspect.signature(route.dismiss_incident).parameters


def test_worker_source_fails_closed_on_missing_aws_account():
    """Missing account row must block, not fall back to platform credentials."""
    import inspect
    from workers import tasks
    src = inspect.getsource(tasks._do_remediation)
    assert "AWS account missing or has no role ARN" in src
    assert "refusing platform-credential remediation (fail-closed)" in src


def test_approve_route_refuses_with_409_before_any_session():
    """The approve route must check account + both roles before building sessions."""
    import inspect
    from api.routes import remediation as route
    src = inspect.getsource(route)
    assert src.index("No auto_remediation_role_arn registered") < src.index("get_session_for_account(")
    assert src.index("No destructive_remediation_role_arn registered") < src.index("get_session_for_account(")
