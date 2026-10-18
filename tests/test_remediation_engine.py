import os, tempfile
from datetime import datetime, timezone
import pytest
from detection.playbooks import ActionType, get_playbook
from detection.rule_engine import DetectedAlert
from detection.storage import LocalJSONLStore
import detection.remediation_engine as engine

def make_alert(technique_id, raw_event=None):
    return DetectedAlert(event_id=f"evt-{technique_id}", source="cloudtrail", event_name="TestEvent",
        event_time=datetime.now(timezone.utc), technique_id=technique_id, technique_name="Test",
        tactic="Persistence", severity=50, risk_tier="high", description="Test",
        actor_arn="arn:aws:iam::123456789012:user/alice", account_id="123456789012",
        region="us-east-1", source_ip="1.2.3.4", modifiers=[], raw_event=raw_event or {})

@pytest.fixture
def store():
    with tempfile.TemporaryDirectory() as tmp:
        yield LocalJSONLStore(os.path.join(tmp, "e.jsonl"))

class TestPlaybookLookup:
    def test_exact_match(self):
        p = get_playbook(make_alert("T1098.001"))
        assert p is not None and p.action == ActionType.DISABLE_ACCESS_KEY

    def test_base_fallback(self):
        p = get_playbook(make_alert("T1078.004"))
        assert p is not None and p.action == ActionType.REVOKE_SESSION

    def test_unmapped_returns_none(self):
        assert get_playbook(make_alert("T9999")) is None

    def test_s3_is_low_risk_action(self):
        assert get_playbook(make_alert("T1537")).action_risk_tier.value == "low"

    def test_iam_detach_is_high_risk_action(self):
        assert get_playbook(make_alert("T1098.003")).action_risk_tier.value == "high"

    def test_notify_only_for_data_destruction(self):
        p = get_playbook(make_alert("T1485"))
        assert p.action == ActionType.NOTIFY_ONLY

class TestRemediationGating:
    def test_disabled_gives_dry_run(self, store, monkeypatch):
        monkeypatch.setattr(engine.REMEDIATION, "enabled", False)
        r = engine.evaluate_and_act(make_alert("T1537"), store)
        assert r.decision == engine.RemediationDecision.DRY_RUN_LOGGED
        assert store.get_by_id("evt-T1537")["status"] == "dry_run"

    def test_low_risk_auto_executes_when_enabled(self, store, monkeypatch):
        monkeypatch.setattr(engine.REMEDIATION, "enabled", True)
        monkeypatch.setattr(engine.REMEDIATION, "auto_approve_tiers", ["low"])
        monkeypatch.setattr(engine.REMEDIATION, "notification_topic_arn", None)
        import detection.remediation_actions as actions
        monkeypatch.setattr(actions, "block_public_s3_access", lambda a: (True, "mocked"))
        r = engine.evaluate_and_act(make_alert("T1537"), store)
        assert r.decision == engine.RemediationDecision.AUTO_EXECUTED
        assert store.get_by_id("evt-T1537")["status"] == "remediated"

    def test_high_risk_requires_approval(self, store, monkeypatch):
        monkeypatch.setattr(engine.REMEDIATION, "enabled", True)
        monkeypatch.setattr(engine.REMEDIATION, "auto_approve_tiers", ["low"])
        monkeypatch.setattr(engine.REMEDIATION, "notification_topic_arn", None)
        r = engine.evaluate_and_act(make_alert("T1098.003"), store)
        assert r.decision == engine.RemediationDecision.PENDING_APPROVAL
        assert store.get_by_id("evt-T1098.003")["status"] == "pending_approval"

    def test_medium_risk_requires_approval(self, store, monkeypatch):
        monkeypatch.setattr(engine.REMEDIATION, "enabled", True)
        monkeypatch.setattr(engine.REMEDIATION, "auto_approve_tiers", ["low"])
        monkeypatch.setattr(engine.REMEDIATION, "notification_topic_arn", None)
        r = engine.evaluate_and_act(make_alert("T1098.001"), store)
        assert r.decision == engine.RemediationDecision.PENDING_APPROVAL

    def test_notify_only_never_auto_executes(self, store, monkeypatch):
        monkeypatch.setattr(engine.REMEDIATION, "enabled", True)
        monkeypatch.setattr(engine.REMEDIATION, "auto_approve_tiers", ["low","medium","high","critical"])
        monkeypatch.setattr(engine.REMEDIATION, "notification_topic_arn", None)
        r = engine.evaluate_and_act(make_alert("T1485"), store)
        assert r.decision == engine.RemediationDecision.NOTIFY_ONLY
        assert store.get_by_id("evt-T1485")["status"] == "notified"

    def test_no_playbook(self, store, monkeypatch):
        monkeypatch.setattr(engine.REMEDIATION, "enabled", True)
        r = engine.evaluate_and_act(make_alert("T9999"), store)
        assert r.decision == engine.RemediationDecision.NO_PLAYBOOK

class TestApprovalWorkflow:
    def test_approve_pending(self, store, monkeypatch):
        monkeypatch.setattr(engine.REMEDIATION, "enabled", True)
        monkeypatch.setattr(engine.REMEDIATION, "auto_approve_tiers", ["low"])
        monkeypatch.setattr(engine.REMEDIATION, "notification_topic_arn", None)
        alert = make_alert("T1098.003", raw_event={"requestParameters": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess","userName":"alice"}})
        engine.evaluate_and_act(alert, store)
        import detection.remediation_actions as actions
        monkeypatch.setattr(actions, "detach_dangerous_policy", lambda a: (True, "mocked"))
        result = engine.approve_remediation(alert.event_id, store)
        assert result.decision == engine.RemediationDecision.AUTO_EXECUTED
        assert store.get_by_id(alert.event_id)["status"] == "remediated"

    def test_approve_nonexistent_raises(self, store):
        with pytest.raises(ValueError): engine.approve_remediation("nonexistent", store)

    def test_approve_non_pending_raises(self, store, monkeypatch):
        monkeypatch.setattr(engine.REMEDIATION, "enabled", False)
        engine.evaluate_and_act(make_alert("T1537"), store)
        with pytest.raises(ValueError): engine.approve_remediation("evt-T1537", store)

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
