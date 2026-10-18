import os, tempfile
from datetime import datetime, timezone
import pytest
from detection.rule_engine import DetectedAlert
from detection.storage import LocalJSONLStore

def make_alert(event_id="evt-1", severity=75):
    return DetectedAlert(event_id=event_id, source="cloudtrail", event_name="CreateAccessKey",
        event_time=datetime.now(timezone.utc), technique_id="T1098.001",
        technique_name="Account Manipulation: Additional Cloud Credentials", tactic="Persistence",
        severity=severity, risk_tier="high", description="New access key created",
        actor_arn="arn:aws:iam::123456789012:user/attacker", account_id="123456789012",
        region="us-east-1", source_ip="203.0.113.5", modifiers=[], raw_event={})

class TestLocalJSONLStore:
    def test_save_and_get_recent(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = LocalJSONLStore(os.path.join(tmp, "e.jsonl"))
            s.save(make_alert("evt-1"))
            r = s.get_recent()
            assert len(r) == 1 and r[0]["event_id"] == "evt-1" and r[0]["status"] == "detected"

    def test_get_by_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = LocalJSONLStore(os.path.join(tmp, "e.jsonl"))
            s.save(make_alert("evt-abc"))
            assert s.get_by_id("evt-abc")["event_id"] == "evt-abc"
            assert s.get_by_id("nonexistent") is None

    def test_update_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = LocalJSONLStore(os.path.join(tmp, "e.jsonl"))
            s.save(make_alert("evt-1"))
            s.update_status("evt-1", "remediating", "revoke_session_token")
            r = s.get_by_id("evt-1")
            assert r["status"] == "remediating" and r["remediation_action"] == "revoke_session_token"

    def test_get_recent_ordering(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = LocalJSONLStore(os.path.join(tmp, "e.jsonl"))
            for i in range(3): s.save(make_alert(f"evt-{i+1}"))
            r = s.get_recent(limit=2)
            assert len(r) == 2 and r[0]["event_id"] == "evt-3"

    def test_multiple_alerts_independent(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = LocalJSONLStore(os.path.join(tmp, "e.jsonl"))
            s.save(make_alert("evt-1", severity=90))
            s.save(make_alert("evt-2", severity=40))
            s.update_status("evt-1", "resolved", "revoked_credentials")
            assert s.get_by_id("evt-1")["status"] == "resolved"
            assert s.get_by_id("evt-2")["status"] == "detected"

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
