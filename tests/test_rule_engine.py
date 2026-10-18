import json
from datetime import datetime, timezone
import pytest
from detection.cloudtrail_ingest import NormalizedEvent
from detection.rule_engine import score_event
from detection.mitre_mappings import RiskTier, get_mapping

def make_event(event_name, actor_type="IAMUser", actor_arn="arn:aws:iam::123456789012:user/test",
               source_ip="203.0.113.5", region="us-east-1", raw_extra=None, event_time=None):
    raw = {"userIdentity": {"type": actor_type, "arn": actor_arn, "accountId": "123456789012", "principalId": "AID123"},
           "sourceIPAddress": source_ip, "awsRegion": region}
    if raw_extra: raw.update(raw_extra)
    return NormalizedEvent({"event_id": f"evt-{event_name}", "source": "cloudtrail", "event_name": event_name,
        "event_time": event_time or datetime.now(timezone.utc),
        "actor": {"type": actor_type, "principal_id": "AID123", "arn": actor_arn, "account_id": "123456789012"},
        "source_ip": source_ip, "region": region, "resources": [], "raw": raw})

class TestMitreMappings:
    def test_known_event_maps(self):
        m = get_mapping("CreateAccessKey")
        assert m is not None and m.technique_id == "T1098.001" and m.risk_tier == RiskTier.HIGH

    def test_unknown_event_returns_none(self):
        assert get_mapping("SomeRandomEvent") is None

class TestRuleEngine:
    def test_benign_unmapped_event_returns_none(self):
        assert score_event(make_event("UnknownAPI")) is None

    def test_create_access_key_high_severity(self):
        alert = score_event(make_event("CreateAccessKey"))
        assert alert is not None and alert.technique_id == "T1098.001" and alert.severity >= 45

    def test_root_account_boosts_severity(self):
        a1 = score_event(make_event("CreateAccessKey", actor_type="IAMUser"))
        a2 = score_event(make_event("CreateAccessKey", actor_type="Root"))
        assert a2.severity > a1.severity and any("Root" in m for m in a2.modifiers)

    def test_console_login_without_mfa_boosts(self):
        e = make_event("ConsoleLogin", raw_extra={"additionalEventData": {"MFAUsed": "No"}, "responseElements": {"ConsoleLogin": "Success"}})
        alert = score_event(e)
        assert alert is not None and any("MFA" in m for m in alert.modifiers)

    def test_console_login_with_mfa_no_boost(self):
        e = make_event("ConsoleLogin", raw_extra={"additionalEventData": {"MFAUsed": "Yes"}, "responseElements": {"ConsoleLogin": "Success"}})
        alert = score_event(e)
        assert not any("MFA" in m for m in alert.modifiers)

    def test_dangerous_policy_attachment_critical(self):
        e = make_event("AttachUserPolicy", raw_extra={"requestParameters": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}})
        alert = score_event(e)
        assert alert is not None and alert.risk_tier == "critical"
        assert any("AdministratorAccess" in m for m in alert.modifiers)

    def test_stop_logging_is_critical(self):
        alert = score_event(make_event("StopLogging"))
        assert alert is not None
        assert alert.severity >= 80
        assert alert.risk_tier == "critical"
        assert alert.tactic == "Defense Evasion"

    def test_public_s3_acl_flagged(self):
        e = make_event("PutBucketAcl", raw_extra={"requestParameters": {"x-amz-acl": "public-read"}})
        alert = score_event(e)
        assert any("public" in m.lower() for m in alert.modifiers)

    def test_off_hours_boosts(self):
        off = datetime(2026, 6, 14, 3, 0, 0, tzinfo=timezone.utc)
        biz = datetime(2026, 6, 14, 14, 0, 0, tzinfo=timezone.utc)
        assert score_event(make_event("CreateAccessKey", event_time=off)).severity > \
               score_event(make_event("CreateAccessKey", event_time=biz)).severity

    def test_ml_score_boosts(self):
        e = make_event("DescribeInstances")
        assert score_event(e, ml_anomaly_score=0.95).severity > score_event(e).severity

    def test_ml_below_threshold_no_effect(self):
        e = make_event("DescribeInstances")
        assert score_event(e).severity == score_event(e, ml_anomaly_score=0.3).severity

    def test_severity_capped_at_100(self):
        e = make_event("AttachUserPolicy", actor_type="Root",
            event_time=datetime(2026,6,14,2,0,0,tzinfo=timezone.utc),
            raw_extra={"requestParameters": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}})
        assert score_event(e, ml_anomaly_score=0.99).severity <= 100

    def test_to_dict_serializable(self):
        alert = score_event(make_event("CreateUser"))
        json.dumps(alert.to_dict())

class TestGuardDutyMapping:
    def test_guardduty_event_scoring(self):
        from detection.cloudtrail_ingest import NormalizedEvent
        gd = NormalizedEvent({"event_id": "gd-1", "source": "guardduty",
            "event_name": "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
            "event_time": datetime.now(timezone.utc),
            "actor": {"type":"IAMUser","principal_id":"AID1","arn":"arn:aws:iam::123:user/u","account_id":"123"},
            "source_ip": "1.2.3.4", "region": "us-east-1", "resources": [], "raw": {},
            "_gd_severity": 8.5, "_gd_mitre": ("T1078","Valid Accounts"), "_gd_count": 1})
        alert = score_event(gd)
        assert alert is not None and alert.severity == 85 and alert.risk_tier == "critical"

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
