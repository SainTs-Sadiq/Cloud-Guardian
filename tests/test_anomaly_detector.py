import os
import tempfile
from datetime import datetime, timedelta, timezone
import pandas as pd
import pytest
from detection.cloudtrail_ingest import NormalizedEvent
from ml.anomaly_detector import AnomalyDetector, FeatureRow, build_actor_history, extract_features

def make_event(event_name, actor_arn, ip, region, t):
    return NormalizedEvent({"event_id": f"e-{event_name}", "source": "cloudtrail", "event_name": event_name,
        "event_time": t, "actor": {"type":"IAMUser","principal_id":"AID1","arn":actor_arn,"account_id":"123"},
        "source_ip": ip, "region": region, "resources": [], "raw": {}})

class TestFeatureExtraction:
    def test_cold_start(self):
        f = extract_features(make_event("DescribeInstances","arn:aws:iam::123:user/alice","1.2.3.4","us-east-1",datetime.now(timezone.utc)))
        assert f.event_name_freq == 0.0 and f.new_source_ip == 1 and f.new_region == 1

    def test_familiar_event_low_novelty(self):
        now = datetime.now(timezone.utc)
        history = pd.DataFrame([{"event_name":"DescribeInstances","source_ip":"1.2.3.4","region":"us-east-1","event_time":now-timedelta(hours=i+2)} for i in range(10)])
        f = extract_features(make_event("DescribeInstances","arn:aws:iam::123:user/alice","1.2.3.4","us-east-1",now), actor_history=history)
        assert f.event_name_freq == 1.0 and f.new_source_ip == 0 and f.new_region == 0

    def test_new_ip_detected(self):
        now = datetime.now(timezone.utc)
        history = pd.DataFrame([{"event_name":"DescribeInstances","source_ip":"1.2.3.4","region":"us-east-1","event_time":now-timedelta(hours=5)}])
        f = extract_features(make_event("DescribeInstances","arn:aws:iam::123:user/alice","9.9.9.9","us-east-1",now), actor_history=history)
        assert f.new_source_ip == 1

    def test_management_event_flag(self):
        now = datetime.now(timezone.utc)
        assert extract_features(make_event("DescribeInstances","a","1.2.3.4","us-east-1",now)).is_management_event == 0
        assert extract_features(make_event("CreateAccessKey","a","1.2.3.4","us-east-1",now)).is_management_event == 1

class TestBuildActorHistory:
    def test_groups_by_actor(self):
        now = datetime.now(timezone.utc)
        events = [make_event("DescribeInstances","arn:aws:iam::123:user/alice","1.2.3.4","us-east-1",now),
                  make_event("ListBuckets","arn:aws:iam::123:user/alice","1.2.3.4","us-east-1",now),
                  make_event("ConsoleLogin","arn:aws:iam::123:user/bob","5.6.7.8","eu-west-1",now)]
        h = build_actor_history(events)
        assert len(h["arn:aws:iam::123:user/alice"]) == 2 and len(h["arn:aws:iam::123:user/bob"]) == 1

    def test_empty_returns_empty(self):
        assert build_actor_history([]) == {}

class TestAnomalyDetector:
    def _normal_rows(self, n=100):
        return [FeatureRow(0.7, 10+(i%8), 0, 0, 0, 2, 0) for i in range(n)]

    def test_fit_and_score(self):
        d = AnomalyDetector(); d.fit(self._normal_rows())
        s = d.score(FeatureRow(0.7, 11, 0, 0, 0, 2, 0))
        assert 0.0 <= s <= 1.0

    def test_anomalous_scores_higher(self):
        d = AnomalyDetector(); d.fit(self._normal_rows())
        normal = d.score(FeatureRow(0.7, 11, 0, 0, 0, 2, 0))
        anomalous = d.score(FeatureRow(0.0, 3, 1, 1, 1, 50, 1))
        assert anomalous > normal

    def test_score_before_fit_returns_neutral(self):
        assert AnomalyDetector().score(FeatureRow(0.5,12,0,0,0,1,0)) == 0.5

    def test_save_load_roundtrip(self):
        d = AnomalyDetector(); d.fit(self._normal_rows())
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "model.joblib")
            d.save(path)
            d2 = AnomalyDetector.load(path)
            pt = FeatureRow(0.7,11,0,0,0,2,0)
            assert abs(d.score(pt) - d2.score(pt)) < 1e-9
            assert d2.n_training_samples == 100

    def test_low_sample_count_no_crash(self):
        d = AnomalyDetector(); d.fit(self._normal_rows(5))
        assert 0.0 <= d.score(FeatureRow(0.5,12,0,0,0,1,0)) <= 1.0

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
