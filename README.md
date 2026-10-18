# Cloud Guardian

**Autonomous cloud attack detection, MITRE ATT&CK mapping, and risk-tiered remediation for AWS.**

## Architecture

```
CloudTrail ─┐
GuardDuty  ─┤─► Ingest Layer ─► Rule Engine + ML Scoring ─► Alert Store (Local / DynamoDB)
VPC Logs   ─┘         │                                              │
                  MITRE Mapping                              Remediation Engine
                (35+ techniques)                            ┌────────────────────┐
                                                            │ LOW risk  → Auto   │
                                                            │ MEDIUM    → Notify │
                                                            │ HIGH      → Approve│
                                                            │ CRITICAL  → Approve│
                                                            └────────────────────┘
```

## Quick Start

### 1. Configure AWS credentials
```bash
aws configure
# or
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_REGION=us-east-1
```

### 2. Attach the read-only detection policy
```bash
aws iam create-policy --policy-name CloudGuardianDetection \
  --policy-document file://infra/iam_policy_detection_readonly.json

aws iam attach-user-policy --user-name YOUR_USER \
  --policy-arn arn:aws:iam::ACCOUNT_ID:policy/CloudGuardianDetection
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Verify setup
```bash
python -m detection.orchestrator check
```

### 5. Train the anomaly detection baseline
```bash
python -m ml.train_baseline --days 14
```
> Requires 14 days of CloudTrail history. Run with `--days 7` if less is available.

### 6. Run a scan
```bash
python -m detection.orchestrator scan --minutes 60
```

### 7. Continuous monitoring
```bash
python -m detection.orchestrator monitor
```

---

## Remediation

Remediation is **disabled by default** (dry-run mode). Enable carefully:

```bash
# Attach remediation IAM policy first
aws iam create-policy --policy-name CloudGuardianRemediation \
  --policy-document file://infra/iam_policy_remediation.json

# Enable remediation (auto-executes LOW risk tier actions only)
export CG_REMEDIATION_ENABLED=true
export CG_SNS_TOPIC_ARN=arn:aws:sns:us-east-1:ACCOUNT:cloud-guardian-alerts

python -m detection.orchestrator scan
```

**Risk tiers:**
| Tier | Auto-execute? | Examples |
|------|--------------|---------|
| LOW | ✅ Yes | Block public S3 ACL |
| MEDIUM | ❌ Notify → Approve | Disable access key, revoke session |
| HIGH | ❌ Notify → Approve | Detach IAM policy, isolate EC2, disable Lambda |
| CRITICAL | ❌ Notify → Approve | Restore CloudTrail logging, re-enable GuardDuty |

**Approve a pending action:**
```bash
python -m detection.remediation_engine pending   # list pending
python -m detection.remediation_engine approve EVT_ID
```

---

## Configuration (environment variables)

| Variable | Default | Description |
|----------|---------|-------------|
| `AWS_REGION` | `us-east-1` | Primary AWS region to scan |
| `AWS_SCAN_REGIONS` | _(empty)_ | Comma-separated additional regions for GuardDuty |
| `CG_LOOKBACK_MINUTES` | `15` | How far back each scan looks |
| `CG_POLL_INTERVAL` | `60` | Monitor loop interval (seconds) |
| `CG_ALERT_THRESHOLD` | `30` | Min severity (0-100) to create an alert |
| `CG_REMEDIATION_ENABLED` | `false` | Enable live remediation actions |
| `CG_SNS_TOPIC_ARN` | _(empty)_ | SNS topic for alert notifications |
| `CG_USE_LOCAL_STORE` | `true` | Use local JSONL file (false = DynamoDB) |
| `CG_EVENTS_TABLE` | `cloud_guardian_events` | DynamoDB table name (if not local) |

---

## MITRE ATT&CK Coverage

35+ CloudTrail event mappings across:
- **Initial Access** — ConsoleLogin, AssumeRole anomalies
- **Persistence** — CreateUser, CreateAccessKey, CreateLoginProfile, PutRolePolicy
- **Privilege Escalation** — AttachUserPolicy, AttachRolePolicy, PutUserPolicy
- **Defense Evasion** — StopLogging, DeleteTrail, DeleteDetector, UpdateDetector
- **Credential Access** — GetSecretValue, GetParameter
- **Discovery** — DescribeInstances, ListBuckets, ListUsers, ListRoles
- **Lateral Movement** — UpdateFunctionCode
- **Exfiltration** — PutBucketAcl, PutBucketPolicy, ModifySnapshotAttribute, CopySnapshot
- **Impact** — DeleteBucket, DeleteDBInstance, TerminateInstances, RunInstances (crypto-mining)

---

## Running Tests

```bash
python -m pytest tests/ -v
```

47 tests covering: rule engine, severity scoring, ML anomaly detection,
storage layer, remediation gating (all risk tiers), and approval workflow.

---

## Project Structure

```
cloud-guardian/
├── config/
│   └── settings.py          # All configuration, sourced from env vars
├── detection/
│   ├── mitre_mappings.py    # 35+ CloudTrail → MITRE ATT&CK mappings
│   ├── cloudtrail_ingest.py # CloudTrail LookupEvents ingestion
│   ├── guardduty_ingest.py  # GuardDuty findings ingestion
│   ├── rule_engine.py       # Severity scoring + contextual risk modifiers
│   ├── orchestrator.py      # Main pipeline entrypoint (scan/monitor/check)
│   ├── storage.py           # Alert persistence (local JSONL or DynamoDB)
│   ├── playbooks.py         # Technique → remediation action mapping
│   ├── remediation_engine.py # Risk-tier gating + approval workflow
│   └── remediation_actions.py # Concrete boto3 remediation calls
├── ml/
│   ├── anomaly_detector.py  # Isolation Forest anomaly model
│   └── train_baseline.py    # Training script for historical CloudTrail data
├── infra/
│   ├── iam_policy_detection_readonly.json
│   └── iam_policy_remediation.json
├── tests/                   # 47 unit tests (no AWS required)
└── data/                    # Local event store + trained model
```

---

## Next Steps (v2 Roadmap)

- [ ] FastAPI REST layer for dashboard integration
- [ ] Multi-tenant cross-account IAM role support
- [ ] EventBridge + S3 ingestion for production-scale CloudTrail
- [ ] Kubernetes audit log integration
- [ ] Additional technique coverage: ECS task injection, RDS snapshot exfiltration
- [ ] Sigma rule import for community-contributed detections

---


## Synthetic Attack Simulator & Evaluation

Cloud Guardian includes a **safe offline simulator** that feeds synthetic CloudTrail-like events into the existing rule engine. It does not send attack traffic to AWS, change cloud resources, or execute remediation.

### Run one evaluation
```bash
python -m simulation.cli run
```

### Repeat on a schedule
```bash
# Run a batch every hour; stop with Ctrl+C
python -m simulation.cli schedule --interval-seconds 3600
```

The interval must be at least 60 seconds. Reports are saved as individual JSON files under `data/simulations/` by default. Set `CG_SIMULATION_DIR` to change the CLI output directory.

### API and dashboard
After starting the API and logging in, open **Attack Simulator** in the dashboard. The authenticated API routes are:
- `GET /simulator/scenarios` — available scenario metadata
- `POST /simulator/run?threshold=30` — run one evaluation (analyst role or higher)
- `GET /simulator/latest` — latest report for the authenticated organization
- `GET /simulator/history?limit=10` — recent run summaries for the organization

### Metrics and interpretation
Reports include precision, recall/detection rate, F1, accuracy, false-positive/negative rates, MITRE mapping accuracy, and a confusion matrix. Unavailable denominators are reported as `null`. MTTD is **0 seconds for in-process synthetic detections only**; it does not represent real CloudTrail ingestion latency. Remediation success is `null` because the simulator deliberately performs no remediation. The intentionally unmapped privilege-escalation scenario acts as a coverage-gap test and should appear as a false negative until a matching rule is implemented.

These results are scenario-suite measurements, not proof of real-world detection performance. Use a separate isolated AWS test account and separately approved reversible test cases before validating live ingestion or remediation.

### Test simulator logic
```bash
python -m pytest tests/test_simulation.py -q
```

## REST API

Start the API server:
```bash
uvicorn api.app:app --reload --port 8000
```

Interactive docs at **http://localhost:8000/docs**

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Credential check, GuardDuty status, model status |
| `GET` | `/coverage` | MITRE ATT&CK coverage + active alerts per tactic |
| `GET` | `/alerts` | List alerts (filter by severity, tactic, status, source) |
| `GET` | `/alerts/{id}` | Full alert detail with modifiers |
| `POST` | `/scan` | Trigger an on-demand detection scan |
| `GET` | `/remediation/pending` | List alerts awaiting human approval |
| `POST` | `/remediation/{id}/approve` | Approve and execute a pending remediation |
| `GET` | `/remediation/{id}/status` | Check remediation status for an alert |

### Example requests

```bash
# Health check
curl http://localhost:8000/health

# List critical alerts
curl "http://localhost:8000/alerts?risk_tier=critical&limit=10"

# Trigger a 30-minute scan
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"minutes": 30, "use_ml": true}'

# List alerts pending human approval
curl http://localhost:8000/remediation/pending

# Approve a remediation action
curl -X POST http://localhost:8000/remediation/EVT_ID/approve \
  -H "Content-Type: application/json" \
  -d '{"confirmed": true}'
```
