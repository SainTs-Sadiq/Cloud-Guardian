# Cloud Guardian

Cloud Guardian is a multi-user cloud intrusion detection platform for AWS. It ingests CloudTrail, GuardDuty and VPC flow data, maps findings to MITRE ATT&CK techniques, scores them with rules plus an anomaly model, and drives SOC-style mitigation with risk-tiered remediation. A learning loop adapts scoring from analyst feedback.

## Stack

- Backend API: FastAPI (Python 3.13)
- Background work: Celery workers with Redis as broker
- Database: PostgreSQL (SQLite for local development)
- Frontend: React (Vite) single-page app
- Cloud: AWS (CloudTrail, GuardDuty, IAM, STS, SNS)

## Multi-tenancy and AWS access

Each organization connects its own AWS accounts. Cloud Guardian never uses long-lived customer keys. Each customer account exposes an IAM role that Cloud Guardian assumes through STS, and the trust policy requires an external ID generated per organization. Role ARNs are validated before they are stored.

Remediation uses two separate customer roles:

- An auto remediation role, used for low-risk actions that run without approval. It carries no destructive permissions.
- A destructive remediation role, used only for human-approved actions that change or delete resources.

Each action runs under only the session for its own role. The auto path cannot reach destructive handlers because its role lacks those permissions, and the code enforces the same split. Both roles must be registered for an account before remediation can run. If either one is missing, execution is blocked.

Remediation is fail-closed: a missing role, a missing session, or a failed guard returns an error (HTTP 409 on the API) and no action is taken.

## Architecture

- `api/`: FastAPI routes for accounts, scans, alerts, incidents, remediation, billing and dashboard data.
- `core/`: authentication, roles, rate limiting, AWS session handling and notifications.
- `detection/`: CloudTrail and GuardDuty ingest, rule engine, MITRE mappings, config scanner, and remediation actions.
- `ml/`: anomaly baseline training and scoring.
- `learning/`: adaptive feedback loop.
- `workers/`: Celery tasks and scheduling for scans and remediation.
- `db/` and `migrations/`: SQLAlchemy models and Alembic migrations.
- `simulation/`: attack simulator used for testing detections.
- `frontend/`: React dashboard.
- `infra/`: IAM policy documents (detection read-only, auto remediation, destructive remediation, combined remediation) and a CloudFormation template.

## Security controls

- Webhook SSRF guard: notification webhooks must use https. Hostnames are resolved and the request is refused if any resolved address is private, loopback, link-local, reserved or multicast.
- Authentication uses JWT with role checks (`require_role`, `require_min_role`).
- Rate limiting on API routes.
- Fail-closed remediation as described above.

## Risk tiers

| Tier | Behavior |
|------|----------|
| LOW | Auto-executed under the auto remediation role (for example, blocking a public S3 ACL) |
| MEDIUM | Notified, requires approval (for example, disabling an access key) |
| HIGH | Notified, requires approval (for example, detaching an IAM policy or isolating an instance) |
| CRITICAL | Notified, requires approval (for example, restoring CloudTrail logging) |

Destructive handlers always require approval and the destructive role.

## MITRE ATT&CK coverage

CloudTrail event mappings cover initial access, persistence, privilege escalation, defense evasion, credential access, discovery, lateral movement, exfiltration and impact. Mappings are validated against the ATT&CK catalog in CI.

## Local development

Requirements: Python 3.13 and Node.js.

```bash
pip install -r requirements.txt
PYTHONPATH=$PWD python -m pytest -q
```

Frontend:

```bash
cd frontend
npm ci
npm run build
```

Docker Compose is also provided (`docker-compose.yml`) for Postgres, Redis and the services.

## Testing and CI

GitHub Actions runs on pushes and pull requests to `main`, using Python 3.13. The pipeline validates the ATT&CK mapping catalog and runs the full pytest suite. Current status: 381 tests passing.

## Deployment

Deployment is leaning toward Render only, not final. The planned layout is a web service (API), a background worker (Celery), a PostgreSQL database, a Redis instance, and a static site for the frontend.

## Configuration

Settings are read from environment variables in `config/settings.py`. Key variables include `AWS_REGION`, `CG_REMEDIATION_ENABLED`, `CG_SNS_TOPIC_ARN` and `CG_USE_LOCAL_STORE`. See that file for the full list.
