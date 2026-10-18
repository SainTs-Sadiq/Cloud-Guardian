# Attack Simulator Integration Notes

## Added
- `simulation/scenarios.py`: six synthetic scenarios, including a benign control and an intentionally unmapped positive scenario.
- `simulation/runner.py`: runs synthetic normalized events through the existing `detection.rule_engine.score_event` and writes immutable JSON evaluation reports.
- `simulation/evaluator.py`: confusion matrix, precision, recall, F1, accuracy, false-positive/negative rates, MITRE mapping accuracy, and explicitly scoped synthetic detection latency.
- `simulation/cli.py`: one-shot and interval scheduler commands.
- `api/routes/simulator.py`: authenticated, organization-scoped API endpoints.
- `tests/test_simulation.py`: scenario, metric, and persistence tests.
- Dashboard **Attack Simulator** page and README instructions.

## Safety boundaries
This is an offline simulator. It does not make AWS calls, change AWS resources, or execute remediation. Higher-fidelity live-account validation is intentionally separate.

## Validation performed in this environment
- Python `compileall` passed.
- Direct evaluator confusion-matrix/metric assertions passed.
- One full synthetic run completed and produced a report: 4 true positives, 0 false positives, 1 true negative, and 1 false negative at threshold 30. The false negative is the intentional unmapped `CreatePolicyVersion` scenario.
- Full pytest could not start because the environment lacks `aiosqlite` (`ModuleNotFoundError` while loading the repository's shared `tests/conftest.py`).
- Frontend production build could not run because Vite is not installed; dependency installation did not complete in this environment. Run `npm ci` and `npm run build` locally to validate the UI bundle.

## Important interpretation notes
- MTTD is zero for in-process synthetic detections and does not represent production telemetry latency.
- Remediation success is `null` because no remediation is executed.
- The scenario set is a small regression suite, not a statistically representative benchmark of real-world detection quality.
