import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from config.settings import REMEDIATION
from detection.mitre_mappings import RiskTier
from detection.playbooks import ActionType, get_playbook
from detection.rule_engine import DetectedAlert
from detection.storage import AlertStore

logger = logging.getLogger("cloud_guardian.remediation")

class RemediationDecision(str, Enum):
    AUTO_EXECUTED = "auto_executed"
    PENDING_APPROVAL = "pending_approval"
    DRY_RUN_LOGGED = "dry_run_logged"
    NO_PLAYBOOK = "no_playbook"
    NOTIFY_ONLY = "notify_only"

@dataclass
class RemediationResult:
    alert_event_id: str
    decision: RemediationDecision
    action: ActionType
    action_risk_tier: str
    detail: str
    executed_at: datetime

def evaluate_and_act(alert, store):
    playbook = get_playbook(alert)

    if playbook is None:

        return RemediationResult(alert.event_id, RemediationDecision.NO_PLAYBOOK, None, None,
            f"No remediation playbook defined for technique {alert.technique_id}", datetime.now(timezone.utc))


    store.save(alert)

    if playbook.action == ActionType.NOTIFY_ONLY:
        store.update_status(alert.event_id, "notified", playbook.action.value)
        _send_notification(alert, playbook, auto=False)
        return RemediationResult(alert.event_id, RemediationDecision.NOTIFY_ONLY, playbook.action,
            playbook.action_risk_tier.value, playbook.description, datetime.now(timezone.utc))

    if not REMEDIATION.enabled:
        detail = f"DRY RUN (remediation disabled): would execute '{playbook.action.value}' — {playbook.description}"
        store.update_status(alert.event_id, "dry_run", playbook.action.value)
        logger.info(f"[{alert.event_id}] {detail}")
        return RemediationResult(alert.event_id, RemediationDecision.DRY_RUN_LOGGED, playbook.action,
            playbook.action_risk_tier.value, detail, datetime.now(timezone.utc))

    if playbook.action_risk_tier.value in REMEDIATION.auto_approve_tiers:
        success, detail = _execute_action(alert, playbook)
        store.update_status(alert.event_id, "remediated" if success else "remediation_failed", playbook.action.value)
        _send_notification(alert, playbook, auto=True)
        logger.warning(f"[{alert.event_id}] AUTO-REMEDIATED: {detail}")
        return RemediationResult(alert.event_id, RemediationDecision.AUTO_EXECUTED, playbook.action,
            playbook.action_risk_tier.value, detail, datetime.now(timezone.utc))


    detail = (f"Action '{playbook.action.value}' ({playbook.action_risk_tier.value} risk) "
              f"requires approval: {playbook.description}")
    store.update_status(alert.event_id, "pending_approval", playbook.action.value)
    _send_notification(alert, playbook, auto=False, requires_approval=True)
    logger.warning(f"[{alert.event_id}] PENDING APPROVAL: {detail}")
    return RemediationResult(alert.event_id, RemediationDecision.PENDING_APPROVAL, playbook.action,
        playbook.action_risk_tier.value, detail, datetime.now(timezone.utc))

def approve_remediation(event_id, store):
    record = store.get_by_id(event_id)
    if record is None:
        raise ValueError(f"No alert found with event_id {event_id}")
    if record.get("status") != "pending_approval":
        raise ValueError(f"Alert {event_id} is not pending approval (status: {record.get('status')})")
    alert = DetectedAlert(
        event_id=record["event_id"], source=record["source"], event_name=record["event_name"],
        event_time=datetime.fromisoformat(record["event_time"]),
        technique_id=record["technique_id"], technique_name=record["technique_name"],
        tactic=record["tactic"], severity=record["severity"], risk_tier=record["risk_tier"],
        description=record["description"], actor_arn=record["actor_arn"],
        account_id=record["account_id"], region=record["region"],
        source_ip=record.get("source_ip"), modifiers=record.get("modifiers", []), raw_event={},
    )
    playbook = get_playbook(alert)
    if playbook is None:
        raise ValueError(f"No playbook found for technique {alert.technique_id}")
    success, detail = _execute_action(alert, playbook)
    store.update_status(event_id, "remediated" if success else "remediation_failed", playbook.action.value)
    logger.warning(f"[{event_id}] APPROVED & EXECUTED: {detail}")
    return RemediationResult(event_id, RemediationDecision.AUTO_EXECUTED, playbook.action,
        playbook.action_risk_tier.value, detail, datetime.now(timezone.utc))

def _execute_action(alert, playbook):
    from detection import remediation_actions as actions
    try:
        handler = getattr(actions, playbook.action.value, None)
        if handler is None:
            return False, f"No handler implemented for action '{playbook.action.value}'"
        return handler(alert)
    except Exception as e:
        logger.error(f"[{alert.event_id}] Remediation action failed: {e}", exc_info=True)
        return False, f"Execution error: {e}"

def _send_notification(alert, playbook, auto, requires_approval=False):
    if not REMEDIATION.notification_topic_arn:
        return
    import boto3
    from config.settings import AWS
    subject = (f"[Cloud Guardian] Auto-remediated: {alert.technique_id} ({alert.severity}/100)" if auto
               else f"[Cloud Guardian] {'APPROVAL NEEDED' if requires_approval else 'Alert'}: {alert.technique_id} ({alert.severity}/100)")
    message = (f"Technique: {alert.technique_id} - {alert.technique_name}\nTactic: {alert.tactic}\n"
               f"Severity: {alert.severity}/100 ({alert.risk_tier})\nEvent: {alert.event_name}\n"
               f"Actor: {alert.actor_arn}\nRegion: {alert.region}\nAction: {playbook.description}\n")
    if requires_approval:
        message += f"\nApprove: python -m detection.remediation_engine approve {alert.event_id}\n"
    try:
        kwargs = {}
        if AWS.profile: kwargs["profile_name"] = AWS.profile
        boto3.Session(**kwargs).client("sns", region_name=AWS.region).publish(
            TopicArn=REMEDIATION.notification_topic_arn, Subject=subject[:100], Message=message)
    except Exception as e:
        logger.error(f"SNS notification failed: {e}")

def _cli():
    import argparse, sys
    from detection.storage import get_store
    parser = argparse.ArgumentParser(description="Cloud Guardian remediation engine")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("approve").add_argument("event_id")
    sub.add_parser("pending")
    args = parser.parse_args()
    store = get_store()
    if args.command == "approve":
        try:
            r = approve_remediation(args.event_id, store)
            print(f"Decision: {r.decision.value}\nDetail: {r.detail}")
        except ValueError as e:
            print(f"Error: {e}"); sys.exit(1)
    elif args.command == "pending":
        pending = [r for r in store.get_recent(100) if r.get("status") == "pending_approval"]
        if not pending: print("No alerts pending approval.")
        for r in pending:
            print(f"\n{r['event_id']}: {r['technique_id']} — {r['technique_name']}")
            print(f"  Severity: {r['severity']}/100 ({r['risk_tier']})")
            print(f"  Approve: python -m detection.remediation_engine approve {r['event_id']}")

if __name__ == "__main__":
    _cli()
