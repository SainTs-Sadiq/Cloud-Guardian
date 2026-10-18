"""
Scan-completion notifications — a lightweight webhook POST, not a full
email/SES pipeline. If an org has configured notification_webhook_url
(see api/routes/organizations.py), we POST a JSON summary whenever a scan
run finishes with open HIGH or CRITICAL findings.

This intentionally does NOT try to distinguish "new this scan" from
"still open from before" — that would need severity-level breakdowns
tracked per ScanRun, which isn't built yet. It notifies whenever a
completed run's findings include high-severity items, which is still
useful (and simple, and testable) even though it's not de-duplicated
against previous notifications.
"""
import logging

import httpx

logger = logging.getLogger("cloud_guardian.notifications")


async def send_scan_notification(org, scan_run, severity_counts: dict) -> bool:
    """
    Best-effort webhook POST. Returns True if sent successfully, False on
    any failure or if no webhook is configured — never raises, since a
    notification failure should never fail the scan itself.
    """
    if not org.notification_webhook_url:
        return False

    high_or_critical = severity_counts.get("high", 0) + severity_counts.get("critical", 0)
    if high_or_critical == 0:
        return False

    payload = {
        "event": "cloud_guardian.scan_completed",
        "organization": org.name,
        "scan_run_id": scan_run.id,
        "status": scan_run.status,
        "trigger": scan_run.trigger,
        "findings_count": scan_run.findings_count,
        "high_or_critical_count": high_or_critical,
        "severity_breakdown": severity_counts,
        "completed_at": scan_run.completed_at.isoformat() if scan_run.completed_at else None,
    }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(org.notification_webhook_url, json=payload)
            response.raise_for_status()
        logger.info(f"Sent scan notification to org {org.id} webhook")
        return True
    except Exception as e:
        logger.warning(f"Failed to send scan notification for org {org.id}: {e}")
        return False
