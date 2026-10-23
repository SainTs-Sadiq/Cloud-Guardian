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

import socket

import httpx

logger = logging.getLogger("cloud_guardian.notifications")


def _validate_webhook_url(url: str, org_id) -> None:
    """Reject non-https and internal/loopback/link-local targets (SSRF guard)."""
    import ipaddress
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError(f"org {org_id} webhook must be a valid https URL")
    try:
        infos = socket.getaddrinfo(parsed.hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise ValueError(f"org {org_id} webhook hostname does not resolve: {e}")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast):
            raise ValueError(f"org {org_id} webhook resolves to a forbidden address ({ip})")

async def send_scan_notification(org, scan_run, severity_counts: dict) -> bool:
    """
    Best-effort webhook POST. Returns True if sent successfully, False on
    any failure or if no webhook is configured — never raises, since a
    notification failure should never fail the scan itself.
    """
    if not org.notification_webhook_url:
        return False

    try:
        _validate_webhook_url(org.notification_webhook_url, org.id)
    except ValueError as e:
        logger.warning(f"Refusing to send webhook for org {org.id}: {e}")
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
