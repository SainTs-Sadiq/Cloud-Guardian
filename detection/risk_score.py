"""
Risk score computation — a transparent, documented formula rather than a
black box. Feeds GET /dashboard/summary and GET /dashboard/risk-score.

Formula:
  risk_points = 10*critical + 5*high + 2*medium + 1*low   (open findings only)
  posture_score = max(0, 100 - min(100, risk_points))     (0=worst, 100=best)

This is intentionally simple: a weighted count of open findings by
severity, capped and inverted into a 0-100 "how healthy is this org"
number. It is NOT a CIS/FSBP-certified compliance score — see
detection/compliance_mappings.py for the (separately reported) control
coverage rollup.
"""

SEVERITY_WEIGHTS = {"critical": 10, "high": 5, "medium": 2, "low": 1}


def compute_risk_score(severity_counts: dict[str, int]) -> dict:
    """
    Args:
        severity_counts: {"critical": n, "high": n, "medium": n, "low": n} — open findings only.

    Returns:
        {"risk_points": int, "posture_score": int, "grade": str, "breakdown": {...}}
    """
    breakdown = {
        tier: {"count": severity_counts.get(tier, 0), "weight": weight,
               "points": severity_counts.get(tier, 0) * weight}
        for tier, weight in SEVERITY_WEIGHTS.items()
    }
    risk_points = sum(b["points"] for b in breakdown.values())
    posture_score = max(0, 100 - min(100, risk_points))

    if posture_score >= 90:
        grade = "A"
    elif posture_score >= 75:
        grade = "B"
    elif posture_score >= 60:
        grade = "C"
    elif posture_score >= 40:
        grade = "D"
    else:
        grade = "F"

    return {
        "risk_points": risk_points,
        "posture_score": posture_score,
        "grade": grade,
        "breakdown": breakdown,
    }
