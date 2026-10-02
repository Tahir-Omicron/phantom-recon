"""
Phantom Recon — Security Posture & Health Score Engine (v1.8.0).

Calculates an executive 0-100 security health score and letter grade (A+ to F)
based on verified vulnerability findings, CVSS weights, and category posture.

⚠️ DISCLAIMER: For authorized security testing only.
"""

from typing import Any, Optional


def calculate_security_score(
    vulnerabilities: list[dict[str, Any]],
    extra_metrics: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    Calculate an executive security health score (0-100) and letter grade.

    Deduction Weights:
      - Critical: -30 points per confirmed finding
      - High:     -15 points per confirmed finding
      - Medium:   -7 points per confirmed finding
      - Low:      -3 points per confirmed finding
      - Info:      0 points

    Args:
        vulnerabilities: List of verified vulnerability dictionaries.
        extra_metrics: Optional dictionary containing additional scan stats.

    Returns:
        Structured scorecard dictionary with score, grade, verdict, and category breakdowns.
    """
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    category_counts: dict[str, dict[str, int]] = {
        "web_app": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "cloud": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "crypto_ssl": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "identity_dns": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "network": {"critical": 0, "high": 0, "medium": 0, "low": 0},
    }

    for v in vulnerabilities:
        sev = str(v.get("severity", "info")).lower()
        if sev in sev_counts:
            sev_counts[sev] += 1

        cat = str(v.get("category", "")).lower()
        target_cat = "web_app"
        if "cloud" in cat or "bucket" in cat or "s3" in cat:
            target_cat = "cloud"
        elif "ssl" in cat or "tls" in cat or "crypto" in cat:
            target_cat = "crypto_ssl"
        elif "dns" in cat or "email" in cat or "spf" in cat or "dmarc" in cat or "whois" in cat:
            target_cat = "identity_dns"
        elif "port" in cat or "network" in cat or "host" in cat:
            target_cat = "network"

        if sev in category_counts[target_cat]:
            category_counts[target_cat][sev] += 1

    # Calculate global deduction
    critical_deduction = sev_counts["critical"] * 30
    high_deduction = sev_counts["high"] * 15
    medium_deduction = sev_counts["medium"] * 7
    low_deduction = sev_counts["low"] * 3
    total_deduction = critical_deduction + high_deduction + medium_deduction + low_deduction

    score = max(0, 100 - total_deduction)

    # Letter Grade & Executive Verdict
    if score >= 95:
        grade = "A+"
        verdict = "Fortified Posture — Zero High-Risk Flaws Detected"
        color = "green"
    elif score >= 85:
        grade = "A"
        verdict = "Hardened Defense — Strong Defensive Configuration"
        color = "green"
    elif score >= 70:
        grade = "B"
        verdict = "Acceptable Posture — Minor Weaknesses Requiring Attention"
        color = "cyan"
    elif score >= 50:
        grade = "C"
        verdict = "Moderate Risk — Actionable Vulnerabilities Detected"
        color = "yellow"
    elif score >= 35:
        grade = "D"
        verdict = "Elevated Exposure — Priority Remediation Strongly Recommended"
        color = "red"
    else:
        grade = "F"
        verdict = "Critical Exposure — Immediate Incident Response Required"
        color = "bold white on red"

    # Category Health Scores (0-100)
    category_scores = {}
    for cat_name, counts in category_counts.items():
        cat_ded = (
            counts["critical"] * 30
            + counts["high"] * 15
            + counts["medium"] * 7
            + counts["low"] * 3
        )
        cat_score = max(0, 100 - cat_ded)
        category_scores[cat_name] = {
            "score": cat_score,
            "grade": "A" if cat_score >= 85 else ("B" if cat_score >= 70 else ("C" if cat_score >= 50 else "F")),
        }

    return {
        "score": score,
        "grade": grade,
        "verdict": verdict,
        "color": color,
        "deductions": {
            "critical": critical_deduction,
            "high": high_deduction,
            "medium": medium_deduction,
            "low": low_deduction,
            "total": total_deduction,
        },
        "findings_count": sev_counts,
        "category_scores": category_scores,
    }
