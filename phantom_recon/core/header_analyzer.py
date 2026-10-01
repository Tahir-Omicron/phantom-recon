"""
Phantom Recon — HTTP Header Security Analyzer.

Analyzes HTTP response headers for security best practices,
grades the configuration, and provides remediation recommendations.

⚠️ DISCLAIMER: For authorized security testing only.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

import requests

from phantom_recon.utils.logger import get_logger, console

logger = get_logger(__name__)


@dataclass
class HeaderCheck:
    """Result of a single header check."""
    header: str
    present: bool
    value: str = ""
    secure: bool = False
    description: str = ""
    recommendation: str = ""
    severity: str = "info"  # critical, high, medium, low, info

    def to_dict(self) -> dict[str, Any]:
        return {
            "header": self.header,
            "present": self.present,
            "value": self.value,
            "secure": self.secure,
            "description": self.description,
            "recommendation": self.recommendation,
            "severity": self.severity,
        }


class HeaderAnalyzer:
    """
    HTTP security header analyzer.

    Checks response headers against security best practices and provides
    a letter grade (A-F) with detailed recommendations.

    Usage:
        analyzer = HeaderAnalyzer(url="https://example.com")
        results = analyzer.analyze()
    """

    def __init__(self, url: str, timeout: float = 10.0):
        """
        Initialize the header analyzer.

        Args:
            url: Target URL.
            timeout: Request timeout.
        """
        self.url = url
        self.timeout = timeout
        self._checks: list[HeaderCheck] = []
        self._grade: str = ""

    def analyze(self) -> dict[str, Any]:
        """
        Analyze all security headers.

        Returns:
            Dictionary with header analysis results and grade.
        """
        logger.info(f"Analyzing headers for [bold magenta]{self.url}[/bold magenta]")

        try:
            resp = requests.get(
                self.url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False,
            )
        except requests.RequestException as e:
            return {"error": str(e), "url": self.url}

        headers = resp.headers
        self._checks = []

        # ── Strict-Transport-Security ──
        hsts = headers.get("Strict-Transport-Security", "")
        self._checks.append(HeaderCheck(
            header="Strict-Transport-Security",
            present=bool(hsts),
            value=hsts,
            secure=bool(hsts and "max-age" in hsts.lower()),
            description="Enforces HTTPS connections." if hsts else "HSTS not set — downgrade attacks possible.",
            recommendation="" if hsts else "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            severity="info" if hsts else "high",
        ))

        # ── Content-Security-Policy ──
        csp = headers.get("Content-Security-Policy", "")
        self._checks.append(HeaderCheck(
            header="Content-Security-Policy",
            present=bool(csp),
            value=csp[:200] + "..." if len(csp) > 200 else csp,
            secure=bool(csp and "unsafe-inline" not in csp and "unsafe-eval" not in csp),
            description="CSP configured." if csp else "No CSP — higher risk of XSS.",
            recommendation="" if csp else "Implement a strict Content-Security-Policy.",
            severity="info" if (csp and "unsafe" not in csp) else "medium",
        ))

        # ── X-Content-Type-Options ──
        xcto = headers.get("X-Content-Type-Options", "")
        self._checks.append(HeaderCheck(
            header="X-Content-Type-Options",
            present=bool(xcto),
            value=xcto,
            secure=xcto.lower() == "nosniff",
            description="MIME sniffing prevented." if xcto else "MIME sniffing not prevented.",
            recommendation="" if xcto else "Add: X-Content-Type-Options: nosniff",
            severity="info" if xcto else "low",
        ))

        # ── X-Frame-Options ──
        xfo = headers.get("X-Frame-Options", "")
        self._checks.append(HeaderCheck(
            header="X-Frame-Options",
            present=bool(xfo),
            value=xfo,
            secure=xfo.upper() in ("DENY", "SAMEORIGIN"),
            description="Clickjacking protection enabled." if xfo else "No clickjacking protection.",
            recommendation="" if xfo else "Add: X-Frame-Options: DENY",
            severity="info" if xfo else "medium",
        ))

        # ── X-XSS-Protection ──
        xxp = headers.get("X-XSS-Protection", "")
        self._checks.append(HeaderCheck(
            header="X-XSS-Protection",
            present=bool(xxp),
            value=xxp,
            secure="1" in xxp and "mode=block" in xxp,
            description="XSS protection set." if xxp else "Browser XSS filter not configured.",
            recommendation="" if xxp else "Add: X-XSS-Protection: 1; mode=block",
            severity="info" if xxp else "low",
        ))

        # ── Referrer-Policy ──
        rp = headers.get("Referrer-Policy", "")
        self._checks.append(HeaderCheck(
            header="Referrer-Policy",
            present=bool(rp),
            value=rp,
            secure=bool(rp),
            description=f"Referrer policy: {rp}" if rp else "No referrer policy set.",
            recommendation="" if rp else "Add: Referrer-Policy: strict-origin-when-cross-origin",
            severity="info" if rp else "low",
        ))

        # ── Permissions-Policy ──
        pp = headers.get("Permissions-Policy", "") or headers.get("Feature-Policy", "")
        self._checks.append(HeaderCheck(
            header="Permissions-Policy",
            present=bool(pp),
            value=pp[:200] + "..." if len(pp) > 200 else pp,
            secure=bool(pp),
            description="Permissions policy configured." if pp else "No permissions policy.",
            recommendation="" if pp else "Add a Permissions-Policy to restrict browser features.",
            severity="info" if pp else "low",
        ))

        # ── Server ──
        server = headers.get("Server", "")
        has_version = bool(server and any(c.isdigit() for c in server))
        self._checks.append(HeaderCheck(
            header="Server",
            present=bool(server),
            value=server,
            secure=not has_version,
            description=f"Server: {server}" + (" (version exposed)" if has_version else ""),
            recommendation="Remove version info from Server header." if has_version else "",
            severity="low" if has_version else "info",
        ))

        # ── X-Powered-By ──
        xpb = headers.get("X-Powered-By", "")
        self._checks.append(HeaderCheck(
            header="X-Powered-By",
            present=bool(xpb),
            value=xpb,
            secure=not bool(xpb),
            description=f"Technology exposed: {xpb}" if xpb else "X-Powered-By not present (good).",
            recommendation="Remove the X-Powered-By header." if xpb else "",
            severity="low" if xpb else "info",
        ))

        # ── Calculate grade ──
        self._grade = self._calculate_grade()

        return {
            "url": self.url,
            "grade": self._grade,
            "status_code": resp.status_code,
            "timestamp": datetime.now().isoformat(),
            "headers_checked": len(self._checks),
            "secure_count": sum(1 for c in self._checks if c.secure),
            "insecure_count": sum(1 for c in self._checks if not c.secure),
            "checks": [c.to_dict() for c in self._checks],
            "all_headers": dict(resp.headers),
        }

    def _calculate_grade(self) -> str:
        """Calculate letter grade based on security header checks."""
        total = len(self._checks)
        if total == 0:
            return "F"

        secure_count = sum(1 for c in self._checks if c.secure)
        ratio = secure_count / total

        if ratio >= 0.9:
            return "A"
        elif ratio >= 0.75:
            return "B"
        elif ratio >= 0.6:
            return "C"
        elif ratio >= 0.4:
            return "D"
        else:
            return "F"

    def get_recommendations(self) -> list[str]:
        """Get list of remediation recommendations."""
        return [
            c.recommendation
            for c in self._checks
            if c.recommendation
        ]
