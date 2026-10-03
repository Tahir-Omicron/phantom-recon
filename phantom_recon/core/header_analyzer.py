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

        is_https = self.url.lower().startswith("https://")

        # ── Strict-Transport-Security ──
        hsts = headers.get("Strict-Transport-Security", "")
        if is_https:
            hsts_secure = bool(hsts and "max-age" in hsts.lower())
            hsts_desc = (
                "Enforces encrypted HTTPS connections via HSTS." if hsts
                else "HTTP Strict-Transport-Security (HSTS) is missing on HTTPS service. Without HSTS, browsers can downgrade connections to plaintext HTTP, leaving sessions vulnerable to SSL stripping."
            )
            hsts_remedy = "" if hsts else "Nginx: add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always; | Apache: Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\""
            hsts_sev = "info" if hsts else "medium"
        else:
            hsts_secure = False
            hsts_desc = "Target is accessed over unencrypted plaintext HTTP. HSTS cannot be enforced on plaintext HTTP (RFC 6797); enable HTTPS first."
            hsts_remedy = "Deploy SSL/TLS and redirect all plaintext HTTP traffic to HTTPS before enforcing HSTS."
            hsts_sev = "info"

        self._checks.append(HeaderCheck(
            header="Strict-Transport-Security",
            present=bool(hsts),
            value=hsts,
            secure=hsts_secure,
            description=hsts_desc,
            recommendation=hsts_remedy,
            severity=hsts_sev,
        ))

        # ── Content-Security-Policy ──
        csp = headers.get("Content-Security-Policy", "")
        self._checks.append(HeaderCheck(
            header="Content-Security-Policy",
            present=bool(csp),
            value=csp[:200] + "..." if len(csp) > 200 else csp,
            secure=bool(csp and "unsafe-inline" not in csp and "unsafe-eval" not in csp),
            description=(
                "Content-Security-Policy (CSP) is actively enforced." if csp
                else "Content-Security-Policy (CSP) header is absent. Without CSP, the browser executes unvetted scripts and frames, drastically elevating impact from Cross-Site Scripting (XSS) and code injection."
            ),
            recommendation=(
                "" if csp
                else "Nginx: add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; frame-ancestors 'self';\" always; | Apache: Header always set Content-Security-Policy \"default-src 'self'; script-src 'self';\""
            ),
            severity="info" if (csp and "unsafe" not in csp) else "medium",
        ))

        # ── X-Content-Type-Options ──
        xcto = headers.get("X-Content-Type-Options", "")
        self._checks.append(HeaderCheck(
            header="X-Content-Type-Options",
            present=bool(xcto),
            value=xcto,
            secure=xcto.lower() == "nosniff",
            description=(
                "MIME-sniffing prevention is enforced (nosniff)." if xcto
                else "X-Content-Type-Options header is missing. Browsers may ignore declared MIME types and interpret uploaded non-executable files as executable HTML/JavaScript."
            ),
            recommendation=(
                "" if xcto
                else "Nginx: add_header X-Content-Type-Options \"nosniff\" always; | Apache: Header always set X-Content-Type-Options \"nosniff\""
            ),
            severity="info" if xcto else "low",
        ))

        # ── X-Frame-Options & Clickjacking Protection ──
        xfo = headers.get("X-Frame-Options", "")
        has_csp_frame = "frame-ancestors" in csp.lower()
        has_xfo = xfo.upper() in ("DENY", "SAMEORIGIN")
        is_frame_protected = has_xfo or has_csp_frame

        if has_csp_frame:
            xfo_desc = "Clickjacking protection enforced via CSP 'frame-ancestors' directive (modern standard)."
            xfo_remedy = ""
            xfo_sev = "info"
        elif has_xfo:
            xfo_desc = f"Clickjacking protection enabled via X-Frame-Options ({xfo})."
            xfo_remedy = ""
            xfo_sev = "info"
        else:
            xfo_desc = "UI frame protection is absent (both X-Frame-Options and CSP frame-ancestors missing). The web application can be framed inside external websites, enabling clickjacking attacks."
            xfo_remedy = "Nginx: add_header X-Frame-Options \"SAMEORIGIN\" always; (or configure CSP frame-ancestors 'self') | Apache: Header always set X-Frame-Options \"SAMEORIGIN\""
            xfo_sev = "medium"

        self._checks.append(HeaderCheck(
            header="X-Frame-Options",
            present=bool(xfo or has_csp_frame),
            value=xfo or ("CSP: frame-ancestors" if has_csp_frame else ""),
            secure=is_frame_protected,
            description=xfo_desc,
            recommendation=xfo_remedy,
            severity=xfo_sev,
        ))

        # ── X-XSS-Protection ──
        xxp = headers.get("X-XSS-Protection", "")
        self._checks.append(HeaderCheck(
            header="X-XSS-Protection",
            present=bool(xxp),
            value=xxp,
            secure="1" in xxp and "mode=block" in xxp,
            description=(
                "Legacy XSS auditor filter configured." if xxp
                else "X-XSS-Protection header is not configured for legacy browsers."
            ),
            recommendation=(
                "" if xxp
                else "Nginx: add_header X-XSS-Protection \"1; mode=block\" always; | Apache: Header always set X-XSS-Protection \"1; mode=block\""
            ),
            severity="info" if xxp else "low",
        ))

        # ── Referrer-Policy ──
        rp = headers.get("Referrer-Policy", "")
        self._checks.append(HeaderCheck(
            header="Referrer-Policy",
            present=bool(rp),
            value=rp,
            secure=bool(rp),
            description=(
                f"Referrer-Policy enforced: {rp}" if rp
                else "Referrer-Policy is missing. Browsers may leak private endpoint query strings, reset tokens, or confidential path URLs in outgoing HTTP Referer headers."
            ),
            recommendation=(
                "" if rp
                else "Nginx: add_header Referrer-Policy \"strict-origin-when-cross-origin\" always; | Apache: Header always set Referrer-Policy \"strict-origin-when-cross-origin\""
            ),
            severity="info" if rp else "low",
        ))

        # ── Permissions-Policy ──
        pp = headers.get("Permissions-Policy", "") or headers.get("Feature-Policy", "")
        self._checks.append(HeaderCheck(
            header="Permissions-Policy",
            present=bool(pp),
            value=pp[:200] + "..." if len(pp) > 200 else pp,
            secure=bool(pp),
            description=(
                "Permissions-Policy configured to restrict browser APIs." if pp
                else "Permissions-Policy header is absent. Browser hardware APIs (camera, microphone, geolocation, payment) are not explicitly restricted."
            ),
            recommendation=(
                "" if pp
                else "Nginx: add_header Permissions-Policy \"camera=(), microphone=(), geolocation=(), payment=()\" always; | Apache: Header always set Permissions-Policy \"camera=(), microphone=(), geolocation=()\""
            ),
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
            description=(
                f"Server header exposes exact software version ({server}), assisting automated exploit search."
                if has_version else f"Server banner: {server or 'Not exposed (secure)'}"
            ),
            recommendation=(
                "Nginx: add 'server_tokens off;' in http block (/etc/nginx/nginx.conf) | Apache: set 'ServerTokens Prod' and 'ServerSignature Off' in httpd.conf"
                if has_version else ""
            ),
            severity="low" if has_version else "info",
        ))

        # ── X-Powered-By ──
        xpb = headers.get("X-Powered-By", "")
        self._checks.append(HeaderCheck(
            header="X-Powered-By",
            present=bool(xpb),
            value=xpb,
            secure=not bool(xpb),
            description=(
                f"X-Powered-By header exposes backend application runtime: {xpb}."
                if xpb else "X-Powered-By not present (good security posture)."
            ),
            recommendation=(
                "PHP: expose_php = Off in php.ini | Express: app.disable('x-powered-by'); | Nginx: proxy_hide_header X-Powered-By;"
                if xpb else ""
            ),
            severity="low" if xpb else "info",
        ))

        # ── Alt-Svc (HTTP/3 & QUIC Modern Transport) ──
        alt_svc = headers.get("Alt-Svc", "")
        has_h3 = bool(alt_svc and ("h3" in alt_svc or "quic" in alt_svc))
        self._checks.append(HeaderCheck(
            header="Alt-Svc",
            present=bool(alt_svc),
            value=alt_svc[:120] + "..." if len(alt_svc) > 120 else alt_svc,
            secure=True,
            description=(
                f"Modern HTTP/3 (QUIC) transport advertised via Alt-Svc: {alt_svc[:50]}..."
                if has_h3 else "Alt-Svc header indicates standard HTTP transport."
            ),
            recommendation="",
            severity="info",
        ))

        # ── Calculate grade ──
        self._grade = self._calculate_grade()

        # ── Deep CSP Evaluation ──
        csp_eval = self.evaluate_csp_deep(headers.get("Content-Security-Policy", ""))

        return {
            "url": self.url,
            "grade": self._grade,
            "status_code": resp.status_code,
            "timestamp": datetime.now().isoformat(),
            "headers_checked": len(self._checks),
            "secure_count": sum(1 for c in self._checks if c.secure),
            "insecure_count": sum(1 for c in self._checks if not c.secure),
            "csp_analysis": csp_eval,
            "checks": [c.to_dict() for c in self._checks],
            "all_headers": dict(resp.headers),
        }

    @staticmethod
    def evaluate_csp_deep(csp: str) -> dict[str, Any]:
        """
        Deep security evaluation of a Content-Security-Policy string.
        Pinpoints bypass vectors, insecure wildcards, and missing guards.
        """
        if not csp:
            return {"configured": False, "score": 0, "issues": ["No Content-Security-Policy header configured."]}

        directives: dict[str, list[str]] = {}
        for part in csp.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            dir_name = tokens[0].lower()
            dir_values = [t.lower() for t in tokens[1:]]
            directives[dir_name] = dir_values

        issues: list[str] = []
        score = 100

        script_src = directives.get("script-src", directives.get("default-src", []))
        if not script_src:
            issues.append("Missing both 'script-src' and 'default-src' directives.")
            score -= 30
        else:
            if "'unsafe-inline'" in script_src:
                issues.append("'script-src' contains 'unsafe-inline' — vulnerable to XSS injection.")
                score -= 25
            if "'unsafe-eval'" in script_src:
                issues.append("'script-src' contains 'unsafe-eval' — allows dynamic JavaScript execution.")
                score -= 15
            if "*" in script_src:
                issues.append("'script-src' allows wildcard '*' source — unrestricted script origin.")
                score -= 25

        object_src = directives.get("object-src", directives.get("default-src", []))
        if not object_src or "'none'" not in object_src:
            issues.append("Missing 'object-src 'none'' — legacy plugin injection possible.")
            score -= 15

        if "base-uri" not in directives:
            issues.append("Missing 'base-uri' directive — document base URL can be hijacked via <base href>.")
            score -= 10

        return {
            "configured": True,
            "raw_policy": csp,
            "directives_count": len(directives),
            "score": max(0, score),
            "is_strict": len(issues) == 0,
            "issues": issues,
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
