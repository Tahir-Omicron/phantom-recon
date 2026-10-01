"""
Phantom Recon — Vulnerability Scanner.

Checks for common web vulnerabilities including missing security headers,
CORS misconfiguration, clickjacking, information disclosure, and more.

⚠️ DISCLAIMER: For authorized security testing only. Only test systems you
have explicit written authorization to test.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

import requests
from urllib.parse import urljoin, urlparse, urlencode

from phantom_recon.utils.logger import get_logger, create_progress, console

logger = get_logger(__name__)


@dataclass
class Vulnerability:
    """Represents a discovered vulnerability."""
    title: str
    severity: str  # critical, high, medium, low, info
    description: str
    evidence: str = ""
    remediation: str = ""
    cve: str = ""
    url: str = ""
    category: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cve": self.cve,
            "url": self.url,
            "category": self.category,
        }


# Security headers to check
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "medium",
        "description": "HTTP Strict Transport Security (HSTS) header is missing. "
                       "This allows downgrade attacks and cookie hijacking.",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' header.",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "description": "Content Security Policy (CSP) header is missing. "
                       "This increases the risk of XSS and data injection attacks.",
        "remediation": "Implement a restrictive Content-Security-Policy header.",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "description": "X-Content-Type-Options header is missing. "
                       "This allows MIME type sniffing.",
        "remediation": "Add 'X-Content-Type-Options: nosniff' header.",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "X-Frame-Options header is missing. "
                       "This allows the page to be framed (clickjacking).",
        "remediation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header.",
    },
    "X-XSS-Protection": {
        "severity": "low",
        "description": "X-XSS-Protection header is missing.",
        "remediation": "Add 'X-XSS-Protection: 1; mode=block' header (legacy browsers).",
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "Referrer-Policy header is missing. "
                       "The browser may leak referrer information.",
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' header.",
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": "Permissions-Policy header is missing. "
                       "Browser features are not explicitly restricted.",
        "remediation": "Add a restrictive Permissions-Policy header.",
    },
}


class VulnerabilityScanner:
    """
    Web vulnerability scanner.

    Checks for common security misconfigurations and vulnerabilities
    including missing headers, CORS issues, information disclosure,
    and clickjacking.

    Usage:
        scanner = VulnerabilityScanner(url="https://example.com")
        vulns = scanner.scan_all()
    """

    def __init__(
        self,
        url: str,
        timeout: float = 10.0,
        user_agent: Optional[str] = None,
        verify_ssl: bool = True,
    ):
        """
        Initialize the vulnerability scanner.

        Args:
            url: Target URL.
            timeout: Request timeout.
            user_agent: Custom User-Agent.
            verify_ssl: Verify SSL certificates.
        """
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": user_agent or (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
        })
        self.session.verify = verify_ssl
        self._vulns: list[Vulnerability] = []
        self._response: Optional[requests.Response] = None

    def _fetch(self) -> requests.Response:
        """Fetch the target URL."""
        if not self._response:
            self._response = self.session.get(
                self.url, timeout=self.timeout, allow_redirects=True
            )
        return self._response

    def _add_vuln(self, vuln: Vulnerability) -> None:
        """Add a vulnerability to the results."""
        vuln.url = vuln.url or self.url
        self._vulns.append(vuln)

    def check_security_headers(self) -> list[Vulnerability]:
        """
        Check for missing security headers.

        Returns:
            List of vulnerabilities for missing headers.
        """
        logger.info("Checking security headers...")
        resp = self._fetch()
        vulns = []

        for header_name, info in SECURITY_HEADERS.items():
            if header_name not in resp.headers:
                vuln = Vulnerability(
                    title=f"Missing {header_name} Header",
                    severity=info["severity"],
                    description=info["description"],
                    remediation=info["remediation"],
                    category="security_headers",
                )
                vulns.append(vuln)
                self._add_vuln(vuln)

        return vulns

    def check_cors(self) -> list[Vulnerability]:
        """
        Check for CORS misconfiguration.

        Returns:
            List of CORS-related vulnerabilities.
        """
        logger.info("Checking CORS configuration...")
        vulns = []

        # Test with arbitrary origin
        test_origins = [
            "https://evil.com",
            "https://attacker.example.com",
            f"https://{urlparse(self.url).netloc}.evil.com",
            "null",
        ]

        for origin in test_origins:
            try:
                resp = self.session.get(
                    self.url,
                    headers={"Origin": origin},
                    timeout=self.timeout,
                )

                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                if acao == "*":
                    vuln = Vulnerability(
                        title="CORS: Wildcard Access-Control-Allow-Origin",
                        severity="medium",
                        description="The server responds with Access-Control-Allow-Origin: * "
                                   "which allows any domain to make cross-origin requests.",
                        evidence=f"Access-Control-Allow-Origin: {acao}",
                        remediation="Restrict CORS to specific trusted origins.",
                        category="cors",
                    )
                    vulns.append(vuln)
                    self._add_vuln(vuln)
                    break

                elif acao == origin and origin != "null":
                    vuln = Vulnerability(
                        title="CORS: Origin Reflection",
                        severity="high",
                        description=f"The server reflects the Origin header ({origin}) "
                                   f"in Access-Control-Allow-Origin, allowing arbitrary "
                                   f"cross-origin access.",
                        evidence=f"Origin: {origin} → ACAO: {acao}",
                        remediation="Implement a strict origin whitelist for CORS.",
                        category="cors",
                    )
                    if acac.lower() == "true":
                        vuln.severity = "critical"
                        vuln.description += " Combined with Allow-Credentials, this can lead to data theft."
                    vulns.append(vuln)
                    self._add_vuln(vuln)

                elif acao == "null":
                    vuln = Vulnerability(
                        title="CORS: Null Origin Allowed",
                        severity="medium",
                        description="The server allows 'null' as a valid origin.",
                        evidence=f"Access-Control-Allow-Origin: null",
                        remediation="Do not allow 'null' as a CORS origin.",
                        category="cors",
                    )
                    vulns.append(vuln)
                    self._add_vuln(vuln)

            except requests.RequestException:
                continue

        return vulns

    def check_clickjacking(self) -> list[Vulnerability]:
        """
        Check for clickjacking vulnerability.

        Returns:
            List of clickjacking-related vulnerabilities.
        """
        logger.info("Checking clickjacking protection...")
        resp = self._fetch()
        vulns = []

        x_frame = resp.headers.get("X-Frame-Options", "")
        csp = resp.headers.get("Content-Security-Policy", "")

        has_xfo = bool(x_frame)
        has_csp_frame = "frame-ancestors" in csp.lower()

        if not has_xfo and not has_csp_frame:
            vuln = Vulnerability(
                title="Clickjacking: No Frame Protection",
                severity="medium",
                description="The page can be embedded in an iframe on any domain, "
                           "enabling clickjacking attacks.",
                remediation="Add 'X-Frame-Options: DENY' or CSP 'frame-ancestors none'.",
                category="clickjacking",
            )
            vulns.append(vuln)
            self._add_vuln(vuln)

        return vulns

    def check_information_disclosure(self) -> list[Vulnerability]:
        """
        Check for information disclosure in headers.

        Returns:
            List of info disclosure vulnerabilities.
        """
        logger.info("Checking information disclosure...")
        resp = self._fetch()
        vulns = []

        # Server header with version info
        server = resp.headers.get("Server", "")
        if server and any(char.isdigit() for char in server):
            vuln = Vulnerability(
                title="Information Disclosure: Server Version",
                severity="low",
                description=f"The Server header reveals version information: '{server}'.",
                evidence=f"Server: {server}",
                remediation="Remove or generalize the Server header to avoid version disclosure.",
                category="info_disclosure",
            )
            vulns.append(vuln)
            self._add_vuln(vuln)

        # X-Powered-By header
        powered_by = resp.headers.get("X-Powered-By", "")
        if powered_by:
            vuln = Vulnerability(
                title="Information Disclosure: X-Powered-By",
                severity="low",
                description=f"The X-Powered-By header reveals technology: '{powered_by}'.",
                evidence=f"X-Powered-By: {powered_by}",
                remediation="Remove the X-Powered-By header.",
                category="info_disclosure",
            )
            vulns.append(vuln)
            self._add_vuln(vuln)

        # X-AspNet-Version
        aspnet = resp.headers.get("X-AspNet-Version", "")
        if aspnet:
            vuln = Vulnerability(
                title="Information Disclosure: ASP.NET Version",
                severity="low",
                description=f"The X-AspNet-Version header reveals version: '{aspnet}'.",
                evidence=f"X-AspNet-Version: {aspnet}",
                remediation="Remove the X-AspNet-Version header in web.config.",
                category="info_disclosure",
            )
            vulns.append(vuln)
            self._add_vuln(vuln)

        return vulns

    def check_open_redirect(self) -> list[Vulnerability]:
        """
        Check for open redirect vulnerabilities.

        Returns:
            List of open redirect vulnerabilities.
        """
        logger.info("Checking open redirect...")
        vulns = []

        # Common redirect parameters
        redirect_params = ["url", "redirect", "next", "return", "returnUrl",
                          "goto", "target", "dest", "destination", "redir",
                          "redirect_uri", "continue", "return_to"]

        test_url = "https://evil.com"

        for param in redirect_params:
            try:
                test = f"{self.url}?{param}={test_url}"
                resp = self.session.get(
                    test,
                    timeout=self.timeout,
                    allow_redirects=False,
                )

                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if "evil.com" in location:
                        vuln = Vulnerability(
                            title=f"Open Redirect via '{param}' parameter",
                            severity="medium",
                            description=f"The '{param}' parameter allows redirecting to "
                                       f"external URLs without validation.",
                            evidence=f"URL: {test}\nLocation: {location}",
                            remediation="Validate redirect URLs against a whitelist of allowed domains.",
                            category="open_redirect",
                        )
                        vulns.append(vuln)
                        self._add_vuln(vuln)
            except requests.RequestException:
                continue

        return vulns

    def check_ssl_issues(self) -> list[Vulnerability]:
        """
        Check for basic SSL/TLS issues.

        Returns:
            List of SSL-related vulnerabilities.
        """
        logger.info("Checking SSL/TLS issues...")
        vulns = []
        parsed = urlparse(self.url)

        # Check if HTTP is available when HTTPS is used
        if parsed.scheme == "https":
            http_url = self.url.replace("https://", "http://")
            try:
                resp = self.session.get(
                    http_url, timeout=self.timeout, allow_redirects=False
                )
                if resp.status_code == 200:
                    vuln = Vulnerability(
                        title="HTTP Available Without Redirect",
                        severity="medium",
                        description="The HTTP version of the site is accessible and does not "
                                   "redirect to HTTPS.",
                        evidence=f"HTTP {http_url} returned status {resp.status_code}",
                        remediation="Configure automatic redirect from HTTP to HTTPS.",
                        category="ssl",
                    )
                    vulns.append(vuln)
                    self._add_vuln(vuln)
            except requests.RequestException:
                pass  # HTTP not available — good

        elif parsed.scheme == "http":
            vuln = Vulnerability(
                title="No HTTPS",
                severity="high",
                description="The site is served over unencrypted HTTP.",
                remediation="Enable HTTPS with a valid TLS certificate.",
                category="ssl",
            )
            vulns.append(vuln)
            self._add_vuln(vuln)

        return vulns

    def scan_all(self) -> list[dict[str, Any]]:
        """
        Run all vulnerability checks.

        Returns:
            List of vulnerability dictionaries sorted by severity.
        """
        logger.info(f"Scanning [bold magenta]{self.url}[/bold magenta] for vulnerabilities")
        start = datetime.now()

        self._vulns = []

        # Run all checks
        self.check_security_headers()
        self.check_cors()
        self.check_clickjacking()
        self.check_information_disclosure()
        self.check_open_redirect()
        self.check_ssl_issues()

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        self._vulns.sort(key=lambda v: severity_order.get(v.severity, 5))

        duration = (datetime.now() - start).total_seconds()
        logger.info(
            f"Found [bold {'red' if self._vulns else 'green'}]"
            f"{len(self._vulns)}[/bold {'red' if self._vulns else 'green'}] "
            f"vulnerabilities in {duration:.1f}s"
        )

        return [v.to_dict() for v in self._vulns]

    def get_summary(self) -> dict[str, int]:
        """Get vulnerability count by severity."""
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in self._vulns:
            severity = vuln.severity.lower()
            if severity in summary:
                summary[severity] += 1
        return summary
