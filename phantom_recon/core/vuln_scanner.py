"""
Phantom Recon — Advanced Vulnerability Scanner (v1.1.0).

Performs precision web vulnerability assessments with exact location tracking,
clickable direct links, proof-of-concept (PoC) cURL generators, and false-positive
resilient validation.

⚠️ DISCLAIMER: For authorized security testing only. Only test systems you
have explicit written authorization to test.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests

from phantom_recon.utils.logger import console, create_progress, get_logger

logger = get_logger(__name__)


@dataclass
class Vulnerability:
    """
    Represents a discovered security vulnerability with exact location
    and reproducible proof-of-concept metadata.
    """
    title: str
    severity: str  # critical, high, medium, low, info
    description: str
    location: str = ""           # Exact place: e.g. "Header: CSP", "Query Param: 'id'", "Path: /.env"
    url: str = ""                # Target base or affected URL
    poc_url: str = ""            # Clickable direct link reproducing or demonstrating the issue
    reproduce_curl: str = ""     # Ready-to-run cURL command for reproduction
    evidence: str = ""           # Concrete evidence from response headers or body
    remediation: str = ""        # Actionable fix advice
    cve: str = ""                # CVE identifier if applicable
    category: str = ""           # Category e.g. injection, headers, cors, sensitive_data
    confidence: str = "HIGH"     # CONFIRMED, HIGH, MEDIUM, LOW
    cvss_score: float = 0.0      # Estimated CVSS v3.1 score
    method: str = "GET"          # HTTP Method
    param: str = ""              # Specific affected parameter if any

    def to_dict(self) -> dict[str, Any]:
        """Convert vulnerability object to dictionary."""
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "location": self.location,
            "url": self.url,
            "poc_url": self.poc_url or self.url,
            "reproduce_curl": self.reproduce_curl,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cve": self.cve,
            "category": self.category,
            "confidence": self.confidence,
            "cvss_score": self.cvss_score,
            "method": self.method,
            "param": self.param,
        }


# Security headers to check with CVSS ratings and remedies
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "medium",
        "cvss": 5.3,
        "description": "HTTP Strict Transport Security (HSTS) header is missing. "
                       "Allows protocol downgrade attacks (SSL stripping) and insecure transmission.",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' header.",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "cvss": 6.1,
        "description": "Content Security Policy (CSP) header is missing. "
                       "Leaves users vulnerable to reflected and stored Cross-Site Scripting (XSS).",
        "remediation": "Implement a strong Content-Security-Policy header restricting script and object sources.",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "cvss": 4.3,
        "description": "X-Content-Type-Options header is missing. "
                       "Allows browsers to MIME-sniff responses away from declared content-types.",
        "remediation": "Add 'X-Content-Type-Options: nosniff' header.",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "cvss": 5.4,
        "description": "X-Frame-Options header is missing. "
                       "Allows the target to be framed within external domains, enabling UI redressing (Clickjacking).",
        "remediation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header, or use CSP 'frame-ancestors'.",
    },
    "X-XSS-Protection": {
        "severity": "low",
        "cvss": 3.7,
        "description": "Legacy X-XSS-Protection header is missing on response.",
        "remediation": "Add 'X-XSS-Protection: 1; mode=block' or adopt a modern Content-Security-Policy.",
    },
    "Referrer-Policy": {
        "severity": "low",
        "cvss": 3.1,
        "description": "Referrer-Policy header is missing. "
                       "Potentially leaks sensitive URLs, tokens, and query strings in Referer headers.",
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' header.",
    },
    "Permissions-Policy": {
        "severity": "low",
        "cvss": 3.1,
        "description": "Permissions-Policy header is missing. "
                       "Device capabilities (camera, microphone, geolocation) are not explicitly restricted.",
        "remediation": "Add a restrictive Permissions-Policy header.",
    },
}

# Sensitive exposed files to verify with signature validation
SENSITIVE_TARGETS = [
    {
        "path": "/.env",
        "title": "Exposed Environment Configuration (.env)",
        "severity": "critical",
        "cvss": 9.8,
        "category": "sensitive_data",
        "signatures": ["DB_PASSWORD", "APP_KEY", "AWS_SECRET", "SECRET_KEY", "DATABASE_URL", "JWT_SECRET", "PASSWORD="],
        "description": "Environment variables file containing database passwords and secret API keys is publicly accessible.",
        "remediation": "Block public HTTP access to dotfiles like .env in your web server (nginx/apache) immediately.",
    },
    {
        "path": "/.git/HEAD",
        "title": "Exposed Git Repository Metadata (.git/HEAD)",
        "severity": "high",
        "cvss": 7.5,
        "category": "sensitive_data",
        "signatures": ["ref: refs/heads/", "ref: refs/tags/"],
        "description": "The .git folder is exposed to the public internet, allowing complete source code and history extraction.",
        "remediation": "Deny web access to /.git and remove source control artifacts from web root.",
    },
    {
        "path": "/.git/config",
        "title": "Exposed Git Config File",
        "severity": "high",
        "cvss": 7.5,
        "category": "sensitive_data",
        "signatures": ["[core]", "[remote \"origin\"]", "repositoryformatversion"],
        "description": "Exposed Git configuration reveals internal remote URLs, repository tokens, and branch infrastructure.",
        "remediation": "Deny web access to the .git directory in web server configuration.",
    },
    {
        "path": "/phpinfo.php",
        "title": "Exposed PHP Information Script (phpinfo)",
        "severity": "medium",
        "cvss": 5.3,
        "category": "info_disclosure",
        "signatures": ["PHP Version", "Configuration File (php.ini)", "System <td class=\"v\">"],
        "description": "phpinfo diagnostic page reveals server software versions, loaded modules, and internal environment paths.",
        "remediation": "Remove phpinfo diagnostic files from publicly accessible production environments.",
    },
    {
        "path": "/server-status",
        "title": "Apache Server Status Page Publicly Accessible",
        "severity": "medium",
        "cvss": 5.3,
        "category": "info_disclosure",
        "signatures": ["Apache Server Status", "Server Version:", "Current Time:"],
        "description": "Apache mod_status exposes active client requests, client IPs, virtual hosts, and CPU consumption.",
        "remediation": "Restrict /server-status access to localhost or internal monitoring IPs only.",
    },
    {
        "path": "/wp-config.php.bak",
        "title": "Exposed WordPress Configuration Backup",
        "severity": "critical",
        "cvss": 9.8,
        "category": "sensitive_data",
        "signatures": ["DB_NAME", "DB_USER", "DB_PASSWORD", "AUTH_KEY"],
        "description": "WordPress backup configuration file contains plain-text database credentials and authentication salts.",
        "remediation": "Remove uncompiled backup files (.bak, .old) from the document root.",
    },
]


class VulnerabilityScanner:
    """
    Advanced Web Vulnerability Scanner with exact location tracking,
    direct clickable PoC links, and cURL commands.
    """

    def __init__(
        self,
        url: str,
        timeout: float = 10.0,
        user_agent: Optional[str] = None,
        verify_ssl: bool = False,
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
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 (PhantomRecon/1.1.0)"
            ),
        })
        self.session.verify = verify_ssl
        self._vulns: list[Vulnerability] = []
        self._response: Optional[requests.Response] = None

    def _fetch(self) -> requests.Response:
        """Fetch the target URL with caching."""
        if self._response is None:
            self._response = self.session.get(
                self.url, timeout=self.timeout, allow_redirects=True
            )
        return self._response

    def _add_vuln(self, vuln: Vulnerability) -> None:
        """Add a vulnerability to the list with guaranteed valid link."""
        vuln.url = vuln.url or self.url
        if not vuln.poc_url:
            vuln.poc_url = vuln.url
        if not vuln.reproduce_curl:
            vuln.reproduce_curl = f"curl -i -k '{vuln.poc_url}'"
        self._vulns.append(vuln)

    def check_security_headers(self) -> list[Vulnerability]:
        """
        Verify presence and strength of security headers with precise location tags.
        """
        logger.info("Checking security headers...")
        try:
            resp = self._fetch()
        except requests.RequestException as e:
            logger.warning(f"Failed to fetch {self.url} for header checks: {e}")
            return []

        vulns = []
        for header_name, info in SECURITY_HEADERS.items():
            if header_name not in resp.headers:
                vuln = Vulnerability(
                    title=f"Missing Security Header: {header_name}",
                    severity=info["severity"],
                    cvss_score=info["cvss"],
                    description=info["description"],
                    location=f"HTTP Response Header: '{header_name}'",
                    url=self.url,
                    poc_url=self.url,
                    reproduce_curl=f"curl -i -k -s '{self.url}' | grep -i '{header_name}'",
                    evidence=f"Header '{header_name}' is absent from HTTP response headers.",
                    remediation=info["remediation"],
                    category="security_headers",
                    confidence="CONFIRMED",
                )
                vulns.append(vuln)
                self._add_vuln(vuln)

        return vulns

    def check_cors(self) -> list[Vulnerability]:
        """
        Audit Cross-Origin Resource Sharing (CORS) with exact request/response proof.
        """
        logger.info("Auditing CORS policy...")
        vulns = []
        parsed = urlparse(self.url)
        evil_origin = f"https://evil-attacker.example.com"
        test_origins = [evil_origin, "null"]

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
                        title="CORS: Insecure Wildcard Origin (*)",
                        severity="medium",
                        cvss_score=5.3,
                        description="The server responds with 'Access-Control-Allow-Origin: *', allowing any site to issue cross-origin requests.",
                        location=f"Response Header: 'Access-Control-Allow-Origin'",
                        url=self.url,
                        poc_url=self.url,
                        reproduce_curl=f"curl -i -k -H 'Origin: {origin}' '{self.url}'",
                        evidence=f"Sent: Origin: {origin}\nReceived: Access-Control-Allow-Origin: *",
                        remediation="Define an explicit allowlist of trusted origins instead of wildcard '*'.",
                        category="cors",
                        confidence="CONFIRMED",
                    )
                    vulns.append(vuln)
                    self._add_vuln(vuln)
                    break

                elif acao == origin and origin != "null":
                    is_credentialed = acac.lower() == "true"
                    severity = "critical" if is_credentialed else "high"
                    cvss = 8.8 if is_credentialed else 7.1

                    vuln = Vulnerability(
                        title="CORS: Arbitrary Origin Reflection" + (" with Credentials" if is_credentialed else ""),
                        severity=severity,
                        cvss_score=cvss,
                        description=f"The backend reflects untrusted client Origin ({origin}) in ACAO."
                                    + (" Combined with Allow-Credentials: true, allows authenticated sensitive data exfiltration." if is_credentialed else ""),
                        location=f"Request/Response Header: Origin -> Access-Control-Allow-Origin",
                        url=self.url,
                        poc_url=self.url,
                        reproduce_curl=f"curl -i -k -H 'Origin: {origin}' '{self.url}'",
                        evidence=f"Sent: Origin: {origin}\nReceived: Access-Control-Allow-Origin: {acao}\nCredentials: {acac or 'None'}",
                        remediation="Validate Origin against a server-side whitelist. Never echo user Origin blindly.",
                        category="cors",
                        confidence="CONFIRMED",
                    )
                    vulns.append(vuln)
                    self._add_vuln(vuln)
                    break

                elif acao == "null":
                    vuln = Vulnerability(
                        title="CORS: Insecure 'null' Origin Permitted",
                        severity="medium",
                        cvss_score=6.5,
                        description="The server trusts 'null' origins, making it susceptible to sandboxed iframes and local file exploits.",
                        location="Response Header: 'Access-Control-Allow-Origin: null'",
                        url=self.url,
                        poc_url=self.url,
                        reproduce_curl=f"curl -i -k -H 'Origin: null' '{self.url}'",
                        evidence="Received: Access-Control-Allow-Origin: null",
                        remediation="Do not allow 'null' origin in CORS configuration.",
                        category="cors",
                        confidence="CONFIRMED",
                    )
                    vulns.append(vuln)
                    self._add_vuln(vuln)
                    break

            except requests.RequestException:
                continue

        return vulns

    def check_clickjacking(self) -> list[Vulnerability]:
        """
        Check for missing framing protection and build iframe reproduction.
        """
        logger.info("Checking clickjacking vulnerability...")
        try:
            resp = self._fetch()
        except requests.RequestException:
            return []

        vulns = []
        x_frame = resp.headers.get("X-Frame-Options", "")
        csp = resp.headers.get("Content-Security-Policy", "")

        has_xfo = bool(x_frame)
        has_csp_frame = "frame-ancestors" in csp.lower()

        if not has_xfo and not has_csp_frame:
            iframe_poc = f"<iframe src='{self.url}' width='800' height='600'></iframe>"
            vuln = Vulnerability(
                title="Clickjacking: Missing Frame Protection",
                severity="medium",
                cvss_score=5.4,
                description="The application lacks X-Frame-Options and CSP frame-ancestors directives, allowing arbitrary malicious sites to frame it.",
                location="HTTP Headers: Missing 'X-Frame-Options' & 'frame-ancestors'",
                url=self.url,
                poc_url=self.url,
                reproduce_curl=f"curl -i -k -s '{self.url}' | grep -Ei 'x-frame-options|frame-ancestors'",
                evidence=f"Neither X-Frame-Options nor frame-ancestors detected.\nTest PoC HTML: {iframe_poc}",
                remediation="Add 'X-Frame-Options: DENY' or 'Content-Security-Policy: frame-ancestors none;'.",
                category="clickjacking",
                confidence="CONFIRMED",
            )
            vulns.append(vuln)
            self._add_vuln(vuln)

        return vulns

    def check_information_disclosure(self) -> list[Vulnerability]:
        """
        Detect software and version disclosures in headers and banners.
        """
        logger.info("Inspecting headers for technology/version leaks...")
        try:
            resp = self._fetch()
        except requests.RequestException:
            return []

        vulns = []
        server = resp.headers.get("Server", "")
        if server and any(c.isdigit() for c in server):
            vuln = Vulnerability(
                title=f"Information Disclosure: Server Software & Version ({server})",
                severity="low",
                cvss_score=3.7,
                description=f"Server header discloses software and version details: '{server}'.",
                location="HTTP Header: 'Server'",
                url=self.url,
                poc_url=self.url,
                reproduce_curl=f"curl -I -k '{self.url}'",
                evidence=f"Server: {server}",
                remediation="Configure server token minimization (e.g. ServerTokens Prod in Apache, server_tokens off in Nginx).",
                category="info_disclosure",
                confidence="CONFIRMED",
            )
            vulns.append(vuln)
            self._add_vuln(vuln)

        powered_by = resp.headers.get("X-Powered-By", "")
        if powered_by:
            vuln = Vulnerability(
                title=f"Information Disclosure: Technology Fingerprint ({powered_by})",
                severity="low",
                cvss_score=3.1,
                description=f"X-Powered-By header discloses underlying language or runtime: '{powered_by}'.",
                location="HTTP Header: 'X-Powered-By'",
                url=self.url,
                poc_url=self.url,
                reproduce_curl=f"curl -I -k '{self.url}'",
                evidence=f"X-Powered-By: {powered_by}",
                remediation="Disable or strip X-Powered-By header in web application configuration.",
                category="info_disclosure",
                confidence="CONFIRMED",
            )
            vulns.append(vuln)
            self._add_vuln(vuln)

        return vulns

    def check_open_redirect(self) -> list[Vulnerability]:
        """
        Detect unvalidated redirect parameters with clickable exploit URL.
        """
        logger.info("Auditing parameters for open redirection...")
        vulns = []
        redirect_params = ["url", "redirect", "next", "return", "goto", "target", "dest", "redir", "continue"]
        canary_domain = "https://example.org/phantom_redirect_test"

        for param in redirect_params:
            test_url = f"{self.url}?{param}={canary_domain}"
            try:
                resp = self.session.get(
                    test_url,
                    timeout=self.timeout,
                    allow_redirects=False,
                )

                if resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("Location", "")
                    if "phantom_redirect_test" in loc or "example.org" in loc:
                        vuln = Vulnerability(
                            title=f"Open Redirect via Parameter '{param}'",
                            severity="medium",
                            cvss_score=6.1,
                            description=f"The '{param}' parameter accepts arbitrary external URLs and redirects users without validation.",
                            location=f"Query Parameter: '{param}'",
                            url=self.url,
                            poc_url=test_url,
                            reproduce_curl=f"curl -i -k '{test_url}'",
                            evidence=f"Status: {resp.status_code}\nLocation: {loc}",
                            remediation="Validate redirection targets against a strict allowlist of relative paths or known internal hosts.",
                            category="open_redirect",
                            confidence="CONFIRMED",
                            param=param,
                        )
                        vulns.append(vuln)
                        self._add_vuln(vuln)
            except requests.RequestException:
                continue

        return vulns

    def check_sensitive_files(self) -> list[Vulnerability]:
        """
        High-precision check for publicly exposed files (.env, .git, phpinfo, etc.)
        Validates content signatures to prevent false positives from generic 200 catch-alls.
        """
        logger.info("Probing for exposed sensitive files and endpoints...")
        vulns = []

        for target in SENSITIVE_TARGETS:
            endpoint_url = urljoin(self.url + "/", target["path"].lstrip("/"))
            try:
                resp = self.session.get(
                    endpoint_url,
                    timeout=self.timeout,
                    allow_redirects=False,
                )

                if resp.status_code == 200:
                    text_snippet = resp.text[:4000]
                    # Check signatures to verify genuine content
                    matched_sig = None
                    for sig in target["signatures"]:
                        if sig in text_snippet:
                            matched_sig = sig
                            break

                    if matched_sig:
                        evidence_sample = text_snippet[:300].strip()
                        vuln = Vulnerability(
                            title=target["title"],
                            severity=target["severity"],
                            cvss_score=target["cvss"],
                            description=target["description"],
                            location=f"Exposed URL Path: {target['path']}",
                            url=self.url,
                            poc_url=endpoint_url,
                            reproduce_curl=f"curl -i -k '{endpoint_url}'",
                            evidence=f"Signature Match: '{matched_sig}'\nSample Preview:\n{evidence_sample}",
                            remediation=target["remediation"],
                            category=target["category"],
                            confidence="CONFIRMED",
                        )
                        vulns.append(vuln)
                        self._add_vuln(vuln)
            except requests.RequestException:
                continue

        return vulns

    def check_parameter_reflection(self) -> list[Vulnerability]:
        """
        Audit existing query parameters or inject test parameters to check for XSS reflection.
        """
        logger.info("Testing parameters for reflection & unescaped input...")
        vulns = []
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)

        # Candidate parameters: if URL already has them, use them; otherwise try common params
        test_keys = list(params.keys()) if params else ["q", "search", "id", "keyword", "query"]
        canary = "phantom<xss>probe789"

        for key in test_keys:
            test_query = dict(params)
            test_query[key] = [canary]
            new_query = urlencode(test_query, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

            try:
                resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=True)
                if canary in resp.text:
                    vuln = Vulnerability(
                        title=f"Reflected Input / Potential XSS in Parameter '{key}'",
                        severity="high",
                        cvss_score=7.2,
                        description=f"The parameter '{key}' reflects unescaped user input (containing HTML tags) directly into the response body.",
                        location=f"Query Parameter: '{key}'",
                        url=self.url,
                        poc_url=test_url,
                        reproduce_curl=f"curl -i -k '{test_url}'",
                        evidence=f"Injected: {canary}\nReflected verbatim in response body without sanitization.",
                        remediation="Contextually encode user input before rendering it in HTML and enforce a strict Content-Security-Policy.",
                        category="injection",
                        confidence="HIGH",
                        param=key,
                    )
                    vulns.append(vuln)
                    self._add_vuln(vuln)
            except requests.RequestException:
                continue

        return vulns

    def check_ssl_issues(self) -> list[Vulnerability]:
        """
        Verify TLS enforcement and unencrypted HTTP fallback.
        """
        logger.info("Evaluating HTTPS enforcement...")
        vulns = []
        parsed = urlparse(self.url)

        if parsed.scheme == "https":
            http_url = self.url.replace("https://", "http://", 1)
            try:
                resp = self.session.get(
                    http_url, timeout=self.timeout, allow_redirects=False
                )
                if resp.status_code == 200:
                    vuln = Vulnerability(
                        title="Insecure HTTP Transport Available (No Redirect)",
                        severity="medium",
                        cvss_score=5.3,
                        description="Plaintext HTTP is accessible on port 80 and does not automatically redirect to HTTPS.",
                        location="Network Endpoint: HTTP Port 80",
                        url=http_url,
                        poc_url=http_url,
                        reproduce_curl=f"curl -I -k '{http_url}'",
                        evidence=f"Plaintext HTTP returned status {resp.status_code} without redirecting to HTTPS.",
                        remediation="Configure web server to permanently redirect (301) all HTTP traffic to HTTPS.",
                        category="ssl",
                        confidence="CONFIRMED",
                    )
                    vulns.append(vuln)
                    self._add_vuln(vuln)
            except requests.RequestException:
                pass

        elif parsed.scheme == "http":
            vuln = Vulnerability(
                title="Missing HTTPS Encryption",
                severity="high",
                cvss_score=7.4,
                description="The application communicates exclusively via unencrypted HTTP, leaving all session data and credentials vulnerable to interception.",
                location="Network Transport: HTTP (Port 80)",
                url=self.url,
                poc_url=self.url,
                reproduce_curl=f"curl -I '{self.url}'",
                evidence="Protocol scheme is unencrypted 'http://'.",
                remediation="Deploy a trusted TLS certificate and force all connections to use HTTPS.",
                category="ssl",
                confidence="CONFIRMED",
            )
            vulns.append(vuln)
            self._add_vuln(vuln)

        return vulns

    def scan_all(self) -> list[dict[str, Any]]:
        """
        Run all high-precision vulnerability checks with location tracing and PoC generation.

        Returns:
            List of sorted vulnerability dictionaries.
        """
        logger.info(f"Initiating full precision scan on [bold magenta]{self.url}[/bold magenta]")
        start = datetime.now()
        self._vulns = []

        # Execute all security modules
        self.check_security_headers()
        self.check_cors()
        self.check_clickjacking()
        self.check_sensitive_files()
        self.check_parameter_reflection()
        self.check_open_redirect()
        self.check_information_disclosure()
        self.check_ssl_issues()

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        self._vulns.sort(key=lambda v: (severity_order.get(v.severity, 5), -v.cvss_score))

        duration = (datetime.now() - start).total_seconds()
        logger.info(
            f"Vulnerability scan completed: [bold {'red' if self._vulns else 'green'}]"
            f"{len(self._vulns)}[/bold {'red' if self._vulns else 'green'}] findings in {duration:.2f}s"
        )

        return [v.to_dict() for v in self._vulns]

    def get_summary(self) -> dict[str, int]:
        """Return vulnerability counts grouped by severity."""
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in self._vulns:
            sev = vuln.severity.lower()
            if sev in summary:
                summary[sev] += 1
        return summary
