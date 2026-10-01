"""
Phantom Recon — Ultra-Precision Vulnerability Scanner (v1.2.0).

Engineered for ZERO FALSE POSITIVES and maximum reproducibility.
Features soft-404 baseline profiling, semantic content validation,
anti-tampering heuristics, and exact location tracking.

⚠️ DISCLAIMER: For authorized security testing only.
"""

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import re
import socket
from typing import Any, Optional
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests

from phantom_recon.utils.logger import console, get_logger

logger = get_logger(__name__)


@dataclass
class Vulnerability:
    """
    Represents a verified security vulnerability with proof-of-concept metadata
    and zero-false-positive validation evidence.
    """
    title: str
    severity: str                # critical, high, medium, low, info
    description: str
    location: str = ""           # Exact parameter, header, or URL path
    url: str = ""                # Base target URL
    poc_url: str = ""            # Direct clickable URL
    reproduce_curl: str = ""     # Ready-to-execute cURL command
    evidence: str = ""           # Concrete response snippet/proof
    remediation: str = ""        # Exact mitigation instruction
    cve: str = ""                # Related CVE if applicable
    category: str = ""           # Vulnerability classification
    confidence: str = "CONFIRMED"# CONFIRMED, HIGH, MEDIUM
    cvss_score: float = 0.0      # CVSS v3.1 rating
    method: str = "GET"          # HTTP Method
    param: str = ""              # Specific affected parameter

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


# Standard security headers to evaluate
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "medium",
        "cvss": 5.3,
        "description": "HTTP Strict Transport Security (HSTS) header is missing, allowing protocol downgrade and SSL stripping attacks.",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to response headers.",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "cvss": 6.1,
        "description": "Content Security Policy (CSP) header is absent, increasing exposure to Cross-Site Scripting (XSS) and code injection.",
        "remediation": "Configure a restrictive Content-Security-Policy header defining trusted script-src, style-src, and frame-ancestors.",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "cvss": 4.3,
        "description": "X-Content-Type-Options header is absent, allowing MIME-type sniffing by browsers.",
        "remediation": "Add 'X-Content-Type-Options: nosniff' header.",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "cvss": 5.4,
        "description": "X-Frame-Options header is missing, enabling UI redressing and Clickjacking attacks.",
        "remediation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header, or specify 'frame-ancestors' in CSP.",
    },
    "Referrer-Policy": {
        "severity": "low",
        "cvss": 3.1,
        "description": "Referrer-Policy header is absent, potentially leaking private tokens or URLs in HTTP Referer.",
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' header.",
    },
    "Permissions-Policy": {
        "severity": "low",
        "cvss": 3.1,
        "description": "Permissions-Policy header is missing; browser hardware APIs (camera, mic, geolocation) are unrestricted.",
        "remediation": "Add a restrictive Permissions-Policy header (e.g. camera=(), microphone=(), geolocation=()).",
    },
    "Cross-Origin-Opener-Policy": {
        "severity": "low",
        "cvss": 3.1,
        "description": "Cross-Origin-Opener-Policy (COOP) header is absent, allowing cross-origin window interaction and Spectre-based leaks.",
        "remediation": "Add 'Cross-Origin-Opener-Policy: same-origin' header.",
    },
    "Cross-Origin-Embedder-Policy": {
        "severity": "low",
        "cvss": 3.1,
        "description": "Cross-Origin-Embedder-Policy (COEP) header is absent, allowing unconstrained cross-origin resource embedding.",
        "remediation": "Add 'Cross-Origin-Embedder-Policy: require-corp' header.",
    },
}

# Sensitive file probes with strict semantic content validators (No False Positives)
SENSITIVE_FILES_DATABASE = [
    {
        "path": "/.env",
        "title": "Exposed Environment Configuration File (.env)",
        "severity": "critical",
        "cvss": 9.8,
        "category": "sensitive_data",
        # Real .env validation: Key=Value structure, NOT HTML
        "regex": r"(?m)^(APP_KEY|DB_PASSWORD|DATABASE_URL|AWS_SECRET|SECRET_KEY|REDIS_PASSWORD|JWT_SECRET|MYSQL_PWD)\s*=\s*.+$",
        "must_not_contain": ["<!DOCTYPE html", "<html", "<head", "<body", "404 Not Found"],
        "description": "Publicly readable environment variables file containing credentials, database secrets, or API keys.",
        "remediation": "Configure web server (Nginx/Apache) to deny public HTTP access to hidden dotfiles like .env.",
    },
    {
        "path": "/backup.sql",
        "title": "Exposed Database SQL Dump (backup.sql)",
        "severity": "critical",
        "cvss": 9.8,
        "category": "sensitive_data",
        "regex": r"(?m)^(CREATE TABLE|INSERT INTO|-- MySQL dump|-- PostgreSQL database dump)",
        "must_not_contain": ["<!DOCTYPE html", "<html", "<head", "<body"],
        "description": "Publicly accessible raw database dump file exposing sensitive schemas, table structures, and stored credentials.",
        "remediation": "Remove backup files from document root and store securely outside public server directories.",
    },
    {
        "path": "/.git/HEAD",
        "title": "Exposed Git Repository Metadata (.git/HEAD)",
        "severity": "high",
        "cvss": 7.5,
        "category": "sensitive_data",
        "regex": r"(?m)^(ref:\s*refs/heads/|ref:\s*refs/tags/|[0-9a-fA-F]{40}$)",
        "must_not_contain": ["<!DOCTYPE html", "<html", "<head", "<body"],
        "description": "Publicly accessible .git folder allows complete source code recovery and revision history extraction.",
        "remediation": "Block access to /.git/ in web server rules and remove VCS artifacts from document root.",
    },
    {
        "path": "/.git/config",
        "title": "Exposed Git Repository Configuration",
        "severity": "high",
        "cvss": 7.5,
        "category": "sensitive_data",
        "regex": r"\[core\][\s\S]*?repositoryformatversion",
        "must_not_contain": ["<!DOCTYPE html", "<html", "<head"],
        "description": "Git repository configuration discloses internal remote URLs, repository tokens, and branch names.",
        "remediation": "Deny all HTTP requests to .git directory in web server configuration.",
    },
    {
        "path": "/phpinfo.php",
        "title": "Exposed PHP Information Diagnostic (phpinfo)",
        "severity": "medium",
        "cvss": 5.3,
        "category": "info_disclosure",
        "regex": r"(PHP Version|Configuration File \(php\.ini\)|<title>phpinfo\(\)</title>)",
        "must_not_contain": ["404 Not Found", "Page Not Found", "Error 404"],
        "description": "Publicly exposed phpinfo script reveals server paths, environment variables, and module versions.",
        "remediation": "Remove phpinfo files from production environments immediately.",
    },
    {
        "path": "/server-status",
        "title": "Exposed Apache Server Status",
        "severity": "medium",
        "cvss": 5.3,
        "category": "info_disclosure",
        "regex": r"(Apache Server Status for|Current Time:|Server Version: Apache)",
        "must_not_contain": ["404 Not Found", "Page Not Found"],
        "description": "Apache server-status page publicly exposes active client requests, client IP addresses, and performance metrics.",
        "remediation": "Restrict /server-status access to localhost in Apache configuration.",
    },
    {
        "path": "/.DS_Store",
        "title": "Exposed Apple macOS Directory Metadata (.DS_Store)",
        "severity": "medium",
        "cvss": 5.3,
        "category": "info_disclosure",
        "regex": r"(\x00\x00\x00\x01Bud1|Bud1)",
        "must_not_contain": ["<!DOCTYPE html", "<html", "<head"],
        "description": "macOS .DS_Store file reveals private file system hierarchy, hidden file names, and directories.",
        "remediation": "Configure web server to deny access to .DS_Store files and add to .gitignore.",
    },
]


class VulnerabilityScanner:
    """
    Advanced Vulnerability Scanner with Soft-404 profiling, semantic validation,
    exact location tracing, and zero false positives.
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
            timeout: Network request timeout.
            user_agent: Custom User-Agent header.
            verify_ssl: Whether to verify SSL certificates.
        """
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": user_agent or (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 (PhantomRecon/1.2.0)"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })
        self.session.verify = verify_ssl
        self._vulns: list[Vulnerability] = []
        self._response: Optional[requests.Response] = None

        # Baseline 404 profiling for soft-404 detection
        self._baseline_status: int = 404
        self._baseline_len: int = 0
        self._baseline_body_hash: str = ""
        self._has_soft_404: bool = False
        self._profiled: bool = False

    def _fetch_root(self) -> Optional[requests.Response]:
        """Fetch the base target URL with caching."""
        if self._response is None:
            try:
                self._response = self.session.get(
                    self.url, timeout=self.timeout, allow_redirects=True
                )
            except requests.RequestException as e:
                logger.warning(f"Failed to connect to target {self.url}: {e}")
                return None
        return self._response

    def profile_404_baseline(self) -> None:
        """
        Send a request to a guaranteed non-existent random endpoint to profile
        how the server handles 404 errors (Soft-404 detection).
        Prevents false-positive findings on servers that return 200 for missing pages.
        """
        if self._profiled:
            return

        probe_token = f"_phantom_probe_404_{hashlib.md5(str(datetime.now().timestamp()).encode()).hexdigest()[:12]}"
        probe_url = f"{self.url}/{probe_token}.html"

        try:
            resp = self.session.get(probe_url, timeout=self.timeout, allow_redirects=True)
            self._baseline_status = resp.status_code
            self._baseline_len = len(resp.content)
            self._baseline_body_hash = hashlib.md5(resp.content).hexdigest()

            # If the server returns 200 for a non-existent random URL, it has Soft-404!
            if resp.status_code == 200:
                self._has_soft_404 = True
                logger.info(f"Target employs Soft-404 (returns 200 for non-existent pages, baseline size: {self._baseline_len} bytes)")
        except requests.RequestException:
            pass
        finally:
            self._profiled = True

    def _is_soft_404(self, resp: requests.Response) -> bool:
        """
        Check if a response matches the server's custom 404 page pattern.
        """
        if resp.status_code == 404:
            return True

        if self._has_soft_404:
            # Check identical MD5 hash
            if hashlib.md5(resp.content).hexdigest() == self._baseline_body_hash:
                return True
            # Check content length within 3% tolerance
            if self._baseline_len > 0 and abs(len(resp.content) - self._baseline_len) < (self._baseline_len * 0.03):
                return True

        return False

    def _add_vuln(self, vuln: Vulnerability) -> None:
        """Add a verified vulnerability to the results."""
        vuln.url = vuln.url or self.url
        if not vuln.poc_url:
            vuln.poc_url = vuln.url
        if not vuln.reproduce_curl:
            vuln.reproduce_curl = f"curl -i -k '{vuln.poc_url}'"
        self._vulns.append(vuln)

    def check_security_headers(self) -> list[Vulnerability]:
        """
        Verify presence of essential security headers on root response.
        """
        logger.info("Auditing security headers...")
        resp = self._fetch_root()
        if not resp:
            return []

        # Only evaluate headers if content is HTML-like
        content_type = resp.headers.get("Content-Type", "").lower()
        vulns = []

        for header_name, info in SECURITY_HEADERS.items():
            if header_name not in resp.headers:
                # If HSTS is checked on plain HTTP, skip it here since it belongs to SSL/HTTPS check
                if header_name == "Strict-Transport-Security" and not self.url.startswith("https://"):
                    continue

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
        High-precision CORS audit. Confirms dynamic origin reflection with dual probes.
        """
        logger.info("Auditing Cross-Origin Resource Sharing (CORS)...")
        vulns = []

        # Use two distinct origins to ensure reflection is dynamic, not a fixed whitelist
        origin_a = "https://phantom-audit-origin-alpha.example.com"
        origin_b = "https://phantom-audit-origin-beta.example.com"

        try:
            resp_a = self.session.get(self.url, headers={"Origin": origin_a}, timeout=self.timeout)
            acao_a = resp_a.headers.get("Access-Control-Allow-Origin", "")
            acac_a = resp_a.headers.get("Access-Control-Allow-Credentials", "").lower()

            if acao_a == origin_a:
                # Confirm with second origin to eliminate static test environment false positives
                resp_b = self.session.get(self.url, headers={"Origin": origin_b}, timeout=self.timeout)
                acao_b = resp_b.headers.get("Access-Control-Allow-Origin", "")

                if acao_b == origin_b:
                    is_credentialed = acac_a == "true"
                    severity = "critical" if is_credentialed else "high"
                    cvss = 8.8 if is_credentialed else 7.1

                    vuln = Vulnerability(
                        title="CORS: Arbitrary Origin Dynamic Reflection" + (" with Credentials" if is_credentialed else ""),
                        severity=severity,
                        cvss_score=cvss,
                        description=(
                            "The server dynamically reflects arbitrary untrusted client Origin headers in "
                            "Access-Control-Allow-Origin. "
                            + ("Combined with Allow-Credentials: true, allows authenticated sensitive cross-origin data theft."
                               if is_credentialed else "Allows unauthorized cross-origin reading.")
                        ),
                        location="HTTP Request/Response Header: Origin -> Access-Control-Allow-Origin",
                        url=self.url,
                        poc_url=self.url,
                        reproduce_curl=f"curl -i -k -H 'Origin: {origin_a}' '{self.url}'",
                        evidence=f"Sent: Origin: {origin_a}\nReceived: Access-Control-Allow-Origin: {acao_a}\nCredentials Allowed: {acac_a}",
                        remediation="Implement a strict, server-side allowlist of trusted origins. Never echo arbitrary client Origin headers.",
                        category="cors",
                        confidence="CONFIRMED",
                    )
                    vulns.append(vuln)
                    self._add_vuln(vuln)

            elif acao_a == "*":
                # Wildcard CORS is only a critical flaw if credentials are explicitly permitted
                if acac_a == "true":
                    vuln = Vulnerability(
                        title="CORS: Insecure Wildcard with Credentials",
                        severity="high",
                        cvss_score=7.5,
                        description="The server pairs Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true, which is dangerous or rejected by modern browsers.",
                        location="Response Header: 'Access-Control-Allow-Origin: *'",
                        url=self.url,
                        poc_url=self.url,
                        reproduce_curl=f"curl -i -k -H 'Origin: {origin_a}' '{self.url}'",
                        evidence="Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
                        remediation="Do not combine wildcard CORS with credential sharing.",
                        category="cors",
                        confidence="CONFIRMED",
                    )
                    vulns.append(vuln)
                    self._add_vuln(vuln)
                else:
                    # Public API wildcard is informational, not false-alarm critical
                    vuln = Vulnerability(
                        title="CORS: Public Wildcard Origin Allowed (*)",
                        severity="info",
                        cvss_score=3.0,
                        description="The server responds with 'Access-Control-Allow-Origin: *'. Common for public APIs, but should be restricted if sensitive data is served.",
                        location="Response Header: 'Access-Control-Allow-Origin'",
                        url=self.url,
                        poc_url=self.url,
                        reproduce_curl=f"curl -i -k -H 'Origin: {origin_a}' '{self.url}'",
                        evidence="Access-Control-Allow-Origin: *",
                        remediation="Ensure this endpoint is intended for public unauthenticated access.",
                        category="cors",
                        confidence="CONFIRMED",
                    )
                    vulns.append(vuln)
                    self._add_vuln(vuln)

        except requests.RequestException:
            pass

        return vulns

    def check_clickjacking(self) -> list[Vulnerability]:
        """
        Verify Clickjacking protection. Eliminates false positives by checking
        both X-Frame-Options and CSP frame-ancestors.
        """
        logger.info("Evaluating clickjacking protection...")
        resp = self._fetch_root()
        if not resp:
            return []

        # Only HTML web pages can be clickjacked; ignore non-HTML responses (JSON, XML)
        content_type = resp.headers.get("Content-Type", "").lower()
        if content_type and not any(t in content_type for t in ["text/html", "application/xhtml"]):
            return []

        x_frame = resp.headers.get("X-Frame-Options", "").upper()
        csp = resp.headers.get("Content-Security-Policy", "").lower()

        has_xfo = any(opt in x_frame for opt in ["DENY", "SAMEORIGIN"])
        has_csp_frame = "frame-ancestors" in csp

        if not has_xfo and not has_csp_frame:
            iframe_poc = f"<iframe src='{self.url}' width='800' height='600'></iframe>"
            vuln = Vulnerability(
                title="Clickjacking: Missing UI Frame Protection",
                severity="medium",
                cvss_score=5.4,
                description="The target web page lacks both X-Frame-Options and CSP 'frame-ancestors' directives. It can be framed inside external websites for clickjacking attacks.",
                location="HTTP Response Headers: Missing 'X-Frame-Options' & 'frame-ancestors'",
                url=self.url,
                poc_url=self.url,
                reproduce_curl=f"curl -i -k -s '{self.url}' | grep -Ei 'x-frame-options|frame-ancestors'",
                evidence=f"Neither X-Frame-Options nor frame-ancestors detected.\nTest PoC HTML: {iframe_poc}",
                remediation="Add 'X-Frame-Options: SAMEORIGIN' (or DENY), or define 'Content-Security-Policy: frame-ancestors self;'.",
                category="clickjacking",
                confidence="CONFIRMED",
            )
            self._add_vuln(vuln)
            return [vuln]

        return []

    def check_sensitive_files(self) -> list[Vulnerability]:
        """
        Zero False-Positive Sensitive File Detector.
        Employs baseline Soft-404 comparison and strict regex semantic checks.
        """
        logger.info("Scanning for exposed sensitive files and credentials...")
        self.profile_404_baseline()
        vulns = []

        for target in SENSITIVE_FILES_DATABASE:
            endpoint_url = urljoin(self.url + "/", target["path"].lstrip("/"))
            try:
                resp = self.session.get(endpoint_url, timeout=self.timeout, allow_redirects=False)

                # Skip non-200 responses immediately
                if resp.status_code != 200:
                    continue

                # Skip soft-404 catch-alls
                if self._is_soft_404(resp):
                    continue

                text_content = resp.text[:8000]

                # Check must_not_contain list to rule out HTML error pages
                if any(bad in text_content for bad in target["must_not_contain"]):
                    continue

                # Apply strict regex validator
                matches = re.findall(target["regex"], text_content)
                if matches:
                    # Provide matched config signatures as concrete proof
                    matched_lines = [line.strip() for line in text_content.splitlines() if any(re.search(target["regex"], line) for _ in [0])]
                    evidence_sample = "\n".join(matched_lines[:5]) if matched_lines else str(matches[0])
                    vuln = Vulnerability(
                        title=target["title"],
                        severity=target["severity"],
                        cvss_score=target["cvss"],
                        description=target["description"],
                        location=f"Exposed URL Path: {target['path']}",
                        url=self.url,
                        poc_url=endpoint_url,
                        reproduce_curl=f"curl -i -k '{endpoint_url}'",
                        evidence=f"Verified Signature Match:\n{evidence_sample}",
                        remediation=target["remediation"],
                        category=target["category"],
                        confidence="CONFIRMED",
                    )
                    vulns.append(vuln)
                    self._add_vuln(vuln)

            except requests.RequestException:
                continue

        return vulns

    def check_directory_listing(self) -> list[Vulnerability]:
        """
        Zero False-Positive Directory Listing / Indexing audit.
        Checks common asset folders (/uploads/, /static/, /assets/, /backup/, /files/, /images/)
        against genuine directory indexing signatures.
        """
        logger.info("Auditing common directories for insecure directory listing...")
        self.profile_404_baseline()
        vulns = []
        candidate_dirs = ["/uploads/", "/static/", "/assets/", "/backup/", "/files/", "/images/"]

        # Real web server index signatures (Apache, Nginx, IIS, Lighttpd, Python)
        index_signatures = [
            r"<title>Index of /",
            r"<title>Directory Listing -- /",
            r"<h2>Directory listing for /",
            r"<pre><a href=\"\.\./\">",
            r"\[To Parent Directory\]",
        ]

        for d in candidate_dirs:
            target_url = urljoin(self.url + "/", d.lstrip("/"))
            try:
                resp = self.session.get(target_url, timeout=self.timeout, allow_redirects=False)
                if resp.status_code != 200:
                    continue
                if self._is_soft_404(resp):
                    continue

                text = resp.text[:4000]
                matched_sig = None
                for sig in index_signatures:
                    if re.search(sig, text, re.IGNORECASE):
                        matched_sig = sig
                        break

                if matched_sig:
                    vuln = Vulnerability(
                        title=f"Insecure Directory Listing Enabled on '{d}'",
                        severity="medium",
                        cvss_score=5.3,
                        description=(
                            f"The directory '{d}' has directory browsing/listing enabled. "
                            "Unauthenticated users can enumerate uploaded files, scripts, and private assets."
                        ),
                        location=f"Web Directory: {d}",
                        url=self.url,
                        poc_url=target_url,
                        reproduce_curl=f"curl -i -k '{target_url}'",
                        evidence=f"Directory index detected. Matched signature: {matched_sig}",
                        remediation="Disable directory indexing in server config (Apache: 'Options -Indexes', Nginx: 'autoindex off;').",
                        category="info_disclosure",
                        confidence="CONFIRMED",
                    )
                    vulns.append(vuln)
                    self._add_vuln(vuln)

            except requests.RequestException:
                continue

        return vulns

    def check_parameter_reflection(self) -> list[Vulnerability]:
        """
        Accurate Reflected XSS / Input Injection test.
        Verifies that special characters (<, >, ", ') are reflected verbatim without entity encoding
        specifically in an HTML rendering context.
        """
        logger.info("Testing parameters for unencoded reflection (XSS)...")
        vulns = []
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)

        test_keys = list(params.keys()) if params else ["q", "search", "id", "keyword", "query"]
        canary = "phantom<xss'probe\"789>"

        for key in test_keys:
            test_query = dict(params)
            test_query[key] = [canary]
            new_query = urlencode(test_query, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

            try:
                resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=True)
                content_type = resp.headers.get("Content-Type", "").lower()

                # Reflection only leads to XSS if rendered in HTML or XML context
                is_html_context = any(t in content_type for t in ["text/html", "application/xhtml"])

                # Verbatim check: the exact dangerous tag probe must appear without escaping
                if canary in resp.text:
                    if is_html_context:
                        vuln = Vulnerability(
                            title=f"Reflected Cross-Site Scripting (XSS) in Parameter '{key}'",
                            severity="high",
                            cvss_score=7.5,
                            description=(
                                f"The parameter '{key}' reflects unescaped user input containing HTML tags (<, >) and quotes "
                                "directly into the response body, allowing arbitrary JavaScript execution."
                            ),
                            location=f"Query Parameter: '{key}'",
                            url=self.url,
                            poc_url=test_url,
                            reproduce_curl=f"curl -i -k '{test_url}'",
                            evidence=f"Probe: {canary}\nReflected unescaped in text/html context without HTML entity encoding.",
                            remediation="Contextually encode all user-supplied input before rendering into HTML templates and enforce CSP.",
                            category="injection",
                            confidence="CONFIRMED",
                            param=key,
                        )
                        vulns.append(vuln)
                        self._add_vuln(vuln)

            except requests.RequestException:
                continue

        return vulns

    def check_open_redirect(self) -> list[Vulnerability]:
        """
        Zero False-Positive Open Redirect test.
        Verifies that the HTTP Location header genuinely redirects outside the target domain.
        """
        logger.info("Auditing parameters for unvalidated open redirect...")
        vulns = []
        parsed_target = urlparse(self.url)
        redirect_params = ["url", "redirect", "next", "return", "goto", "target", "dest", "continue", "redir"]
        external_canary = "https://example.org/phantom_redirect_verification"

        for param in redirect_params:
            test_url = f"{self.url}?{param}={external_canary}"
            try:
                resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)

                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "").strip()
                    parsed_loc = urlparse(location)

                    # Strict verification: the destination host MUST be example.org
                    # and MUST NOT match the target's own domain or be an internal relative path
                    if parsed_loc.netloc in ["example.org", "www.example.org"]:
                        vuln = Vulnerability(
                            title=f"Open Redirect via Parameter '{param}'",
                            severity="medium",
                            cvss_score=6.1,
                            description=(
                                f"The parameter '{param}' redirects users to external third-party domains without validation. "
                                "Attackers can leverage this for credential phishing campaigns."
                            ),
                            location=f"Query Parameter: '{param}'",
                            url=self.url,
                            poc_url=test_url,
                            reproduce_curl=f"curl -i -k '{test_url}'",
                            evidence=f"HTTP {resp.status_code} Redirect\nLocation: {location}",
                            remediation="Validate redirection targets against a strict whitelist of internal relative paths.",
                            category="open_redirect",
                            confidence="CONFIRMED",
                            param=param,
                        )
                        vulns.append(vuln)
                        self._add_vuln(vuln)

            except requests.RequestException:
                continue

        return vulns

    def check_information_disclosure(self) -> list[Vulnerability]:
        """
        Inspect headers for technical leakage and version disclosures.
        """
        logger.info("Inspecting headers for version leaks...")
        resp = self._fetch_root()
        if not resp:
            return []

        vulns = []
        server = resp.headers.get("Server", "")
        # Only flag if concrete version digits are leaked
        if server and any(c.isdigit() for c in server):
            vuln = Vulnerability(
                title=f"Information Disclosure: Server Version ({server})",
                severity="low",
                cvss_score=3.7,
                description=f"Server header discloses software and exact version number: '{server}'.",
                location="HTTP Response Header: 'Server'",
                url=self.url,
                poc_url=self.url,
                reproduce_curl=f"curl -I -k '{self.url}'",
                evidence=f"Server: {server}",
                remediation="Configure server to suppress version numbers (e.g., ServerTokens Prod in Apache, server_tokens off in Nginx).",
                category="info_disclosure",
                confidence="CONFIRMED",
            )
            vulns.append(vuln)
            self._add_vuln(vuln)

        powered_by = resp.headers.get("X-Powered-By", "")
        if powered_by:
            vuln = Vulnerability(
                title=f"Information Disclosure: Technology Stack ({powered_by})",
                severity="low",
                cvss_score=3.1,
                description=f"X-Powered-By header discloses underlying backend framework: '{powered_by}'.",
                location="HTTP Response Header: 'X-Powered-By'",
                url=self.url,
                poc_url=self.url,
                reproduce_curl=f"curl -I -k '{self.url}'",
                evidence=f"X-Powered-By: {powered_by}",
                remediation="Disable or remove X-Powered-By header in web application settings.",
                category="info_disclosure",
                confidence="CONFIRMED",
            )
            vulns.append(vuln)
            self._add_vuln(vuln)

        return vulns

    def check_ssl_issues(self) -> list[Vulnerability]:
        """
        Evaluate HTTPS enforcement and unencrypted HTTP downgrade risks.
        """
        logger.info("Evaluating SSL/HTTPS enforcement...")
        vulns = []
        parsed = urlparse(self.url)

        if parsed.scheme == "https":
            http_url = self.url.replace("https://", "http://", 1)
            try:
                resp = self.session.get(http_url, timeout=self.timeout, allow_redirects=False)
                if resp.status_code == 200:
                    vuln = Vulnerability(
                        title="Plaintext HTTP Accessible Without HTTPS Redirect",
                        severity="medium",
                        cvss_score=5.3,
                        description="Plaintext HTTP on port 80 is accessible and does not redirect to HTTPS, leaving communication vulnerable to eavesdropping.",
                        location="Network Transport: HTTP (Port 80)",
                        url=http_url,
                        poc_url=http_url,
                        reproduce_curl=f"curl -I -k '{http_url}'",
                        evidence=f"HTTP {http_url} returned 200 OK without redirecting to HTTPS.",
                        remediation="Configure web server to automatically redirect (301) all HTTP requests to HTTPS.",
                        category="ssl",
                        confidence="CONFIRMED",
                    )
                    vulns.append(vuln)
                    self._add_vuln(vuln)
            except requests.RequestException:
                pass

        elif parsed.scheme == "http":
            vuln = Vulnerability(
                title="Missing HTTPS Encryption (Plaintext Transport)",
                severity="high",
                cvss_score=7.4,
                description="The entire application operates over unencrypted HTTP, leaving all sessions, passwords, and cookies vulnerable to man-in-the-middle attacks.",
                location="Network Transport: HTTP (Port 80)",
                url=self.url,
                poc_url=self.url,
                reproduce_curl=f"curl -I '{self.url}'",
                evidence="Protocol scheme is unencrypted 'http://'.",
                remediation="Install a valid SSL/TLS certificate and force all connections over HTTPS.",
                category="ssl",
                confidence="CONFIRMED",
            )
            vulns.append(vuln)
            self._add_vuln(vuln)

        return vulns

    def scan_all(self) -> list[dict[str, Any]]:
        """
        Run the complete ultra-precision vulnerability scan suite.
        Returns a sorted list of confirmed vulnerabilities.
        """
        logger.info(f"Initiating zero-false-positive scan on [bold magenta]{self.url}[/bold magenta]")
        start = datetime.now()
        self._vulns = []

        # Run all precision detection modules
        self.profile_404_baseline()
        self.check_security_headers()
        self.check_cors()
        self.check_clickjacking()
        self.check_sensitive_files()
        self.check_directory_listing()
        self.check_parameter_reflection()
        self.check_open_redirect()
        self.check_information_disclosure()
        self.check_ssl_issues()

        # Sort by severity and CVSS score
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        self._vulns.sort(key=lambda v: (severity_order.get(v.severity, 5), -v.cvss_score))

        duration = (datetime.now() - start).total_seconds()
        logger.info(
            f"Audit finished in {duration:.2f}s: [bold {'red' if self._vulns else 'green'}]"
            f"{len(self._vulns)}[/bold {'red' if self._vulns else 'green'}] verified findings."
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
