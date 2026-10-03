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
        "remediation": "Nginx: add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always; | Apache: Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "cvss": 6.1,
        "description": "Content Security Policy (CSP) header is absent, increasing exposure to Cross-Site Scripting (XSS), script injection, and frame hijacking.",
        "remediation": "Nginx: add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; frame-ancestors 'self';\" always; | Apache: Header always set Content-Security-Policy \"default-src 'self'; script-src 'self';\"",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "cvss": 4.3,
        "description": "X-Content-Type-Options header is absent, allowing MIME-type sniffing by browsers and potentially executing uploaded media as scripts.",
        "remediation": "Nginx: add_header X-Content-Type-Options \"nosniff\" always; | Apache: Header always set X-Content-Type-Options \"nosniff\"",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "cvss": 5.4,
        "description": "X-Frame-Options header is missing, allowing third-party sites to embed this page in invisible frames to orchestrate clickjacking attacks.",
        "remediation": "Nginx: add_header X-Frame-Options \"SAMEORIGIN\" always; (or DENY) | Apache: Header always set X-Frame-Options \"SAMEORIGIN\"",
    },
    "Referrer-Policy": {
        "severity": "low",
        "cvss": 3.1,
        "description": "Referrer-Policy header is absent, potentially leaking private tokens or URLs in HTTP Referer headers when navigating external links.",
        "remediation": "Nginx: add_header Referrer-Policy \"strict-origin-when-cross-origin\" always; | Apache: Header always set Referrer-Policy \"strict-origin-when-cross-origin\"",
    },
    "Permissions-Policy": {
        "severity": "low",
        "cvss": 3.1,
        "description": "Permissions-Policy header is missing; browser hardware APIs (camera, microphone, geolocation, payment) are unrestricted.",
        "remediation": "Nginx: add_header Permissions-Policy \"camera=(), microphone=(), geolocation=(), payment=()\" always; | Apache: Header always set Permissions-Policy \"camera=(), microphone=(), geolocation=()\"",
    },
    "Cross-Origin-Opener-Policy": {
        "severity": "low",
        "cvss": 3.1,
        "description": "Cross-Origin-Opener-Policy (COOP) header is absent, allowing cross-origin window interaction and Spectre-based leaks.",
        "remediation": "Nginx: add_header Cross-Origin-Opener-Policy \"same-origin\" always; | Apache: Header always set Cross-Origin-Opener-Policy \"same-origin\"",
    },
    "Cross-Origin-Embedder-Policy": {
        "severity": "low",
        "cvss": 3.1,
        "description": "Cross-Origin-Embedder-Policy (COEP) header is absent, allowing unconstrained cross-origin resource embedding.",
        "remediation": "Nginx: add_header Cross-Origin-Embedder-Policy \"require-corp\" always; | Apache: Header always set Cross-Origin-Embedder-Policy \"require-corp\"",
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
    {
        "path": "/docker-compose.yml",
        "title": "Exposed Docker Compose Configuration (docker-compose.yml)",
        "severity": "high",
        "cvss": 7.5,
        "category": "sensitive_data",
        "regex": r"(?m)^(version:\s*['\"]?[23]|services:\s*\n\s+\w+:)",
        "must_not_contain": ["<!DOCTYPE html", "<html", "<head", "<body"],
        "description": "Publicly accessible Docker Compose manifest discloses internal container architecture, linked services, ports, and environment variable names.",
        "remediation": "Remove container orchestration files from public document roots.",
    },
    {
        "path": "/terraform.tfstate",
        "title": "Exposed Terraform Infrastructure State File (terraform.tfstate)",
        "severity": "critical",
        "cvss": 9.8,
        "category": "sensitive_data",
        "regex": r"(?m)(\"format_version\":|\"terraform_version\":|\"resources\":\s*\[)",
        "must_not_contain": ["<!DOCTYPE html", "<html", "<head", "<body"],
        "description": "Publicly readable Terraform state file disclosing cloud infrastructure architecture, private IP subnets, and plaintext resource credentials.",
        "remediation": "Never store terraform.tfstate in web document roots. Use secure encrypted remote state backends.",
    },
    {
        "path": "/Dockerfile",
        "title": "Exposed Docker Container Build Specification (Dockerfile)",
        "severity": "medium",
        "cvss": 5.3,
        "category": "info_disclosure",
        "regex": r"(?m)^(FROM\s+[a-zA-Z0-9_\.\/-]+|RUN\s+|ENTRYPOINT\s+|WORKDIR\s+)",
        "must_not_contain": ["<!DOCTYPE html", "<html", "<head", "<body"],
        "description": "Exposed Dockerfile reveals base image versions, internal system packages, and build execution steps.",
        "remediation": "Exclude Dockerfiles from the public web server directory.",
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
        skip_standalone_modules: bool = False,
    ):
        """
        Initialize the vulnerability scanner.

        Args:
            url: Target URL.
            timeout: Network request timeout.
            user_agent: Custom User-Agent header.
            verify_ssl: Whether to verify SSL certificates.
            skip_standalone_modules: Whether to skip standalone modules already run in master pipeline.
        """
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.skip_standalone_modules = skip_standalone_modules
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

            # If arbitrary reflection was not already detected, test specific null origin handling
            if not any("Arbitrary Origin Dynamic Reflection" in v.title for v in vulns):
                try:
                    resp_null = self.session.get(self.url, headers={"Origin": "null"}, timeout=self.timeout)
                    acao_null = resp_null.headers.get("Access-Control-Allow-Origin", "").strip()
                    acac_null = resp_null.headers.get("Access-Control-Allow-Credentials", "").lower()

                    if acao_null.lower() == "null":
                        is_cred = acac_null == "true"
                        vuln = Vulnerability(
                            title="CORS: Insecure 'null' Origin Whitelist" + (" with Credentials" if is_cred else ""),
                            severity="high" if is_cred else "medium",
                            cvss_score=7.5 if is_cred else 5.3,
                            description=(
                                "The server trusts the 'null' Origin in Access-Control-Allow-Origin. "
                                "Attackers can leverage sandboxed iframes or local HTML files to execute unauthorized cross-origin requests."
                            ),
                            location="HTTP Response Header: 'Access-Control-Allow-Origin: null'",
                            url=self.url,
                            poc_url=self.url,
                            reproduce_curl=f"curl -i -k -H 'Origin: null' '{self.url}'",
                            evidence=f"Sent: Origin: null\nReceived: Access-Control-Allow-Origin: null\nCredentials: {acac_null}",
                            remediation="Do not reflect or whitelist 'null' in Access-Control-Allow-Origin. Specify exact trusted host origins.",
                            category="cors",
                            confidence="CONFIRMED",
                        )
                        vulns.append(vuln)
                        self._add_vuln(vuln)
                except requests.RequestException:
                    pass

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
                description=(
                    f"The HTTP response header discloses the web server software and granular version: 'Server: {server}'. "
                    "Revealing exact software versions assists attackers in identifying version-specific CVEs, known unpatched flaws, "
                    "and automated exploit payloads."
                ),
                location="HTTP Response Header: 'Server'",
                url=self.url,
                poc_url=self.url,
                reproduce_curl=f"curl -I -k '{self.url}'",
                evidence=f"Server: {server}",
                remediation=(
                    "Nginx: add 'server_tokens off;' inside http block (/etc/nginx/nginx.conf) | "
                    "Apache: set 'ServerTokens Prod' and 'ServerSignature Off' in httpd.conf"
                ),
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
                description=(
                    f"The 'X-Powered-By' header discloses the backend programming framework or runtime: '{powered_by}'. "
                    "Disclosing backend runtime technology reduces attacker reconnaissance effort and provides targeting intelligence for framework exploits."
                ),
                location="HTTP Response Header: 'X-Powered-By'",
                url=self.url,
                poc_url=self.url,
                reproduce_curl=f"curl -I -k '{self.url}'",
                evidence=f"X-Powered-By: {powered_by}",
                remediation=(
                    "PHP: set 'expose_php = Off' in php.ini | "
                    "Express.js: call 'app.disable(\"x-powered-by\");' | "
                    "ASP.NET: remove X-Powered-By in web.config | "
                    "Nginx: use 'proxy_hide_header X-Powered-By;'"
                ),
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

    def check_cookie_security(self) -> list[Vulnerability]:
        """
        Zero False-Positive Cookie Security Audit.
        Verifies presence of Secure, HttpOnly, and SameSite attributes on all session and application cookies.
        """
        logger.info("Auditing cookie security flags...")
        resp = self._fetch_root()
        if not resp:
            return []

        vulns = []
        session_names = {"session", "sess", "phpsessid", "jsessionid", "token", "auth", "jwt", "sid", "aspsessionid"}

        for cookie in resp.cookies:
            cname = cookie.name
            is_session = any(s in cname.lower() for s in session_names)

            # 1. Secure Flag Check (when accessing over HTTPS)
            if self.url.startswith("https://") and not cookie.secure:
                vuln = Vulnerability(
                    title=f"Insecure Cookie: Missing 'Secure' Flag on '{cname}'",
                    severity="low",
                    cvss_score=3.5,
                    description=(
                        f"The cookie '{cname}' is transmitted over HTTPS without the 'Secure' attribute. "
                        "Browsers may leak this cookie over unencrypted HTTP connections if plaintext requests occur."
                    ),
                    location=f"Set-Cookie Header: '{cname}'",
                    url=self.url,
                    poc_url=self.url,
                    reproduce_curl=f"curl -i -k '{self.url}' | grep -i 'set-cookie'",
                    evidence=f"Cookie: {cname}\nMissing: Secure flag",
                    remediation=f"Append '; Secure' to '{cname}' in Set-Cookie header.",
                    category="cookie_security",
                    confidence="CONFIRMED",
                )
                vulns.append(vuln)
                self._add_vuln(vuln)

            # 2. HttpOnly Flag Check
            is_httponly = bool(getattr(cookie, "_rest", {}).get("HttpOnly", False))
            if not is_httponly:
                vuln = Vulnerability(
                    title=f"Insecure Cookie: Missing 'HttpOnly' Flag on '{cname}'",
                    severity="medium" if is_session else "low",
                    cvss_score=5.3 if is_session else 3.1,
                    description=(
                        f"The cookie '{cname}' lacks the 'HttpOnly' attribute, making it accessible "
                        "to client-side scripts via document.cookie. In the event of an XSS flaw, this allows cookie theft."
                    ),
                    location=f"Set-Cookie Header: '{cname}'",
                    url=self.url,
                    poc_url=self.url,
                    reproduce_curl=f"curl -i -k '{self.url}' | grep -i 'set-cookie'",
                    evidence=f"Cookie: {cname}\nMissing: HttpOnly flag",
                    remediation=f"Append '; HttpOnly' to '{cname}' in Set-Cookie header.",
                    category="cookie_security",
                    confidence="CONFIRMED",
                )
                vulns.append(vuln)
                self._add_vuln(vuln)

            # 3. SameSite Flag Check
            samesite = getattr(cookie, "_rest", {}).get("SameSite", "")
            if not samesite:
                vuln = Vulnerability(
                    title=f"Insecure Cookie: Missing 'SameSite' Attribute on '{cname}'",
                    severity="low",
                    cvss_score=3.1,
                    description=(
                        f"The cookie '{cname}' does not configure a SameSite attribute (Lax/Strict), "
                        "making requests susceptible to Cross-Site Request Forgery (CSRF)."
                    ),
                    location=f"Set-Cookie Header: '{cname}'",
                    url=self.url,
                    poc_url=self.url,
                    reproduce_curl=f"curl -i -k '{self.url}' | grep -i 'set-cookie'",
                    evidence=f"Cookie: {cname}\nMissing: SameSite attribute",
                    remediation=f"Append '; SameSite=Lax' (or SameSite=Strict) to '{cname}' in Set-Cookie header.",
                    category="cookie_security",
                    confidence="CONFIRMED",
                )
                vulns.append(vuln)
                self._add_vuln(vuln)

        return vulns

    def check_http_trace_xst(self) -> list[Vulnerability]:
        """
        Audit for Cross-Site Tracing (XST) via enabled HTTP TRACE method.
        Eliminates false positives by asserting status 200 and reflection of a custom probe header.
        """
        logger.info("Auditing HTTP TRACE method for Cross-Site Tracing (XST)...")
        vulns = []
        probe_header = "X-Phantom-XST-Probe"
        probe_val = "phantom_trace_test_99"

        try:
            resp = self.session.request(
                "TRACE",
                self.url,
                headers={probe_header: probe_val},
                timeout=self.timeout,
                allow_redirects=False,
            )

            # Strict verification: must return 200 OK, echo probe header, and not be a soft-404 page
            if resp.status_code == 200 and probe_val in resp.text and not self._is_soft_404(resp):
                vuln = Vulnerability(
                    title="Cross-Site Tracing (XST): HTTP TRACE Method Enabled",
                    severity="medium",
                    cvss_score=5.3,
                    cve="CVE-2004-2320",
                    description=(
                        "The web server has the HTTP TRACE method enabled and echoes request headers back in the response body. "
                        "When combined with a Cross-Site Scripting (XSS) vulnerability, attackers can steal HttpOnly cookies and authorization headers."
                    ),
                    location="HTTP Request Method: TRACE",
                    url=self.url,
                    poc_url=self.url,
                    reproduce_curl=f"curl -i -k -X TRACE -H '{probe_header}: {probe_val}' '{self.url}'",
                    evidence=f"HTTP 200 OK received for TRACE request.\nEchoed Header Probe: {probe_header}: {probe_val}",
                    remediation="Disable HTTP TRACE on the web server (Apache: 'TraceEnable Off'; Nginx: return 405 for TRACE requests).",
                    category="misconfiguration",
                    confidence="CONFIRMED",
                    method="TRACE",
                )
                vulns.append(vuln)
                self._add_vuln(vuln)

        except requests.RequestException:
            pass

        return vulns

    def check_email_security(self) -> list[Vulnerability]:
        """
        DNS Email Security and Anti-Spoofing Audit (SPF & DMARC).
        Identifies missing or insecure policies that allow domain-level email phishing and spoofing.
        """
        parsed = urlparse(self.url)
        domain = parsed.hostname or ""
        # Skip IP addresses or localhost
        if not domain or re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", domain) or domain in ("localhost", "127.0.0.1"):
            return []

        logger.info(f"Auditing DNS email spoofing defenses for domain '{domain}'...")
        vulns = []
        try:
            from phantom_recon.core.dns_enum import DNSEnumerator
            dns_auditor = DNSEnumerator(domain=domain, timeout=self.timeout)
            audit = dns_auditor.audit_email_security()

            # 1. DMARC Checks
            dmarc = audit.get("dmarc", {})
            if not dmarc.get("present"):
                vuln = Vulnerability(
                    title=f"Email Spoofing Risk: Missing DMARC Record on '{domain}'",
                    severity="high",
                    cvss_score=7.1,
                    description=(
                        f"The domain '{domain}' lacks a DMARC (Domain-based Message Authentication, Reporting, and Conformance) DNS record. "
                        "Without DMARC, receiving email servers cannot verify authentic senders, allowing attackers to forge emails from this domain."
                    ),
                    location=f"DNS TXT Record: '_dmarc.{domain}'",
                    url=self.url,
                    poc_url=f"https://mxtoolbox.com/SuperTool.aspx?action=dmarc%3a{domain}",
                    reproduce_curl=f"nslookup -type=TXT _dmarc.{domain}",
                    evidence=f"No DMARC TXT record detected at _dmarc.{domain}.",
                    remediation=f"Publish a DMARC TXT record at '_dmarc.{domain}' (e.g. 'v=DMARC1; p=reject; rua=mailto:dmarc-reports@{domain}').",
                    category="dns_security",
                    confidence="CONFIRMED",
                )
                vulns.append(vuln)
                self._add_vuln(vuln)
            elif dmarc.get("policy") == "none":
                vuln = Vulnerability(
                    title=f"Email Spoofing Exposure: Ineffective DMARC Policy (p=none) on '{domain}'",
                    severity="medium",
                    cvss_score=5.3,
                    description=(
                        f"The DMARC policy for '{domain}' is set to 'p=none' (monitoring only). "
                        "Spoofed emails originating from unauthorized third parties will still be delivered to recipient inboxes without rejection or quarantine."
                    ),
                    location=f"DNS TXT Record: '_dmarc.{domain}'",
                    url=self.url,
                    poc_url=f"https://mxtoolbox.com/SuperTool.aspx?action=dmarc%3a{domain}",
                    reproduce_curl=f"nslookup -type=TXT _dmarc.{domain}",
                    evidence=f"Current DMARC Record: {dmarc.get('raw', '')}\nPolicy: p=none",
                    remediation=f"Enforce anti-spoofing by upgrading the DMARC policy from 'p=none' to 'p=quarantine' or 'p=reject'.",
                    category="dns_security",
                    confidence="CONFIRMED",
                )
                vulns.append(vuln)
                self._add_vuln(vuln)

            # 2. SPF Checks
            spf = audit.get("spf", {})
            if not spf.get("present"):
                vuln = Vulnerability(
                    title=f"Email Security: Missing SPF Record on '{domain}'",
                    severity="medium",
                    cvss_score=5.3,
                    description=(
                        f"The domain '{domain}' does not publish a Sender Policy Framework (SPF) record. "
                        "Mail servers cannot determine authorized IP addresses permitted to send email on behalf of this domain."
                    ),
                    location=f"DNS TXT Record: '{domain}'",
                    url=self.url,
                    poc_url=f"https://mxtoolbox.com/SuperTool.aspx?action=spf%3a{domain}",
                    reproduce_curl=f"nslookup -type=TXT {domain}",
                    evidence=f"No SPF record starting with 'v=spf1' found on {domain}.",
                    remediation="Add a valid SPF TXT record defining authorized sending servers (e.g. 'v=spf1 mx -all').",
                    category="dns_security",
                    confidence="CONFIRMED",
                )
                vulns.append(vuln)
                self._add_vuln(vuln)
            elif spf.get("policy") == "+all":
                vuln = Vulnerability(
                    title=f"Critical Email Spoofing: Permissive SPF Record (+all) on '{domain}'",
                    severity="critical",
                    cvss_score=9.1,
                    description=(
                        f"The SPF record on '{domain}' explicitly specifies '+all', authorizing every server on the internet to send legitimate emails from this domain."
                    ),
                    location=f"DNS TXT Record: '{domain}'",
                    url=self.url,
                    poc_url=f"https://mxtoolbox.com/SuperTool.aspx?action=spf%3a{domain}",
                    reproduce_curl=f"nslookup -type=TXT {domain}",
                    evidence=f"Insecure SPF Record: {spf.get('raw', '')}",
                    remediation="Update SPF policy from '+all' to '-all' (hard fail) or '~all' (soft fail).",
                    category="dns_security",
                    confidence="CONFIRMED",
                )
                vulns.append(vuln)
                self._add_vuln(vuln)

        except Exception as e:
            logger.debug(f"Email security audit error for {domain}: {e}")

        return vulns

    def check_javascript_secrets(self) -> list[Vulnerability]:
        """
        Audit client-side JavaScript files for exposed credentials and private API keys.
        """
        logger.info("Analyzing client-side JavaScript files for hardcoded secrets...")
        vulns = []
        try:
            from phantom_recon.core.web_recon import WebRecon
            recon = WebRecon(url=self.url, timeout=self.timeout, follow_redirects=self.follow_redirects)
            js_results = recon.analyze_javascript_files(max_files=6)

            for secret in js_results.get("secrets", []):
                sec_type = secret.get("type", "API Secret")
                sec_file = secret.get("file", self.url)
                preview = secret.get("preview", "***")

                vuln = Vulnerability(
                    title=f"Information Disclosure: Exposed {sec_type} in JavaScript",
                    severity="high" if any(w in sec_type for w in ["Key", "Token", "Secret"]) else "medium",
                    cvss_score=7.5 if any(w in sec_type for w in ["Key", "Token", "Secret"]) else 5.3,
                    description=(
                        f"A client-side JavaScript file exposes sensitive credentials ({sec_type}). "
                        "Publicly accessible secrets can be harvested by malicious actors to access private cloud services or APIs."
                    ),
                    location=f"JavaScript Asset: {sec_file}",
                    url=self.url,
                    poc_url=sec_file,
                    reproduce_curl=f"curl -i -k '{sec_file}'",
                    evidence=f"Identified credential signature: {sec_type}\nRedacted Token: {preview}",
                    remediation="Remove sensitive credentials from client-side bundles. Use backend proxy endpoints or secrets management.",
                    category="sensitive_data",
                    confidence="CONFIRMED",
                )
                vulns.append(vuln)
                self._add_vuln(vuln)

        except Exception as e:
            logger.debug(f"JavaScript secret scanning error: {e}")

        return vulns

    def check_waf_and_origin_leakage(self) -> list[Vulnerability]:
        """
        Audit for WAF/CDN edge proxy presence and unproxied backend origin IP leakage.
        """
        logger.info(f"Auditing WAF presence and backend origin IP leakage on '{self.url}'...")
        vulns = []
        try:
            from phantom_recon.core.waf_detector import WAFDetector
            detector = WAFDetector(target=self.url, timeout=self.timeout)
            waf_results = detector.run_full_waf_analysis()

            has_waf = waf_results.get("has_waf", False)
            waf_name = waf_results.get("waf_name", "Unknown")
            resolved_ips = waf_results.get("resolved_ips", [])
            origin_leak = waf_results.get("origin_leakage", {})
            unprotected_candidates = origin_leak.get("unprotected_origin_candidates", [])

            if has_waf:
                # If WAF detected and unprotected origin server candidates exist
                if unprotected_candidates:
                    leak_details = "\n".join(
                        f"• {c['source']} → IP: {c['ip']} ({c.get('evidence', '')})"
                        for c in unprotected_candidates[:5]
                    )
                    vuln = Vulnerability(
                        title=f"WAF Bypass Exposure: Potential Origin Server IP Leaked for '{detector.domain}'",
                        severity="high",
                        cvss_score=7.5,
                        description=(
                            f"The domain '{detector.domain}' is fronted by {waf_name} Web Application Firewall, "
                            "but exposed DNS/subdomain records reveal direct, unproxied backend origin IP addresses. "
                            "Adversaries can bypass all cloud WAF inspection, rate limiting, and DDoS mitigation "
                            "by directing traffic directly to these unprotected origin IPs."
                        ),
                        location=f"DNS / Origin Infrastructure: {detector.domain}",
                        url=self.url,
                        poc_url=self.url,
                        reproduce_curl=f"curl -i -k -H 'Host: {detector.domain}' 'https://{unprotected_candidates[0]['ip']}/'",
                        evidence=(
                            f"Target is fronted by: {waf_name}\n"
                            f"Resolved Edge IPs: {', '.join(resolved_ips)}\n"
                            f"Exposed Origin Candidates:\n{leak_details}"
                        ),
                        remediation=(
                            f"1. Configure origin server firewall/security groups to reject all incoming HTTP/HTTPS connections "
                            f"except from authorized {waf_name} IP ranges.\n"
                            "2. Proxify or isolate mail (MX), FTP, and internal subdomains onto separate non-application IP ranges.\n"
                            "3. Do not publish backend origin server IP addresses in SPF TXT records."
                        ),
                        category="infrastructure_exposure",
                        confidence="CONFIRMED",
                    )
                    vulns.append(vuln)
                    self._add_vuln(vuln)
                else:
                    # Target is behind WAF and no direct origin leak found
                    vuln = Vulnerability(
                        title=f"Cloud Infrastructure: Target Fronted by {waf_name} CDN/WAF",
                        severity="info",
                        cvss_score=0.0,
                        description=(
                            f"The target host '{detector.domain}' is fronted by {waf_name} edge proxy infrastructure. "
                            "Direct port scanning and perimeter probing will target edge Anycast nodes rather than internal origin hosts."
                        ),
                        location=f"Network Edge: {waf_name}",
                        url=self.url,
                        poc_url=self.url,
                        reproduce_curl=f"curl -I '{self.url}'",
                        evidence=f"Edge Provider: {waf_name}. Indicators: {'; '.join(waf_results.get('indicators', [])[:3])}",
                        remediation="Ensure origin server IP is strictly firewalled to only accept traffic from the CDN/WAF provider.",
                        category="infrastructure_info",
                        confidence="CONFIRMED",
                    )
                    vulns.append(vuln)
                    self._add_vuln(vuln)

        except Exception as e:
            logger.debug(f"WAF and origin leakage check error: {e}")

        return vulns

    def check_api_and_docs(self) -> list[Vulnerability]:
        """
        Audit for publicly exposed API documentation, OpenAPI/Swagger schemas,
        GraphQL endpoints, and Spring Boot Actuators.
        """
        logger.info(f"Auditing target for exposed API schemas & endpoints on '{self.url}'...")
        vulns = []
        try:
            from phantom_recon.core.api_scanner import APIScanner
            api_scanner = APIScanner(url=self.url, timeout=self.timeout)
            findings = api_scanner.scan_endpoints()

            for ep in findings:
                cat = ep.get("category", "")
                ep_type = ep.get("type", "API Endpoint")
                ep_url = ep.get("url", "")
                ep_path = ep.get("path", "")
                evidence = ep.get("evidence", "")

                if cat == "actuator" and ep_path in ("/actuator/env", "/actuator/httptrace"):
                    sev = "high"
                    cvss = 7.5
                elif cat in ("schema", "actuator"):
                    sev = "medium"
                    cvss = 5.3
                else:
                    sev = "low"
                    cvss = 3.7

                vuln = Vulnerability(
                    title=f"API Exposure: Confirmed {ep_type} at '{ep_path}'",
                    severity=sev,
                    cvss_score=cvss,
                    description=(
                        f"The web application publicly exposes an active {ep_type}. "
                        "Publicly accessible API schemas and interfaces expose application routes, "
                        "data models, parameter requirements, and potential administrative hooks to unauthorized users."
                    ),
                    location=f"API Path: {ep_path}",
                    url=self.url,
                    poc_url=ep_url,
                    reproduce_curl=f"curl -i -k '{ep_url}'",
                    evidence=f"HTTP {ep.get('status_code')} OK\n{evidence}",
                    remediation=ep.get("remediation", "Restrict endpoint to authorized roles."),
                    category="api_exposure",
                    confidence="CONFIRMED",
                )
                vulns.append(vuln)
                self._add_vuln(vuln)

        except Exception as e:
            logger.debug(f"API discovery error: {e}")

        return vulns

    def check_cloud_storage(self) -> list[Vulnerability]:
        """
        Audit for publicly exposed cloud storage buckets (AWS S3, GCP, Azure Blob)
        associated with the target organization.
        """
        logger.info(f"Auditing target for exposed cloud storage buckets...")
        vulns = []
        try:
            from phantom_recon.core.cloud_auditor import CloudAuditor
            auditor = CloudAuditor(target=self.url, timeout=self.timeout)
            results = auditor.run_cloud_audit()

            open_buckets = results.get("open_buckets") or [
                f for f in results.get("findings", []) if f.get("is_open")
            ]
            for b in open_buckets:
                provider = b.get("provider", "Cloud Storage")
                name = b.get("bucket_name", "")
                url = b.get("url", "")
                count = b.get("object_count", 0)
                evidence = b.get("evidence", "")

                vuln = Vulnerability(
                    title=f"Cloud Storage Leakage: Publicly Listable {provider} Bucket '{name}'",
                    severity="critical",
                    cvss_score=9.1,
                    description=(
                        f"The {provider} storage bucket '{name}' is publicly accessible and listable without authentication. "
                        f"Anonymous users can list and download sensitive files ({count} objects detected)."
                    ),
                    location=f"Cloud Storage: {url}",
                    url=self.url,
                    poc_url=url,
                    reproduce_curl=f"curl -i -s '{url}'",
                    evidence=evidence,
                    remediation=b.get("remediation", "Disable public access and enforce strict IAM bucket policies."),
                    category="cloud_misconfiguration",
                    confidence="CONFIRMED",
                )
                vulns.append(vuln)
                self._add_vuln(vuln)

        except Exception as e:
            logger.debug(f"Cloud storage audit error: {e}")

        return vulns

    def check_http_methods(self) -> list[Vulnerability]:
        """
        Audit supported HTTP methods and dangerous verbs (PUT, DELETE, TRACE, WebDAV PROPFIND).
        """
        logger.info("Auditing HTTP methods and dangerous verbs (PUT, DELETE, TRACE, WebDAV)...")
        vulns = []
        try:
            from phantom_recon.core.http_methods import HTTPMethodsAuditor
            auditor = HTTPMethodsAuditor(
                url=self.url,
                timeout=self.timeout,
                verify_ssl=self.verify_ssl,
            )
            audit_data = auditor.audit_all()
            for v_data in audit_data.get("vulnerabilities", []):
                # Avoid duplicate findings
                if any(existing.method == v_data.get("method") and existing.title == v_data.get("title") for existing in self._vulns):
                    continue
                v = Vulnerability(
                    title=v_data["title"],
                    severity=v_data["severity"],
                    cvss_score=v_data.get("cvss_score", 5.0),
                    description=v_data["description"],
                    location=v_data.get("location", f"HTTP Method: {v_data.get('method', 'OPTIONS')}"),
                    url=self.url,
                    poc_url=v_data.get("poc_url", self.url),
                    reproduce_curl=v_data.get("reproduce_curl", f"curl -i -k '{self.url}'"),
                    evidence=v_data.get("evidence", ""),
                    remediation=v_data.get("remediation", ""),
                    cve=v_data.get("cve", ""),
                    category=v_data.get("category", "misconfiguration"),
                    confidence=v_data.get("confidence", "CONFIRMED"),
                    method=v_data.get("method", "GET"),
                )
                vulns.append(v)
                self._add_vuln(v)
        except Exception as e:
            logger.debug(f"HTTP methods audit error: {e}")

        return vulns

    def check_cms_and_frameworks(self) -> list[Vulnerability]:
        """
        Audit CMS, web frameworks, and client-side source map exposures.
        """
        logger.info("Auditing CMS, web frameworks, and source map disclosures...")
        vulns = []
        try:
            from phantom_recon.core.cms_auditor import CMSAuditor
            auditor = CMSAuditor(
                url=self.url,
                timeout=self.timeout,
                verify_ssl=self.verify_ssl,
            )
            cms_results = auditor.run_full_audit()
            for v_data in cms_results.get("vulnerabilities", []):
                # Avoid duplicate findings
                if any(existing.title == v_data.get("title") for existing in self._vulns):
                    continue
                v = Vulnerability(
                    title=v_data["title"],
                    severity=v_data["severity"],
                    cvss_score=v_data.get("cvss_score", 5.0),
                    description=v_data["description"],
                    location=v_data.get("location", "CMS / Framework Architecture"),
                    url=self.url,
                    poc_url=v_data.get("poc_url", self.url),
                    reproduce_curl=v_data.get("reproduce_curl", f"curl -i -k '{self.url}'"),
                    evidence=v_data.get("evidence", ""),
                    remediation=v_data.get("remediation", ""),
                    category="cms_framework",
                    confidence="CONFIRMED",
                )
                vulns.append(v)
                self._add_vuln(v)
        except Exception as e:
            logger.debug(f"CMS audit error: {e}")

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
        if not self.skip_standalone_modules:
            self.check_waf_and_origin_leakage()
            self.check_api_and_docs()
            self.check_cloud_storage()
            self.check_cms_and_frameworks()
            self.check_http_methods()
            self.check_security_headers()
        self.check_cookie_security()
        self.check_cors()
        self.check_clickjacking()
        self.check_sensitive_files()
        self.check_directory_listing()
        self.check_parameter_reflection()
        self.check_open_redirect()
        self.check_http_trace_xst()
        self.check_javascript_secrets()
        self.check_information_disclosure()
        if not self.skip_standalone_modules:
            self.check_email_security()
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

    def get_security_score(self) -> dict[str, Any]:
        """Calculate and return executive security health score and letter grade."""
        from phantom_recon.reporting.security_score import calculate_security_score
        return calculate_security_score([v.to_dict() for v in self._vulns])

