"""
Phantom Recon — CMS & Framework Security Auditor (v1.9.0).

Specialized in fingerprinting and auditing Content Management Systems (WordPress,
Drupal, Joomla) and Web Frameworks (Laravel, Django, Spring Boot, Next.js).
Audits for user enumeration, XML-RPC exposure, debug logs, administrative panels,
and frontend JavaScript Source Map (.js.map) disclosures.

Engineered with zero-false-positive soft-404 profiling.

⚠️ DISCLAIMER: For authorized security testing only.
"""

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import re
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from phantom_recon.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class CMSFinding:
    """Represents a validated CMS or framework finding."""
    title: str
    cms_name: str
    severity: str
    cvss: float
    description: str
    location: str
    url: str
    remediation: str
    evidence: str = ""
    reproduce_curl: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "cms_name": self.cms_name,
            "severity": self.severity,
            "cvss_score": self.cvss,
            "description": self.description,
            "location": self.location,
            "url": self.url,
            "poc_url": self.url,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "reproduce_curl": self.reproduce_curl or f"curl -i -k '{self.url}'",
            "category": "cms_framework",
            "confidence": "CONFIRMED",
        }


class CMSAuditor:
    """
    Advanced CMS & Framework Security Auditor.
    Identifies software architectures and performs precision vulnerability auditing.
    """

    def __init__(
        self,
        url: str,
        timeout: float = 6.0,
        user_agent: Optional[str] = None,
        verify_ssl: bool = False,
    ):
        parsed = urlparse(url)
        if not parsed.scheme:
            self.url = f"https://{url}".rstrip("/")
        else:
            self.url = url.rstrip("/")

        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers.update({
            "User-Agent": user_agent or (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 (PhantomRecon/1.9.0)"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })

        self._root_html: str = ""
        self._root_headers: dict[str, str] = {}
        self._baseline_status = 404
        self._baseline_length = 0
        self._has_soft_404 = False
        self._profiled = False

    def _profile_baseline(self) -> None:
        """Establish soft-404 baseline using a random canary probe."""
        if self._profiled:
            return
        token = hashlib.md5(f"cms_canary_{datetime.now().timestamp()}".encode()).hexdigest()[:12]
        canary_url = f"{self.url}/__phantom_cms_probe_{token}.html"
        try:
            resp = self.session.get(canary_url, timeout=self.timeout, allow_redirects=True)
            self._baseline_status = resp.status_code
            self._baseline_length = len(resp.content)
            if resp.status_code == 200:
                self._has_soft_404 = True
        except requests.RequestException:
            pass
        finally:
            self._profiled = True

    def _is_soft_404(self, resp: requests.Response) -> bool:
        """Check if response is a custom soft-404 error page."""
        if resp.status_code == 404:
            return True
        if self._has_soft_404:
            if resp.status_code == self._baseline_status:
                if abs(len(resp.content) - self._baseline_length) < (self._baseline_length * 0.05 + 50):
                    return True
        return False

    def _fetch_root(self) -> tuple[str, dict[str, str]]:
        """Fetch target root page with caching."""
        if not self._root_html:
            try:
                resp = self.session.get(self.url, timeout=self.timeout, allow_redirects=True)
                self._root_html = resp.text
                self._root_headers = dict(resp.headers)
            except requests.RequestException as e:
                logger.debug(f"Failed to fetch root: {e}")
        return self._root_html, self._root_headers

    def fingerprint_cms(self) -> dict[str, Any]:
        """
        Identify CMS and Framework technologies present on the target.
        """
        html, headers = self._fetch_root()
        detected = []
        details = {}

        # 1. WordPress Detection
        if (
            "wp-content" in html
            or "wp-includes" in html
            or "wordpress" in headers.get("X-Powered-By", "").lower()
            or "wordpress" in html.lower()[:2000]
        ):
            wp_version = ""
            meta_gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([\d\.]*)["\']', html, re.I)
            if meta_gen and meta_gen.group(1):
                wp_version = meta_gen.group(1)
            detected.append("WordPress")
            details["WordPress"] = {"version": wp_version}

        # 2. Laravel Detection
        if (
            "laravel_session" in headers.get("Set-Cookie", "")
            or "XSRF-TOKEN" in headers.get("Set-Cookie", "")
            or "laravel" in headers.get("X-Powered-By", "").lower()
        ):
            detected.append("Laravel")
            details["Laravel"] = {}

        # 3. Django Detection
        if (
            "csrftoken" in headers.get("Set-Cookie", "")
            or "csrfmiddlewaretoken" in html
        ):
            detected.append("Django")
            details["Django"] = {}

        # 4. Next.js / React
        if "__NEXT_DATA__" in html or "/_next/static/" in html:
            detected.append("Next.js")
            details["Next.js"] = {}

        # 5. Drupal Detection
        if "drupal" in headers.get("X-Generator", "").lower() or "drupal.js" in html.lower():
            detected.append("Drupal")
            details["Drupal"] = {}

        # 6. Joomla Detection
        if "joomla" in html.lower() and ("/media/jui/" in html or "joomla!" in html.lower()):
            detected.append("Joomla")
            details["Joomla"] = {}

        # 7. Spring Boot
        if "whitelabel error page" in html.lower() or "timestamp" in html.lower() and "status" in html.lower() and "error" in html.lower():
            detected.append("Spring Boot")
            details["Spring Boot"] = {}

        return {
            "detected_cms": detected,
            "primary_cms": detected[0] if detected else "Generic / Custom",
            "details": details,
        }

    def audit_wordpress(self) -> list[CMSFinding]:
        """
        Specialized audit for WordPress deployments.
        Checks for user enumeration via REST API, XML-RPC exposure, debug logs, and registration.
        """
        findings: list[CMSFinding] = []
        self._profile_baseline()

        # Check 1: REST API User Enumeration (/wp-json/wp/v2/users)
        users_url = f"{self.url}/wp-json/wp/v2/users"
        try:
            resp = self.session.get(users_url, timeout=self.timeout, allow_redirects=False)
            if resp.status_code == 200 and "application/json" in resp.headers.get("Content-Type", ""):
                try:
                    data = resp.json()
                    if isinstance(data, list) and len(data) > 0 and "slug" in data[0]:
                        usernames = [u.get("slug") for u in data if isinstance(u, dict) and u.get("slug")]
                        if usernames:
                            evidence = f"Exposed {len(usernames)} user account(s): {', '.join(usernames[:10])}"
                            findings.append(CMSFinding(
                                title="WordPress User Enumeration via REST API (/wp-json/wp/v2/users)",
                                cms_name="WordPress",
                                severity="medium",
                                cvss=5.3,
                                description=(
                                    "The WordPress REST API publicly discloses registered user login names and IDs. "
                                    "Attackers utilize these enumerated accounts to conduct targeted credential brute force attacks."
                                ),
                                location="URL: /wp-json/wp/v2/users",
                                url=users_url,
                                evidence=evidence,
                                reproduce_curl=f"curl -i -k -s '{users_url}' | grep 'slug'",
                                remediation="Restrict public access to /wp-json/wp/v2/users or require authentication using a security plugin.",
                            ))
                except json.JSONDecodeError:
                    pass
        except requests.RequestException:
            pass

        # Check 2: XML-RPC Amplification & Brute Force Vector (/xmlrpc.php)
        xmlrpc_url = f"{self.url}/xmlrpc.php"
        try:
            resp = self.session.get(xmlrpc_url, timeout=self.timeout, allow_redirects=False)
            # Standard xmlrpc response is 405 or 200 with text 'XML-RPC server accepts POST requests only.'
            if "XML-RPC server accepts POST requests only" in resp.text:
                findings.append(CMSFinding(
                    title="WordPress XML-RPC Interface Exposed (/xmlrpc.php)",
                    cms_name="WordPress",
                    severity="low",
                    cvss=4.3,
                    description=(
                        "The XML-RPC API is enabled on the server. This interface can be exploited for "
                        "amplified multi-call brute-force attacks and distributed Denial of Service (pingback DDoS)."
                    ),
                    location="URL: /xmlrpc.php",
                    url=xmlrpc_url,
                    evidence="Received: 'XML-RPC server accepts POST requests only.'",
                    reproduce_curl=f"curl -i -k '{xmlrpc_url}'",
                    remediation="Disable XML-RPC in web server configuration or .htaccess (deny from all to xmlrpc.php).",
                ))
        except requests.RequestException:
            pass

        # Check 3: Exposed WordPress Debug Log (/wp-content/debug.log)
        debug_url = f"{self.url}/wp-content/debug.log"
        try:
            resp = self.session.get(debug_url, timeout=self.timeout, allow_redirects=False)
            if resp.status_code == 200 and not self._is_soft_404(resp):
                # Verify genuine PHP debug log structure
                if re.search(r"\[\d{2}-[A-Za-z]{3}-\d{4}.*?\]\s+PHP\s+(Notice|Fatal error|Warning)", resp.text):
                    findings.append(CMSFinding(
                        title="Exposed WordPress Debug Log (/wp-content/debug.log)",
                        cms_name="WordPress",
                        severity="high",
                        cvss=7.5,
                        description=(
                            "The WordPress WP_DEBUG_LOG file is publicly readable. It exposes PHP stack traces, "
                            "database queries, internal file system paths, and potentially sensitive credentials."
                        ),
                        location="URL: /wp-content/debug.log",
                        url=debug_url,
                        evidence=resp.text[:160],
                        reproduce_curl=f"curl -i -k '{debug_url}'",
                        remediation="Set WP_DEBUG_LOG to false or configure server rules to deny HTTP access to .log files.",
                    ))
        except requests.RequestException:
            pass

        # Check 4: Version Disclosure in readme.html
        readme_url = f"{self.url}/readme.html"
        try:
            resp = self.session.get(readme_url, timeout=self.timeout, allow_redirects=False)
            if resp.status_code == 200 and not self._is_soft_404(resp):
                ver_match = re.search(r"Version\s+([\d\.]+)", resp.text, re.I)
                if ver_match:
                    findings.append(CMSFinding(
                        title=f"WordPress Version Disclosure via readme.html ({ver_match.group(1)})",
                        cms_name="WordPress",
                        severity="low",
                        cvss=3.1,
                        description="The default WordPress readme.html file is accessible and reveals the exact CMS version.",
                        location="URL: /readme.html",
                        url=readme_url,
                        evidence=f"Disclosed version: {ver_match.group(1)}",
                        reproduce_curl=f"curl -i -k '{readme_url}'",
                        remediation="Delete readme.html and license.txt from document root.",
                    ))
        except requests.RequestException:
            pass

        return findings

    def audit_laravel(self) -> list[CMSFinding]:
        """
        Specialized audit for Laravel deployments.
        Checks for exposed log files, telescope dashboard, and horizon.
        """
        findings: list[CMSFinding] = []
        self._profile_baseline()

        # Check 1: Exposed Laravel Application Log
        log_url = f"{self.url}/storage/logs/laravel.log"
        try:
            resp = self.session.get(log_url, timeout=self.timeout, allow_redirects=False)
            if resp.status_code == 200 and not self._is_soft_404(resp):
                if re.search(r"\[\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\]\s+[a-zA-Z0-9_\.]+\.(ERROR|INFO|WARNING)", resp.text):
                    findings.append(CMSFinding(
                        title="Exposed Laravel Application Log (/storage/logs/laravel.log)",
                        cms_name="Laravel",
                        severity="high",
                        cvss=7.5,
                        description=(
                            "The internal Laravel application log file is publicly accessible. "
                            "It reveals system stack traces, database schema errors, and internal server exceptions."
                        ),
                        location="URL: /storage/logs/laravel.log",
                        url=log_url,
                        evidence=resp.text[:160],
                        reproduce_curl=f"curl -i -k '{log_url}'",
                        remediation="Ensure the web server document root points to the public/ directory, never the project root.",
                    ))
        except requests.RequestException:
            pass

        # Check 2: Exposed Laravel Telescope Dashboard
        telescope_url = f"{self.url}/telescope"
        try:
            resp = self.session.get(telescope_url, timeout=self.timeout, allow_redirects=False)
            if resp.status_code == 200 and not self._is_soft_404(resp):
                if "Telescope" in resp.text and ("Requests" in resp.text or "Commands" in resp.text or "telescope-app" in resp.text):
                    findings.append(CMSFinding(
                        title="Exposed Laravel Telescope Debug Dashboard (/telescope)",
                        cms_name="Laravel",
                        severity="high",
                        cvss=7.5,
                        description=(
                            "Laravel Telescope debug assistant is accessible without authentication. "
                            "It logs all incoming HTTP requests, session tokens, SQL queries, and mail messages."
                        ),
                        location="URL: /telescope",
                        url=telescope_url,
                        evidence="Telescope UI loaded with active request monitoring access.",
                        reproduce_curl=f"curl -i -k '{telescope_url}'",
                        remediation="Restrict Telescope access in app/Providers/TelescopeServiceProvider.php to authorized emails or local environment.",
                    ))
        except requests.RequestException:
            pass

        return findings

    def audit_source_maps(self) -> list[CMSFinding]:
        """
        Audit for publicly accessible JavaScript Source Map files (.js.map).
        Extracts script tags and tests corresponding .map URLs.
        Allows full frontend source code recovery.
        """
        findings: list[CMSFinding] = []
        html, _ = self._fetch_root()
        if not html:
            return findings

        self._profile_baseline()
        soup = BeautifulSoup(html, "html.parser")
        script_srcs = []

        for s in soup.find_all("script", src=True):
            src = s["src"]
            if src.endswith(".js"):
                # Normalize relative URLs
                full_js_url = urljoin(self.url, src)
                # Ensure it's internal to the target domain
                if urlparse(full_js_url).netloc == urlparse(self.url).netloc:
                    script_srcs.append(full_js_url)

        # Probe up to 5 discovered script bundles for .map files
        for js_url in script_srcs[:5]:
            map_url = f"{js_url}.map"
            try:
                resp = self.session.get(map_url, timeout=self.timeout, allow_redirects=False)
                if resp.status_code == 200 and not self._is_soft_404(resp):
                    # Verify genuine Source Map format: JSON with "version" and "sources"
                    content_preview = resp.text[:300]
                    if '"version":' in content_preview and '"sources":' in content_preview:
                        findings.append(CMSFinding(
                            title="Publicly Exposed JavaScript Source Map File (.js.map)",
                            cms_name="Frontend / Build Artifacts",
                            severity="medium",
                            cvss=5.3,
                            description=(
                                f"A JavaScript Source Map file was discovered at {map_url}. "
                                "Source maps allow reverse-engineering of original frontend source code, "
                                "TypeScript files, developer comments, and internal API routes."
                            ),
                            location=f"URL: {urlparse(map_url).path}",
                            url=map_url,
                            evidence=f"Valid JSON source map detected ({len(resp.content)} bytes). Preview: {content_preview[:120]}...",
                            reproduce_curl=f"curl -i -k '{map_url}'",
                            remediation="Disable source map generation in production builds (e.g. productionSourceMap: false in webpack/vite/next.config.js).",
                        ))
                        # Record one finding for source maps to avoid flooding
                        break
            except requests.RequestException:
                pass

        return findings

    def audit_admin_panels(self) -> list[CMSFinding]:
        """
        Check for exposed administrative login interfaces (Django Admin, Drupal, Joomla).
        """
        findings: list[CMSFinding] = []
        self._profile_baseline()

        candidates = [
            {"path": "/admin/login/", "cms": "Django", "title": "Exposed Django Administration Portal", "match": "Django administration"},
            {"path": "/user/login", "cms": "Drupal", "title": "Exposed Drupal User Login Portal", "match": "edit-name"},
            {"path": "/administrator/", "cms": "Joomla", "title": "Exposed Joomla Administration Login", "match": "Joomla"},
        ]

        for c in candidates:
            cand_url = f"{self.url}{c['path']}"
            try:
                resp = self.session.get(cand_url, timeout=self.timeout, allow_redirects=False)
                if resp.status_code == 200 and not self._is_soft_404(resp):
                    if c["match"].lower() in resp.text.lower():
                        findings.append(CMSFinding(
                            title=c["title"],
                            cms_name=c["cms"],
                            severity="low",
                            cvss=3.5,
                            description=f"Standard administrative authentication portal is publicly accessible at {c['path']}.",
                            location=f"URL: {c['path']}",
                            url=cand_url,
                            evidence=f"HTTP 200 OK matching {c['match']}.",
                            reproduce_curl=f"curl -i -k '{cand_url}'",
                            remediation="Restrict access to administrative paths using IP allowlists or VPN.",
                        ))
            except requests.RequestException:
                pass

        return findings

    def run_full_audit(self) -> dict[str, Any]:
        """
        Execute comprehensive CMS, Framework, and Client Artifact audit.
        """
        logger.info(f"Auditing CMS & Framework architecture on [bold magenta]{self.url}[/bold magenta]")

        # 1. Fingerprint
        fp = self.fingerprint_cms()
        detected = fp["detected_cms"]

        # 2. Targeted Audits
        all_findings: list[CMSFinding] = []

        if "WordPress" in detected or not detected:
            all_findings.extend(self.audit_wordpress())

        if "Laravel" in detected or not detected:
            all_findings.extend(self.audit_laravel())

        # Check frontend source maps
        all_findings.extend(self.audit_source_maps())

        # Check admin panels
        all_findings.extend(self.audit_admin_panels())

        return {
            "url": self.url,
            "detected_cms": detected,
            "primary_cms": fp["primary_cms"],
            "details": fp["details"],
            "findings": [f.to_dict() for f in all_findings],
            "vulnerabilities": [f.to_dict() for f in all_findings],
        }

    # Alias for API consistency
    audit_all = run_full_audit

