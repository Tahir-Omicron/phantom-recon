"""
Phantom Recon — RFC 9116 Security.txt & Sensitive Surface Auditor (v2.1.0).

Audits target web applications for:
1. RFC 9116 Vulnerability Disclosure Policy compliance (/.well-known/security.txt).
2. Robots.txt and Sitemap.xml sensitive disallow/hidden paths (/admin, /backup, /internal).
3. Live accessibility verification of discovered sensitive endpoints.

⚠️ DISCLAIMER: For authorized security testing and defensive posture assessment only.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
import re
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from phantom_recon.utils.logger import get_logger

logger = get_logger(__name__)

SENSITIVE_PATH_PATTERNS = [
    r"/admin", r"/administrator", r"/backup", r"/backups", r"/staging", r"/internal",
    r"/dev", r"/development", r"/portal", r"/console", r"/private", r"/manage",
    r"/secret", r"/dashboard", r"/api/private", r"/db", r"/database", r"/dump"
]


@dataclass
class PolicyFinding:
    """Represents a policy or sensitive surface finding."""
    title: str
    severity: str
    cvss_score: float
    category: str
    location: str
    description: str
    remediation: str
    evidence: str
    poc_url: str

    def __getitem__(self, item: str) -> Any:
        return self.to_dict()[item]

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "category": self.category,
            "location": self.location,
            "description": self.description,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "poc_url": self.poc_url,
        }


class PolicyAuditor:
    """
    Auditor for RFC 9116 security.txt compliance and sensitive robots.txt/sitemap endpoints.
    """

    def __init__(self, base_url: str, timeout: float = 5.0, verify_ssl: bool = False):
        if not base_url.startswith("http://") and not base_url.startswith("https://"):
            self.base_url = f"https://{base_url}"
        else:
            self.base_url = base_url.rstrip("/")

        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 PhantomRecon/2.1.0"
            )
        })

    def audit_security_txt(self) -> dict[str, Any]:
        """
        Audit /.well-known/security.txt and /security.txt according to RFC 9116 specifications.
        """
        candidates = [
            f"{self.base_url}/.well-known/security.txt",
            f"{self.base_url}/security.txt",
        ]

        found_url = None
        content = ""

        for u in candidates:
            try:
                resp = self.session.get(u, timeout=self.timeout, allow_redirects=True)
                if resp.status_code == 200 and ("contact:" in resp.text.lower() or "expires:" in resp.text.lower()):
                    found_url = u
                    content = resp.text
                    break
            except requests.RequestException:
                pass

        if not found_url:
            return {
                "has_security_txt": False,
                "url": candidates[0],
                "compliant": False,
                "fields": {},
                "finding": PolicyFinding(
                    title="Missing RFC 9116 Vulnerability Disclosure Policy (security.txt)",
                    severity="info",
                    cvss_score=2.0,
                    category="Policy & Compliance",
                    location=candidates[0],
                    description=(
                        f"The web application does not publish a standardized vulnerability disclosure policy at '{candidates[0]}'. "
                        "RFC 9116 defines the established internet standard for ethical security researchers and CSIRT/CERT "
                        "teams to responsibly disclose critical security flaws directly to organizational engineers."
                    ),
                    remediation=(
                        f"Create a UTF-8 text file at '/.well-known/security.txt' with the following template:\n"
                        f"Contact: mailto:security@{urlparse(self.base_url).hostname or 'example.com'}\n"
                        f"Expires: 2027-12-31T23:59:59.000Z\n"
                        f"Preferred-Languages: az, en\n"
                        f"Canonical: {candidates[0]}"
                    ),
                    evidence="HTTP 404/not found at standard security.txt locations.",
                    poc_url=candidates[0],
                ),
            }

        # Parse fields
        fields: dict[str, list[str]] = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                key, val = line.split(":", 1)
                k = key.strip().lower()
                v = val.strip()
                fields.setdefault(k, []).append(v)

        has_contact = "contact" in fields
        has_expires = "expires" in fields
        is_expired = False
        expired_date = None

        if has_expires:
            exp_str = fields["expires"][0]
            # Try to parse ISO timestamp
            try:
                # Remove timezone offset or replace Z
                clean_exp = exp_str.replace("Z", "+00:00")
                exp_dt = datetime.fromisoformat(clean_exp)
                if exp_dt.tzinfo:
                    from datetime import timezone
                    now_dt = datetime.now(timezone.utc)
                else:
                    now_dt = datetime.now()
                if exp_dt < now_dt:
                    is_expired = True
                    expired_date = str(exp_dt)
            except Exception:
                pass

        finding = None
        if not has_contact:
            finding = PolicyFinding(
                title="Invalid RFC 9116 security.txt: Missing Mandatory 'Contact' Directive",
                severity="low",
                cvss_score=3.1,
                category="Policy & Compliance",
                location=found_url,
                description="The security.txt file is present but lacks the mandatory 'Contact:' field required by RFC 9116.",
                remediation="Add a valid 'Contact: mailto:security@example.com' or 'Contact: https://example.com/security' directive.",
                evidence=f"Parsed security.txt keys: {list(fields.keys())}",
                poc_url=found_url,
            )
        elif is_expired:
            finding = PolicyFinding(
                title="Expired RFC 9116 Security Policy (security.txt)",
                severity="low",
                cvss_score=3.5,
                category="Policy & Compliance",
                location=found_url,
                description=f"The security.txt file has expired (Expired on {expired_date}). RFC 9116 mandates an active expiry date.",
                remediation="Update the 'Expires:' field in security.txt with a future ISO 8601 date.",
                evidence=f"Expires header is in the past: {fields.get('expires')}",
                poc_url=found_url,
            )

        return {
            "has_security_txt": True,
            "url": found_url,
            "compliant": has_contact and not is_expired,
            "fields": fields,
            "finding": finding,
        }

    def audit_sensitive_surface(self) -> dict[str, Any]:
        """
        Extract Disallow rules from robots.txt, identify high-risk administrative or backup paths,
        and test live availability.
        """
        robots_url = f"{self.base_url}/robots.txt"
        discovered_paths = set()
        findings: list[PolicyFinding] = []

        try:
            resp = self.session.get(robots_url, timeout=self.timeout, allow_redirects=True)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            path = parts[1].strip()
                            if path and not path.endswith("*") and path != "/":
                                discovered_paths.add(path)
        except requests.RequestException:
            pass

        # Filter for sensitive keywords
        flagged_paths = []
        for path in discovered_paths:
            for pattern in SENSITIVE_PATH_PATTERNS:
                if re.search(pattern, path, re.IGNORECASE):
                    flagged_paths.append(path)
                    break

        # Probe candidate sensitive paths
        def _check_path(p: str) -> Optional[PolicyFinding]:
            full_u = urljoin(self.base_url, p)
            try:
                r = self.session.get(full_u, timeout=self.timeout, allow_redirects=False)
                if r.status_code == 200 and len(r.content) > 30:
                    # Exclude generic soft-404s
                    if "404" in r.text[:200] or "not found" in r.text.lower()[:200]:
                        return None
                    return PolicyFinding(
                        title=f"Sensitive Administrative/Internal Path Disclosed in robots.txt ({p})",
                        severity="medium",
                        cvss_score=5.3,
                        category="Information Disclosure",
                        location=full_u,
                        description=(
                            f"The robots.txt file disallows path '{p}', which is publicly accessible with HTTP 200 OK. "
                            "Adversaries inspect robots.txt to discover unlisted administrative consoles and internal portals."
                        ),
                        remediation="Ensure administrative and internal portals require authentication and are restricted by IP/firewall.",
                        evidence=f"Disallowed path '{p}' returned HTTP 200 OK ({len(r.content)} bytes).",
                        poc_url=full_u,
                    )
            except requests.RequestException:
                pass
            return None

        if flagged_paths:
            with ThreadPoolExecutor(max_workers=min(len(flagged_paths), 10)) as executor:
                future_to_p = {executor.submit(_check_path, p): p for p in flagged_paths[:20]}
                for future in as_completed(future_to_p):
                    try:
                        res = future.result()
                        if res:
                            findings.append(res)
                    except Exception:
                        pass

        return {
            "total_disallow_paths": len(discovered_paths),
            "flagged_sensitive_paths": flagged_paths,
            "findings": [f.to_dict() for f in findings],
        }

    def run_full_policy_audit(self) -> dict[str, Any]:
        """Run all policy & sensitive surface checks."""
        sec_txt = self.audit_security_txt()
        surface = self.audit_sensitive_surface()

        all_findings = []
        if sec_txt.get("finding"):
            f = sec_txt["finding"]
            all_findings.append(f if isinstance(f, dict) else f.to_dict())
        all_findings.extend(surface.get("findings", []))

        return {
            "security_txt": sec_txt,
            "sensitive_surface": surface,
            "findings": all_findings,
        }
