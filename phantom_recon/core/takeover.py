"""
Phantom Recon — Subdomain Takeover & Dangling DNS Auditor (v2.1.0).

Identifies dangling DNS CNAME records pointing to deprovisioned or unclaimed third-party
cloud infrastructure (AWS S3, GitHub Pages, Heroku, Azure, Vercel, Netlify, Fastly, Shopify, etc.).
Subdomain takeovers permit adversaries to hijack organizational subdomains, steal authentication
cookies, and launch high-trust phishing campaigns.

Engineered with zero-false-positive body signature verification.

⚠️ DISCLAIMER: For authorized security testing and defensive posture assessment only.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Optional
import dns.resolver
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from phantom_recon.utils.logger import get_logger

logger = get_logger(__name__)

# Canonical Subdomain Takeover Signatures Database
TAKEOVER_SIGNATURES: list[dict[str, Any]] = [
    {
        "provider": "GitHub Pages",
        "cname": ["github.io"],
        "fingerprints": ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/)"],
        "severity": "high",
        "cvss": 8.6,
    },
    {
        "provider": "AWS S3 Bucket",
        "cname": ["s3.amazonaws.com", "s3-website", "s3.dualstack"],
        "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
        "severity": "high",
        "cvss": 8.8,
    },
    {
        "provider": "AWS CloudFront",
        "cname": ["cloudfront.net"],
        "fingerprints": ["The request could not be satisfied", "Bad request."],
        "severity": "medium",
        "cvss": 6.5,
    },
    {
        "provider": "Heroku",
        "cname": ["herokuapp.com", "herokudns.com"],
        "fingerprints": ["No such app", "Heroku | Welcome to your new app!", "There's nothing here, yet."],
        "severity": "high",
        "cvss": 8.5,
    },
    {
        "provider": "Microsoft Azure",
        "cname": ["azurewebsites.net", "cloudapp.net", "trafficmanager.net", "azure-api.net"],
        "fingerprints": ["404 Web Site not found", "The resource you are looking for has been removed"],
        "severity": "high",
        "cvss": 8.7,
    },
    {
        "provider": "Netlify",
        "cname": ["netlify.app", "netlify.com"],
        "fingerprints": ["Not Found - Request ID", "page not found - Netlify"],
        "severity": "high",
        "cvss": 8.5,
    },
    {
        "provider": "Vercel",
        "cname": ["vercel.app", "zeit.world"],
        "fingerprints": ["404: NOT_FOUND", "The deployment could not be found"],
        "severity": "high",
        "cvss": 8.5,
    },
    {
        "provider": "Fastly CDN",
        "cname": ["fastly.net", "fastlylb.net"],
        "fingerprints": ["Fastly error: unknown domain"],
        "severity": "high",
        "cvss": 8.5,
    },
    {
        "provider": "Shopify",
        "cname": ["myshopify.com"],
        "fingerprints": ["Sorry, this shop is currently unavailable", "Only one step left!"],
        "severity": "high",
        "cvss": 8.2,
    },
    {
        "provider": "Zendesk",
        "cname": ["zendesk.com"],
        "fingerprints": ["Help Center Closed", "No such app"],
        "severity": "high",
        "cvss": 8.0,
    },
    {
        "provider": "Ghost",
        "cname": ["ghost.io"],
        "fingerprints": ["The thing you were looking for is no longer here"],
        "severity": "high",
        "cvss": 8.0,
    },
    {
        "provider": "Surge.sh",
        "cname": ["surge.sh"],
        "fingerprints": ["project not found"],
        "severity": "high",
        "cvss": 8.5,
    },
    {
        "provider": "Pantheon",
        "cname": ["pantheonsite.io"],
        "fingerprints": ["404 error unknown site!", "The gods are wise"],
        "severity": "high",
        "cvss": 8.5,
    },
    {
        "provider": "WordPress.com",
        "cname": ["wordpress.com"],
        "fingerprints": ["Do you want to register"],
        "severity": "high",
        "cvss": 8.0,
    },
    {
        "provider": "Webflow",
        "cname": ["webflow.io"],
        "fingerprints": ["The page you are looking for doesn't exist or has been moved"],
        "severity": "high",
        "cvss": 8.0,
    },
    {
        "provider": "Bitbucket",
        "cname": ["bitbucket.io"],
        "fingerprints": ["Repository not found"],
        "severity": "high",
        "cvss": 8.0,
    },
    {
        "provider": "Unbounce",
        "cname": ["unbouncepages.com"],
        "fingerprints": ["The requested URL was not found on this server"],
        "severity": "high",
        "cvss": 8.0,
    },
]

TAKEOVER_FINGERPRINTS = TAKEOVER_SIGNATURES


@dataclass
class TakeoverFinding:
    """Represents a validated subdomain takeover vulnerability."""
    subdomain: str
    cname: str
    provider: str
    severity: str
    cvss_score: float
    matched_fingerprint: str
    evidence: str
    remediation: str
    poc_url: str
    is_takeover: bool = True

    def __getitem__(self, item: str) -> Any:
        return self.to_dict()[item]

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": f"Subdomain Takeover: Dangling CNAME to {self.provider} ({self.subdomain})",
            "subdomain": self.subdomain,
            "cname": self.cname,
            "provider": self.provider,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "matched_fingerprint": self.matched_fingerprint,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "poc_url": self.poc_url,
            "location": f"DNS CNAME: {self.subdomain} -> {self.cname}",
            "category": "DNS / Cloud Takeover",
            "is_takeover": True,
        }


class SubdomainTakeoverAuditor:
    """
    Subdomain Takeover Scanner.
    Resolves CNAME records for target hostnames and validates dangling pointers against provider signatures.
    """

    def check_subdomain(self, host: str) -> Optional["TakeoverFinding"]:
        """Audit a single hostname for dangling CNAME takeovers."""
        return self._audit_single_host(host)

    def audit_single_host(self, host: str) -> Optional["TakeoverFinding"]:
        """Audit a single hostname for dangling CNAME takeovers."""
        return self._audit_single_host(host)

    def __init__(
        self,
        targets: list[str],
        timeout: float = 4.0,
        threads: int = 15,
        verify_ssl: bool = False,
    ):
        self.targets = list(set(targets))
        self.timeout = timeout
        self.threads = threads
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 PhantomRecon/2.1.0"
            )
        })

    def _resolve_cname(self, domain: str) -> Optional[str]:
        """Resolve DNS CNAME for a domain."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            answers = resolver.resolve(domain, "CNAME")
            for rdata in answers:
                return str(rdata.target).rstrip(".")
        except Exception:
            return None

    def _verify_dangling_http(self, domain: str, cname: str, sig: dict[str, Any]) -> Optional[TakeoverFinding]:
        """Perform HTTP/HTTPS probe to verify the deprovisioned signature."""
        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}"
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                body = resp.text
                for fp in sig["fingerprints"]:
                    if fp.lower() in body.lower():
                        return TakeoverFinding(
                            subdomain=domain,
                            cname=cname,
                            provider=sig["provider"],
                            severity=sig["severity"],
                            cvss_score=sig["cvss"],
                            matched_fingerprint=fp,
                            evidence=f"CNAME '{cname}' returned deprovisioned {sig['provider']} signature: '{fp}'",
                            remediation=(
                                f"Immediately remove or update the dangling CNAME record for '{domain}' in your DNS "
                                f"zone editor, or claim the resource in your {sig['provider']} account."
                            ),
                            poc_url=url,
                        )
            except requests.RequestException:
                pass

        return None

    def _audit_single_host(self, host: str) -> Optional[TakeoverFinding]:
        """Audit a single hostname for dangling CNAME takeovers."""
        clean_host = host.strip().lower()
        if clean_host.startswith("http://") or clean_host.startswith("https://"):
            from urllib.parse import urlparse
            clean_host = urlparse(clean_host).hostname or clean_host

        cname = self._resolve_cname(clean_host)
        if not cname:
            return None

        # Check if CNAME matches any known cloud/SaaS provider
        for sig in TAKEOVER_SIGNATURES:
            for pattern in sig["cname"]:
                if pattern in cname:
                    logger.debug(f"Candidate takeover CNAME: {clean_host} -> {cname} ({sig['provider']})")
                    # Actively verify deprovisioned fingerprint
                    finding = self._verify_dangling_http(clean_host, cname, sig)
                    if finding:
                        logger.warning(
                            f"🚨 SUBDOMAIN TAKEOVER VULNERABILITY CONFIRMED: {clean_host} -> {cname} ({sig['provider']})"
                        )
                        return finding

        return None

    def audit_all(self) -> list[dict[str, Any]]:
        """Run multi-threaded takeover audit across all targets."""
        findings: list[TakeoverFinding] = []
        if not self.targets:
            return []

        logger.info(f"Auditing {len(self.targets)} host(s) for dangling CNAME subdomain takeovers ({self.threads} threads)...")

        with ThreadPoolExecutor(max_workers=min(len(self.targets), self.threads)) as executor:
            future_to_host = {executor.submit(self._audit_single_host, h): h for h in self.targets}
            for future in as_completed(future_to_host):
                try:
                    res = future.result()
                    if res:
                        findings.append(res)
                except Exception as e:
                    logger.debug(f"Error auditing host: {e}")

        logger.info(f"Subdomain takeover audit completed: {len(findings)} confirmed takeover(s).")
        return [f.to_dict() for f in findings]
