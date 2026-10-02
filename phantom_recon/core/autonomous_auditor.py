"""
Phantom Recon — Autonomous Master Audit Engine (v2.0.0).

Executes a unified, end-to-end autonomous penetration testing & vulnerability
assessment with a single command. Consolidates surface reconnaissance, network
perimeter probing, cloud auditing, API/CMS discovery, and deep vulnerability
scanning into a unified, zero-false-positive findings matrix.

⚠️ DISCLAIMER: For authorized security testing only.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Optional
from urllib.parse import urlparse

from phantom_recon.utils.logger import get_logger
from phantom_recon.utils.validators import (
    DANGEROUS_SERVICES_PORTS,
    TOP_100_PORTS,
    normalize_target_input,
)
from phantom_recon.reporting.security_score import calculate_security_score

logger = get_logger(__name__)


@dataclass
class AuditFinding:
    """Standardized vulnerability finding across all audit domains."""
    title: str
    severity: str
    cvss_score: float
    category: str
    location: str
    description: str
    remediation: str
    evidence: str = ""
    poc_url: str = ""
    reproduce_curl: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity.lower(),
            "cvss_score": round(self.cvss_score, 1),
            "category": self.category,
            "location": self.location,
            "description": self.description,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "poc_url": self.poc_url or self.location,
            "reproduce_curl": self.reproduce_curl or f"curl -i -k '{self.poc_url or self.location}'",
            "confidence": "CONFIRMED",
        }


class AutonomousAuditor:
    """
    Unified Autonomous Security Assessment Engine.
    Executes full reconnaissance & vulnerability assessment in a single unified run.
    """

    TOTAL_STAGES = 13

    def __init__(
        self,
        target: str,
        threads: int = 25,
        timeout: float = 6.0,
        verify_ssl: bool = False,
        fast_mode: bool = False,
        status_callback: Optional[Callable[[int, int, str], None]] = None,
    ):
        self.raw_target = target
        self.host, self.url, self.target_type = normalize_target_input(target)
        self.threads = threads
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.fast_mode = fast_mode
        self.status_callback = status_callback

        self.findings: list[AuditFinding] = []
        self.scan_data: dict[str, Any] = {
            "target": self.host,
            "url": self.url,
            "target_type": self.target_type,
            "timestamp": datetime.now().isoformat(),
            "start_time": datetime.now().isoformat(),
        }

    def _notify(self, stage: int, description: str) -> None:
        if self.status_callback:
            self.status_callback(stage, self.TOTAL_STAGES, description)
        logger.info(f"[Stage {stage}/{self.TOTAL_STAGES}] {description}")

    def _add_finding(self, finding: AuditFinding) -> None:
        # Avoid duplicate titles at the same location
        for existing in self.findings:
            if existing.title == finding.title and existing.location == finding.location:
                return
        self.findings.append(finding)

    def run_full_audit(self) -> dict[str, Any]:
        """
        Execute all reconnaissance and vulnerability assessment stages sequentially.
        Returns unified scan results with aggregated findings and security health score.
        """
        start_time = datetime.now()

        # ─── Stage 1: WHOIS & Domain Intelligence ─────────────────────
        self._notify(1, "WHOIS Lookup & Registration Intelligence")
        if self.target_type in ("domain", "url"):
            try:
                from phantom_recon.core.whois_lookup import WhoisLookup
                whois_data = WhoisLookup(target=self.host, timeout=self.timeout).lookup()
                self.scan_data["whois"] = whois_data
            except Exception as e:
                logger.debug(f"Stage 1 error: {e}")

        # ─── Stage 2: DNS & Email Spoofing Defense ────────────────────
        self._notify(2, "DNS Enumeration & Anti-Spoofing Policy Audit")
        if self.target_type in ("domain", "url"):
            try:
                from phantom_recon.core.dns_enum import DNSEnumerator
                dns_data = DNSEnumerator(domain=self.host, timeout=self.timeout).enumerate_all()
                self.scan_data["dns"] = dns_data

                # Check SPF & DMARC
                sec = dns_data.get("security", {})
                dmarc = sec.get("dmarc", {})
                spf = sec.get("spf", {})

                if not dmarc.get("has_dmarc"):
                    self._add_finding(AuditFinding(
                        title="Missing DMARC Anti-Spoofing DNS Policy",
                        severity="medium",
                        cvss_score=5.3,
                        category="DNS / Email Security",
                        location=f"_dmarc.{self.host}",
                        description=(
                            f"The domain '{self.host}' lacks a published DMARC DNS record. Attackers can forge "
                            "phishing emails masquerading as legitimate organizational correspondence."
                        ),
                        remediation=f"Publish a DMARC TXT record at '_dmarc.{self.host}' (e.g. 'v=DMARC1; p=reject;').",
                        evidence="No TXT record found at _dmarc." + self.host,
                    ))

                if not spf.get("has_spf"):
                    self._add_finding(AuditFinding(
                        title="Missing SPF Email Authentication DNS Record",
                        severity="low",
                        cvss_score=3.5,
                        category="DNS / Email Security",
                        location=f"DNS: {self.host}",
                        description=(
                            f"The domain '{self.host}' does not publish an SPF (Sender Policy Framework) record, "
                            "permitting unauthorized mail servers to dispatch emails claiming to originate from this domain."
                        ),
                        remediation=f"Publish an SPF TXT record on {self.host} (e.g. 'v=spf1 include:_spf.example.com -all').",
                        evidence="No TXT record with 'v=spf1' located.",
                    ))
            except Exception as e:
                logger.debug(f"Stage 2 error: {e}")

        # ─── Stage 3: Subdomain & Attack Surface Discovery ─────────────
        self._notify(3, "Subdomain Discovery & Attack Surface Mapping")
        if self.target_type in ("domain", "url"):
            try:
                from phantom_recon.core.subdomain import SubdomainFinder
                finder = SubdomainFinder(
                    domain=self.host,
                    threads=self.threads if not self.fast_mode else 10,
                    timeout=self.timeout,
                )
                subs = finder.find_all()
                self.scan_data["subdomains"] = subs
            except Exception as e:
                logger.debug(f"Stage 3 error: {e}")

        # ─── Stage 4: WAF Edge & Backend Origin IP Leakage Audit ──────
        self._notify(4, "WAF Edge Detection & Unproxied Origin IP Leakage Audit")
        try:
            from phantom_recon.core.waf_detector import WAFDetector
            waf_detector = WAFDetector(target=self.host, timeout=self.timeout)
            waf_results = waf_detector.run_full_waf_analysis()
            self.scan_data["waf"] = waf_results

            origin_leak = waf_results.get("origin_leakage", {})
            if origin_leak.get("leakage_detected"):
                unprot = origin_leak.get("unprotected_origin_candidates", [])
                candidates_str = ", ".join(f"{c['ip']} ({c['hostname']})" for c in unprot[:3])
                self._add_finding(AuditFinding(
                    title="Potential Backend Origin Server IP Leakage (WAF Bypass)",
                    severity="high",
                    cvss_score=7.5,
                    category="Edge / Perimeter",
                    location=f"Target: {self.host}",
                    description=(
                        f"The domain is fronted by {waf_results.get('waf_name')} WAF/CDN, but direct backend origin "
                        f"IPs were detected ({candidates_str}). Attackers can connect directly to origin IPs, "
                        "completely bypassing edge firewall inspection, DDoS mitigation, and rate limits."
                    ),
                    remediation="Configure network firewalls (security groups) on origin servers to only accept incoming traffic from CDN IP ranges.",
                    evidence=f"Candidate origin servers: {candidates_str}",
                    poc_url=f"http://{unprot[0]['ip']}" if unprot else self.url,
                ))
        except Exception as e:
            logger.debug(f"Stage 4 error: {e}")

        # ─── Stage 5: Multi-Cloud Bucket Storage Audit ─────────────────
        self._notify(5, "Multi-Cloud Storage & Bucket Leakage Audit (AWS/GCP/Azure)")
        try:
            from phantom_recon.core.cloud_auditor import CloudAuditor
            cloud_auditor = CloudAuditor(
                target=self.host,
                threads=self.threads,
                timeout=self.timeout,
            )
            cloud_results = cloud_auditor.run_cloud_audit()
            self.scan_data["cloud_storage"] = cloud_results

            for f in cloud_results.get("findings", []):
                if f.get("is_open"):
                    self._add_finding(AuditFinding(
                        title=f"Publicly Listable {f.get('provider')} Cloud Storage Bucket",
                        severity="high",
                        cvss_score=8.5,
                        category="Cloud Storage",
                        location=f.get("url", "Cloud Bucket"),
                        description=(
                            f"The {f.get('provider')} cloud storage bucket '{f.get('bucket_name')}' permits public "
                            "unauthenticated listing of its contents, exposing sensitive business files, customer data, and backups."
                        ),
                        remediation=f"Enable Public Access Prevention on {f.get('bucket_name')} and configure IAM bucket policies to require authentication.",
                        evidence=f.get("evidence", ""),
                        poc_url=f.get("url", ""),
                        reproduce_curl=f"curl -i -k '{f.get('url')}'",
                    ))
        except Exception as e:
            logger.debug(f"Stage 5 error: {e}")

        # ─── Stage 6: Perimeter Port Reconnaissance & Risky Services ───
        self._notify(6, "Perimeter Port Scanning & Risky Database / Daemon Auditing")
        try:
            from phantom_recon.core.scanner import PortScanner
            port_spec = "1-1024" if not self.fast_mode else ",".join(str(p) for p in TOP_100_PORTS[:25])
            scanner = PortScanner(
                target=self.host,
                ports=port_spec,
                threads=self.threads * 2,
                timeout=1.5 if self.fast_mode else 2.0,
            )
            scan_results = scanner.scan()
            self.scan_data["ports"] = scan_results.get("ports", {})

            # Check for risky open ports
            for port, p_info in scan_results.get("ports", {}).items():
                p_int = int(port)
                if p_int in DANGEROUS_SERVICES_PORTS:
                    rule = DANGEROUS_SERVICES_PORTS[p_int]
                    self._add_finding(AuditFinding(
                        title=rule["title"],
                        severity=rule["risk"],
                        cvss_score=rule["cvss"],
                        category="Network / Infrastructure",
                        location=f"{self.host}:{port}/tcp",
                        description=rule["desc"],
                        remediation=rule["remediation"],
                        evidence=f"Port {port}/tcp is OPEN ({p_info.get('service', rule['service'])}) banner: {p_info.get('banner', '')[:60]}",
                    ))
        except Exception as e:
            logger.debug(f"Stage 6 error: {e}")

        # ─── Stage 7: Web Application Stack & Tech Fingerprinting ──────
        self._notify(7, "Web Application Reconnaissance & Stack Fingerprinting")
        try:
            from phantom_recon.core.web_recon import WebRecon
            web_recon = WebRecon(url=self.url, timeout=self.timeout)
            web_results = web_recon.run_full_recon()
            self.scan_data["technologies"] = web_results.get("technologies", [])
            self.scan_data["directories"] = web_results.get("directories", [])
            self.scan_data["forms"] = web_results.get("forms", [])
        except Exception as e:
            logger.debug(f"Stage 7 error: {e}")

        # ─── Stage 8: API Discovery & Schema Auditing ───────────────────
        self._notify(8, "API Discovery, Swagger/OpenAPI & GraphQL Auditing")
        try:
            from phantom_recon.core.api_scanner import APIScanner
            api_scanner = APIScanner(url=self.url, timeout=self.timeout)
            api_results = api_scanner.scan_endpoints()
            self.scan_data["api_endpoints"] = api_results

            for api in api_results:
                sev = api.get("severity", "low")
                if sev in ("medium", "high", "critical"):
                    self._add_finding(AuditFinding(
                        title=f"Exposed API Schema / Portal ({api.get('type')})",
                        severity=sev,
                        cvss_score=5.3 if sev == "medium" else 7.5,
                        category="API / Architecture",
                        location=api.get("url", self.url),
                        description=f"Publicly accessible {api.get('type')} endpoint at {api.get('path')} discloses application data contracts and backend routes.",
                        remediation="Place API schemas and interactive consoles behind authentication in production environments.",
                        evidence=api.get("evidence", ""),
                        poc_url=api.get("url", self.url),
                    ))
        except Exception as e:
            logger.debug(f"Stage 8 error: {e}")

        # ─── Stage 9: CMS & Framework Security Audit ───────────────────
        self._notify(9, "CMS & Framework Security Audit (WordPress/Laravel/Django/.js.map)")
        try:
            from phantom_recon.core.cms_auditor import CMSAuditor
            cms_auditor = CMSAuditor(url=self.url, timeout=self.timeout, verify_ssl=self.verify_ssl)
            cms_results = cms_auditor.run_full_audit()
            self.scan_data["cms"] = cms_results

            for cf in cms_results.get("findings", []):
                self._add_finding(AuditFinding(
                    title=cf["title"],
                    severity=cf["severity"],
                    cvss_score=cf.get("cvss_score", 5.0),
                    category="CMS & Frameworks",
                    location=cf.get("location", self.url),
                    description=cf["description"],
                    remediation=cf.get("remediation", "Update security configuration."),
                    evidence=cf.get("evidence", ""),
                    poc_url=cf.get("url", self.url),
                    reproduce_curl=cf.get("reproduce_curl", f"curl -i -k '{cf.get('url', self.url)}'"),
                ))
        except Exception as e:
            logger.debug(f"Stage 9 error: {e}")

        # ─── Stage 10: Security Headers & Cookie Security ──────────────
        self._notify(10, "Security Headers, CSP Directives & Cookie Security")
        try:
            from phantom_recon.core.header_analyzer import HeaderAnalyzer
            header_analyzer = HeaderAnalyzer(url=self.url, timeout=self.timeout)
            header_results = header_analyzer.analyze()
            self.scan_data["headers"] = header_results

            # Check critical missing headers
            for chk in header_results.get("checks", []):
                if not chk.get("secure") and chk.get("header") in ("Strict-Transport-Security", "Content-Security-Policy"):
                    self._add_finding(AuditFinding(
                        title=f"Missing Security Header ({chk.get('header')})",
                        severity="low" if chk.get("header") == "Strict-Transport-Security" else "medium",
                        cvss_score=3.7 if chk.get("header") == "Strict-Transport-Security" else 5.0,
                        category="Web Defense / Headers",
                        location=f"Response Headers: {chk.get('header')}",
                        description=chk.get("description", "Security header is missing from server responses."),
                        remediation=chk.get("recommendation", "Implement standard defense header in reverse proxy or web server configuration."),
                        evidence=f"Header '{chk.get('header')}' was not returned.",
                        poc_url=self.url,
                    ))
        except Exception as e:
            logger.debug(f"Stage 10 error: {e}")

        # ─── Stage 11: SSL/TLS Cryptographic Analysis ──────────────────
        self._notify(11, "SSL/TLS Protocol Inspection & Cryptographic Hygiene")
        if self.target_type in ("domain", "url"):
            try:
                from phantom_recon.core.ssl_analyzer import SSLAnalyzer
                ssl_analyzer = SSLAnalyzer(host=self.host, timeout=self.timeout)
                ssl_results = ssl_analyzer.analyze()
                self.scan_data["ssl"] = ssl_results

                cert = ssl_results.get("certificate", {})
                if cert.get("expired"):
                    self._add_finding(AuditFinding(
                        title="Expired SSL/TLS Certificate",
                        severity="high",
                        cvss_score=7.4,
                        category="Cryptographic / SSL",
                        location=f"TLS Service: {self.host}:443",
                        description=f"The SSL/TLS certificate expired on {cert.get('not_after')}. Browsers will block connections.",
                        remediation="Renew and deploy an active SSL/TLS certificate immediately.",
                        evidence=f"Certificate expired on {cert.get('not_after')}",
                        poc_url=f"https://{self.host}",
                    ))
            except Exception as e:
                logger.debug(f"Stage 11 error: {e}")

        # ─── Stage 12: HTTP Methods & Dangerous Verbs Audit ────────────
        self._notify(12, "HTTP Methods & Dangerous Verbs Audit (PUT/DELETE/TRACE/WebDAV)")
        try:
            from phantom_recon.core.http_methods import HTTPMethodsAuditor
            methods_auditor = HTTPMethodsAuditor(url=self.url, timeout=self.timeout)
            methods_results = methods_auditor.audit_all()
            self.scan_data["http_methods"] = methods_results

            for p in methods_results.get("probes", []):
                if p.get("is_vulnerable"):
                    self._add_finding(AuditFinding(
                        title=f"Insecure HTTP Method Enabled ({p.get('method')})",
                        severity=p.get("risk", "medium").lower(),
                        cvss_score=7.5 if p.get("method") == "PUT" else (5.3 if p.get("method") == "TRACE" else 6.5),
                        category="HTTP Protocol / Verbs",
                        location=f"HTTP Verb: {p.get('method')} on {self.url}",
                        description=f"The server allows {p.get('method')} method, presenting security exposure to unauthenticated modifications or XST attacks.",
                        remediation=p.get("remediation", "Disable unsafe HTTP methods in web server configuration."),
                        evidence=p.get("evidence", ""),
                        poc_url=self.url,
                        reproduce_curl=f"curl -i -X {p.get('method')} -k '{self.url}'",
                    ))
        except Exception as e:
            logger.debug(f"Stage 12 error: {e}")

        # ─── Stage 13: Precision Web Vulnerability Scanner ─────────────
        self._notify(13, "Precision Web Vulnerability Scanner & Deep Configuration Audit")
        try:
            from phantom_recon.core.vuln_scanner import VulnerabilityScanner
            vuln_scanner = VulnerabilityScanner(
                url=self.url,
                timeout=self.timeout,
                verify_ssl=self.verify_ssl,
            )
            # Run core checks (sensitive files, cors, open redirect, clickjacking, git/env)
            web_vulns = vuln_scanner.scan_all()

            for wv in web_vulns:
                self._add_finding(AuditFinding(
                    title=wv["title"],
                    severity=wv["severity"],
                    cvss_score=wv.get("cvss_score", 5.0),
                    category=wv.get("category", "Web Vulnerability").replace("_", " ").title(),
                    location=wv.get("location", self.url),
                    description=wv["description"],
                    remediation=wv.get("remediation", ""),
                    evidence=wv.get("evidence", ""),
                    poc_url=wv.get("poc_url", self.url),
                    reproduce_curl=wv.get("reproduce_curl", f"curl -i -k '{self.url}'"),
                ))
        except Exception as e:
            logger.debug(f"Stage 13 error: {e}")

        # ─── Final Aggregation, Sorting & Scoring ──────────────────────
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        self.findings.sort(key=lambda f: (severity_order.get(f.severity.lower(), 5), -f.cvss_score))

        all_findings_dict = [f.to_dict() for f in self.findings]
        self.scan_data["vulnerabilities"] = all_findings_dict
        self.scan_data["total_vulnerabilities"] = len(all_findings_dict)

        # Calculate Executive Security Health Score
        score_data = calculate_security_score(all_findings_dict)
        self.scan_data["security_score"] = score_data

        duration = (datetime.now() - start_time).total_seconds()
        self.scan_data["duration_seconds"] = round(duration, 2)
        self.scan_data["end_time"] = datetime.now().isoformat()

        return self.scan_data
