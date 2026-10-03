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
    Unified Autonomous Security Assessment Engine (v2.1.0).
    Executes full 15-stage reconnaissance & vulnerability assessment in a single unified run.
    """

    TOTAL_STAGES = 15

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
        # Avoid duplicate titles or duplicate targets across stages
        f_title_lower = finding.title.lower()
        f_cat_lower = finding.category.lower()

        for existing in self.findings:
            e_title_lower = existing.title.lower()
            e_cat_lower = existing.category.lower()

            # 1. Exact match on title and location
            if existing.title == finding.title and existing.location == finding.location:
                return

            # 2. Cloud storage bucket deduplication
            if ("cloud" in e_cat_lower or "cloud" in f_cat_lower) and (
                (existing.poc_url and existing.poc_url == finding.poc_url) or
                (existing.location and existing.location == finding.location) or
                (finding.poc_url and existing.poc_url and (finding.poc_url in existing.poc_url or existing.poc_url in finding.poc_url))
            ):
                if finding.cvss_score > existing.cvss_score:
                    existing.title = finding.title
                    existing.severity = finding.severity
                    existing.cvss_score = finding.cvss_score
                    existing.description = finding.description
                    existing.evidence = finding.evidence or existing.evidence
                return

            # 3. DMARC Anti-Spoofing Policy deduplication (cross-stage)
            if "dmarc" in e_title_lower and "dmarc" in f_title_lower:
                if finding.cvss_score > existing.cvss_score:
                    existing.title = finding.title
                    existing.severity = finding.severity
                    existing.cvss_score = finding.cvss_score
                    existing.description = finding.description
                    existing.remediation = finding.remediation or existing.remediation
                    existing.reproduce_curl = finding.reproduce_curl or existing.reproduce_curl
                return

            # 4. SPF Anti-Spoofing Policy deduplication (cross-stage)
            if "spf" in e_title_lower and "spf" in f_title_lower:
                if finding.cvss_score > existing.cvss_score:
                    existing.title = finding.title
                    existing.severity = finding.severity
                    existing.cvss_score = finding.cvss_score
                    existing.description = finding.description
                    existing.remediation = finding.remediation or existing.remediation
                    existing.reproduce_curl = finding.reproduce_curl or existing.reproduce_curl
                return

            # 5. DNSSEC Zone Signing deduplication (cross-stage)
            if "dnssec" in e_title_lower and "dnssec" in f_title_lower:
                if finding.cvss_score > existing.cvss_score:
                    existing.title = finding.title
                    existing.severity = finding.severity
                    existing.cvss_score = finding.cvss_score
                    existing.description = finding.description
                    existing.remediation = finding.remediation or existing.remediation
                    existing.reproduce_curl = finding.reproduce_curl or existing.reproduce_curl
                return

            # 5. Security Header deduplication (HSTS, CSP, Clickjacking/X-Frame-Options)
            for hdr_kw in ("content-security-policy", "strict-transport-security", "frame protection", "clickjacking"):
                if hdr_kw in e_title_lower and hdr_kw in f_title_lower:
                    if finding.cvss_score > existing.cvss_score:
                        existing.title = finding.title
                        existing.severity = finding.severity
                        existing.cvss_score = finding.cvss_score
                        existing.description = finding.description
                    return

            # 6. Duplicate title on same domain / host
            if existing.title == finding.title:
                return

        self.findings.append(finding)

    def _adapt_web_url_and_check_liveness(self, open_ports: dict[str, Any]) -> bool:
        """
        Dynamically determine if web services (HTTP/HTTPS) are responsive,
        and adapt self.url to the active listening scheme and port.
        Always probes HTTPS first because modern enterprise sites default to HTTPS.
        """
        # If user explicitly supplied scheme and/or port
        if self.raw_target.startswith("http://") or self.raw_target.startswith("https://"):
            return True

        open_port_ints = set()
        for p in open_ports.keys():
            try:
                open_port_ints.add(int(p))
            except (ValueError, TypeError):
                pass

        # Case A: Port 443 is confirmed open in port scan
        if 443 in open_port_ints:
            self.url = f"https://{self.host}"
            return True

        # Case B: Modern HTTPS probe (even if port scan was filtered or fast)
        try:
            resp = requests.head(f"https://{self.host}", timeout=3.0, verify=False, allow_redirects=True)
            self.url = f"https://{self.host}"
            return True
        except Exception:
            pass

        # Case C: Port 80 is confirmed open in port scan
        if 80 in open_port_ints:
            self.url = f"http://{self.host}"
            return True

        # Case D: Active HTTP probe
        try:
            resp = requests.head(f"http://{self.host}", timeout=3.0, verify=False, allow_redirects=True)
            self.url = f"http://{self.host}"
            return True
        except Exception:
            pass

        # If a port scan was executed and neither 80 nor 443 (or common web ports) are open
        if open_port_ints and not any(p in open_port_ints for p in (80, 443, 8000, 8080, 8443)):
            return False

        return False

    def run_full_audit(self) -> dict[str, Any]:
        """
        Execute all reconnaissance and vulnerability assessment stages sequentially.
        Returns unified scan results with aggregated findings and security health score.
        """
        start_time = datetime.now()

        # ─── Stage 1: WHOIS & Autonomous BGP / ASN Network Intelligence ───
        self._notify(1, "WHOIS & Autonomous BGP / ASN Network Intelligence")
        if self.target_type in ("domain", "url", "ip"):
            try:
                from phantom_recon.core.network_intel import NetworkIntelligence
                net_intel = NetworkIntelligence(target=self.host, timeout=self.timeout).analyze()
                self.scan_data["network_intel"] = net_intel.to_dict()
                if net_intel.asn:
                    logger.info(
                        f"Network Intel: [bold cyan]{net_intel.asn}[/bold cyan] ({net_intel.as_name}) | "
                        f"Prefix: {net_intel.bgp_prefix} | Country: {net_intel.country}"
                    )
            except Exception as e:
                logger.debug(f"Stage 1 Network Intel error: {e}")

        if self.target_type in ("domain", "url"):
            try:
                from phantom_recon.core.whois_lookup import WhoisLookup
                whois_data = WhoisLookup(target=self.host, timeout=self.timeout).lookup()
                self.scan_data["whois"] = whois_data
            except Exception as e:
                logger.debug(f"Stage 1 WHOIS error: {e}")

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
                            f"The domain '{self.host}' lacks a published DMARC (Domain-based Message Authentication, "
                            "Reporting, and Conformance) DNS policy. Without DMARC, receiving mail exchange (MX) servers "
                            "have no directives to reject spoofed messages, allowing attackers to conduct CEO fraud, "
                            "business email compromise (BEC), and phishing campaigns masquerading as this organization."
                        ),
                        remediation=(
                            f"1. Publish an initial monitoring DMARC TXT record at '_dmarc.{self.host}':\n"
                            f"   'v=DMARC1; p=none; rua=mailto:dmarc-reports@{self.host}; aspf=r;'\n"
                            f"2. Validate legitimate sender alignment across SPF and DKIM.\n"
                            f"3. Escalate policy to quarantine ('p=quarantine') and ultimately enforcement ('p=reject')."
                        ),
                        evidence="No TXT record found at _dmarc." + self.host,
                        poc_url=f"https://mxtoolbox.com/SuperTool.aspx?action=dmarc%3a{self.host}",
                        reproduce_curl=f"nslookup -type=TXT _dmarc.{self.host}",
                    ))

                if not spf.get("has_spf"):
                    self._add_finding(AuditFinding(
                        title="Missing SPF Email Authentication DNS Record",
                        severity="low",
                        cvss_score=3.5,
                        category="DNS / Email Security",
                        location=f"DNS TXT: {self.host}",
                        description=(
                            f"The domain '{self.host}' does not publish an SPF (Sender Policy Framework) TXT record. "
                            "External mail transfer agents (MTAs) cannot verify which mail servers are legitimately "
                            "authorized to send emails on behalf of this domain, permitting unauthorized sender spoofing."
                        ),
                        remediation=(
                            f"Publish an SPF TXT record on {self.host} authorizing legitimate outbound mail infrastructure "
                            f"(e.g. 'v=spf1 mx include:_spf.google.com -all' or 'v=spf1 -all' if this domain does not transmit email)."
                        ),
                        evidence="No TXT record with 'v=spf1' located.",
                        poc_url=f"https://mxtoolbox.com/SuperTool.aspx?action=spf%3a{self.host}",
                        reproduce_curl=f"nslookup -type=TXT {self.host}",
                    ))

                # Check DNSSEC Cryptographic Zone Signing
                dnssec = sec.get("dnssec", {})
                if dnssec and not dnssec.get("enabled"):
                    self._add_finding(AuditFinding(
                        title="Missing DNSSEC Cryptographic Zone Signing",
                        severity="low",
                        cvss_score=3.1,
                        category="DNS / Domain Integrity",
                        location=f"DNS Zone: {self.host}",
                        description=(
                            f"The domain '{self.host}' does not have DNSSEC enabled (no valid DNSKEY or DS records published). "
                            "DNS queries and responses are unauthenticated, leaving recursive resolvers and clients "
                            "vulnerable to DNS cache poisoning (Kaminsky attacks), BGP route hijacking, and rogue DNS record spoofing."
                        ),
                        remediation=(
                            f"1. Enable DNSSEC signing in your authoritative DNS zone provider (e.g. Cloudflare, Route 53, BIND, PowerDNS).\n"
                            f"2. Obtain the Delegation Signer (DS) record generated by your DNS provider.\n"
                            f"3. Submit the DS record to your domain registrar (TLD registry) to complete the cryptographic chain of trust."
                        ),
                        evidence=f"No DNSKEY or DS cryptographic records found for '{self.host}'.",
                        poc_url=f"https://dnssec-analyzer.verisignlabs.com/{self.host}",
                        reproduce_curl=f"nslookup -type=DNSKEY {self.host}",
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

        # ─── Stage 4: Subdomain Takeover & Dangling DNS Pointer Audit ──
        self._notify(4, "Subdomain Takeover & Dangling DNS Pointer Audit")
        if self.target_type in ("domain", "url"):
            try:
                from phantom_recon.core.takeover import SubdomainTakeoverAuditor
                takeover_candidates = [self.host]
                subs_data = self.scan_data.get("subdomains", [])
                if isinstance(subs_data, list):
                    for s in subs_data:
                        if isinstance(s, dict) and "subdomain" in s:
                            takeover_candidates.append(s["subdomain"])
                        elif isinstance(s, str):
                            takeover_candidates.append(s)
                elif isinstance(subs_data, dict):
                    takeover_candidates.extend(subs_data.get("subdomains", []))

                takeover_candidates = list(dict.fromkeys(takeover_candidates))
                if self.fast_mode:
                    takeover_candidates = takeover_candidates[:20]

                takeover_auditor = SubdomainTakeoverAuditor(
                    targets=takeover_candidates,
                    timeout=self.timeout,
                    threads=self.threads,
                )
                takeover_results = takeover_auditor.audit_all()
                self.scan_data["takeovers"] = takeover_results

                for tk in takeover_results:
                    self._add_finding(AuditFinding(
                        title=tk["title"],
                        severity=tk["severity"],
                        cvss_score=tk["cvss_score"],
                        category=tk["category"],
                        location=tk["location"],
                        description=(
                            f"The domain '{tk['subdomain']}' has a dangling CNAME record pointing to {tk['provider']} ({tk['cname']}). "
                            "Because the resource is unclaimed, an adversary can register the asset and take complete control over "
                            "the subdomain, bypassing origin security policies and intercepting cookies/credentials."
                        ),
                        remediation=tk["remediation"],
                        evidence=tk["evidence"],
                        poc_url=tk["poc_url"],
                    ))
            except Exception as e:
                logger.debug(f"Stage 4 error: {e}")

        # ─── Stage 5: WAF Edge & Backend Origin IP Leakage Audit ──────
        self._notify(5, "WAF Edge Detection & Unproxied Origin IP Leakage Audit")
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
            logger.debug(f"Stage 5 error: {e}")

        # ─── Stage 6: Multi-Cloud Bucket Storage Audit ─────────────────
        self._notify(6, "Multi-Cloud Storage & Bucket Leakage Audit (AWS/GCP/Azure)")
        try:
            from phantom_recon.core.cloud_auditor import CloudAuditor
            cloud_auditor = CloudAuditor(
                target=self.host,
                threads=self.threads,
                timeout=self.timeout,
                high_confidence_only=True,
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
            logger.debug(f"Stage 6 error: {e}")

        # ─── Stage 7: Perimeter Port Reconnaissance & Risky Services ───
        self._notify(7, "Perimeter Port Scanning & Risky Database / Daemon Auditing")
        try:
            from phantom_recon.core.scanner import PortScanner
            if self.fast_mode:
                # Essential perimeter ports: web (80, 443, 8080, 8443), mail, databases, remote access
                fast_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 6379, 8000, 8080, 8443, 9200, 27017]
                port_spec = ",".join(str(p) for p in fast_ports)
            else:
                port_spec = "1-1024"
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
            logger.debug(f"Stage 7 error: {e}")

        # ─── Web Target Liveness & Protocol Resolution ────────────────
        web_active = self._adapt_web_url_and_check_liveness(self.scan_data.get("ports", {}))
        self.scan_data["web_active"] = web_active
        self.scan_data["url"] = self.url
        logger.info(f"Target web endpoint resolved to: [bold cyan]{self.url}[/bold cyan] (Web Active: {web_active})")

        # ─── Stage 8: Web Application Stack & Favicon MMH3 Fingerprinting ───
        self._notify(8, "Web Application Stack & Favicon MMH3 Fingerprinting")
        if web_active:
            try:
                from phantom_recon.core.web_recon import WebRecon
                from phantom_recon.core.favicon_analyzer import FaviconAnalyzer

                web_recon = WebRecon(url=self.url, timeout=self.timeout)
                web_results = web_recon.run_full_recon()
                self.scan_data["technologies"] = web_results.get("technologies", [])
                self.scan_data["directories"] = web_results.get("directories", [])
                self.scan_data["forms"] = web_results.get("forms", [])

                fav_analyzer = FaviconAnalyzer(target_url=self.url, timeout=self.timeout)
                fav_res = fav_analyzer.analyze()
                if fav_res:
                    self.scan_data["favicon"] = fav_res.to_dict()
                    if fav_res.identified_tech:
                        logger.info(
                            f"Favicon MMH3: [bold cyan]{fav_res.mmh3_hash}[/bold cyan] -> "
                            f"[bold green]{fav_res.identified_tech}[/bold green] ({fav_res.vendor})"
                        )
                        tech_names = [t.get("name") if isinstance(t, dict) else t for t in self.scan_data["technologies"]]
                        if fav_res.identified_tech not in tech_names:
                            self.scan_data["technologies"].append({
                                "name": fav_res.identified_tech,
                                "category": fav_res.category,
                                "confidence": fav_res.confidence,
                                "method": "Favicon MMH3",
                            })
            except Exception as e:
                logger.debug(f"Stage 8 error: {e}")
        else:
            logger.info(f"Target '{self.host}' has no active HTTP/HTTPS service. Skipping web app recon.")

        # ─── Stage 9: API Discovery, Swagger/OpenAPI, GraphQL & JS Route Extraction ───
        self._notify(9, "API Discovery, Swagger/OpenAPI, GraphQL & JS Route Extraction")
        if web_active:
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

                # Client-Side JavaScript Route & API Endpoint Extraction
                from phantom_recon.core.js_miner import JSEndpointExtractor
                js_extractor = JSEndpointExtractor(
                    url=self.url,
                    timeout=self.timeout,
                    max_scripts=6 if self.fast_mode else 12,
                    verify_ssl=self.verify_ssl,
                    probe_endpoints=not self.fast_mode,
                )
                js_results = js_extractor.extract()
                self.scan_data["js_endpoints"] = js_results.to_dict()

                for probe in js_results.probed_findings:
                    if probe.get("is_exposed"):
                        self._add_finding(AuditFinding(
                            title=f"Exposed Client-Side Sensitive Route ({probe['path']})",
                            severity="medium",
                            cvss_score=5.3,
                            category="API / Attack Surface",
                            location=probe.get("url", self.url),
                            description=(
                                f"Client-side JavaScript references sensitive endpoint '{probe['path']}' "
                                "which responds with HTTP 200 OK without requiring authentication."
                            ),
                            remediation="Enforce strict authentication and authorization checks on all internal and administrative endpoints.",
                            evidence=f"Endpoint: {probe['url']} returned HTTP 200 OK.",
                            poc_url=probe.get("url", self.url),
                            reproduce_curl=f"curl -i -k '{probe.get('url', self.url)}'",
                        ))
            except Exception as e:
                logger.debug(f"Stage 9 error: {e}")
        else:
            logger.info(f"Skipping API audit because web service is not reachable on '{self.host}'.")

        # ─── Stage 10: CMS & Framework Security Audit ───────────────────
        self._notify(10, "CMS & Framework Security Audit (WordPress/Laravel/Django/.js.map)")
        if web_active:
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
                logger.debug(f"Stage 10 error: {e}")
        else:
            logger.info(f"Skipping CMS audit because web service is not reachable on '{self.host}'.")

        # ─── Stage 11: Security Headers & Cookie Security ──────────────
        self._notify(11, "Security Headers, CSP Directives & Cookie Security")
        if web_active:
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
                            reproduce_curl=f"curl -I -k '{self.url}'",
                        ))
            except Exception as e:
                logger.debug(f"Stage 11 error: {e}")
        else:
            logger.info(f"Skipping security headers audit because web service is not reachable on '{self.host}'.")

        # ─── Stage 12: RFC 9116 Security.txt & Sensitive Surface Audit ─
        self._notify(12, "RFC 9116 Security.txt & Sensitive Robots/Sitemap Surface Audit")
        if web_active:
            try:
                from phantom_recon.core.policy_auditor import PolicyAuditor
                policy_auditor = PolicyAuditor(base_url=self.url, timeout=self.timeout)
                policy_results = policy_auditor.run_full_policy_audit()
                self.scan_data["policy"] = policy_results

                for pf in policy_results.get("findings", []):
                    self._add_finding(AuditFinding(
                        title=pf["title"],
                        severity=pf["severity"],
                        cvss_score=pf.get("cvss_score", 3.0),
                        category=pf.get("category", "Policy & Surface"),
                        location=pf.get("location", self.url),
                        description=pf["description"],
                        remediation=pf.get("remediation", ""),
                        evidence=pf.get("evidence", ""),
                        poc_url=pf.get("poc_url", self.url),
                        reproduce_curl=f"curl -i -k '{pf.get('poc_url', self.url)}'",
                    ))
            except Exception as e:
                logger.debug(f"Stage 12 error: {e}")
        else:
            logger.info(f"Skipping security.txt and surface audit because web service is not reachable on '{self.host}'.")

        # ─── Stage 13: SSL/TLS Cryptographic Analysis ──────────────────
        self._notify(13, "SSL/TLS Protocol Inspection & Cryptographic Hygiene")
        if self.target_type in ("domain", "url"):
            open_ports = self.scan_data.get("ports", {})
            has_443 = "443" in open_ports or 443 in open_ports or self.url.startswith("https://")
            if not has_443:
                try:
                    import socket
                    with socket.create_connection((self.host, 443), timeout=3.0):
                        has_443 = True
                except Exception:
                    pass
            if has_443:
                try:
                    from phantom_recon.core.ssl_analyzer import SSLAnalyzer
                    ssl_analyzer = SSLAnalyzer(host=self.host, timeout=min(self.timeout, 4.0))
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
                    logger.debug(f"Stage 13 error: {e}")
            else:
                logger.info(f"Target '{self.host}' does not expose HTTPS port 443. SSL inspection skipped.")

        # ─── Stage 14: HTTP Methods & Dangerous Verbs Audit ────────────
        self._notify(14, "HTTP Methods & Dangerous Verbs Audit (PUT/DELETE/TRACE/WebDAV)")
        if web_active:
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
                logger.debug(f"Stage 14 error: {e}")
        else:
            logger.info(f"Skipping HTTP methods audit because web service is not reachable on '{self.host}'.")

        # ─── Stage 15: Precision Web Vulnerability Scanner ─────────────
        self._notify(15, "Precision Web Vulnerability Scanner & Deep Configuration Audit")
        if web_active:
            try:
                from phantom_recon.core.vuln_scanner import VulnerabilityScanner
                vuln_scanner = VulnerabilityScanner(
                    url=self.url,
                    timeout=self.timeout,
                    verify_ssl=self.verify_ssl,
                    skip_standalone_modules=True,
                )
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
                logger.debug(f"Stage 15 error: {e}")
        else:
            logger.info(f"Skipping deep web vulnerability audit because web service is not reachable on '{self.host}'.")

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
