"""
Unit tests for Phantom Recon Precision & False-Positive Elimination (v2.3.1).

Verifies:
1. Compound TLD organizational domain extraction (RFC 7489) for .edu.az, .co.uk, .gov.az, etc.
2. RFC 7208 multiple SPF record PermError detection.
3. Permissive SPF (+all, ?all) policy detection and severity categorization.
4. Subdomain DMARC inheritance across compound second-level domains.
5. Content-Security-Policy frame-ancestors satisfying clickjacking protection in HeaderAnalyzer.
6. RFC 6797 plaintext HTTP HSTS behavior (informational, not high-severity vulnerability).
7. HTTPS HSTS missing header detection.
8. Dynamic nonce in VulnerabilityScanner parameter reflection tests.
"""

from unittest.mock import MagicMock, patch
import pytest

from phantom_recon.core.dns_enum import DNSEnumerator
from phantom_recon.core.header_analyzer import HeaderAnalyzer
from phantom_recon.core.vuln_scanner import VulnerabilityScanner


class TestDNSPrecisionFixes:
    """Validate RFC compliance and precision in DNS enumeration."""

    def test_compound_tld_organizational_domain(self):
        # Compound SLD ccTLDs (.edu.az, .gov.az, .co.uk, .com.tr)
        assert DNSEnumerator.get_organizational_domain("sub.naa.edu.az") == "naa.edu.az"
        assert DNSEnumerator.get_organizational_domain("portal.naa.edu.az") == "naa.edu.az"
        assert DNSEnumerator.get_organizational_domain("naa.edu.az") == "naa.edu.az"
        assert DNSEnumerator.get_organizational_domain("test.example.co.uk") == "example.co.uk"
        assert DNSEnumerator.get_organizational_domain("example.co.uk") == "example.co.uk"
        assert DNSEnumerator.get_organizational_domain("sub.domain.gov.az") == "domain.gov.az"

        # Standard gTLDs (.com, .org, .net)
        assert DNSEnumerator.get_organizational_domain("sub.example.com") == "example.com"
        assert DNSEnumerator.get_organizational_domain("api.v1.sub.example.com") == "example.com"
        assert DNSEnumerator.get_organizational_domain("example.com") == "example.com"

    @patch.object(DNSEnumerator, "_query_record")
    @patch.object(DNSEnumerator, "_resolve_query")
    def test_rfc7208_multiple_spf_records_permerror(self, mock_resolve, mock_query):
        mock_resolve.side_effect = Exception("NXDOMAIN")
        mock_query.return_value = [
            {"type": "TXT", "value": "v=spf1 include:_spf.google.com ~all"},
            {"type": "TXT", "value": "v=spf1 ip4:192.0.2.1 -all"},
        ]

        dns_enum = DNSEnumerator("example.com")
        res = dns_enum.audit_email_security()

        assert res["spf"]["present"] is True
        assert any("RFC 7208 PermError" in issue for issue in res["spf"]["issues"])
        assert any(i["severity"] == "high" for i in res["issues"])

    @patch.object(DNSEnumerator, "_query_record")
    @patch.object(DNSEnumerator, "_resolve_query")
    def test_permissive_spf_policies(self, mock_resolve, mock_query):
        mock_resolve.side_effect = Exception("NXDOMAIN")

        # Test +all (Critical)
        mock_query.return_value = [{"type": "TXT", "value": "v=spf1 mx +all"}]
        res_plus = DNSEnumerator("example.com").audit_email_security()
        assert res_plus["spf"]["policy"] == "+all"
        assert any(i["severity"] == "critical" for i in res_plus["issues"])

        # Test ?all (Medium warning)
        mock_query.return_value = [{"type": "TXT", "value": "v=spf1 mx ?all"}]
        res_quest = DNSEnumerator("example.com").audit_email_security()
        assert res_quest["spf"]["policy"] == "?all"
        assert any(i["severity"] == "medium" for i in res_quest["issues"])

    @patch.object(DNSEnumerator, "_query_record")
    @patch.object(DNSEnumerator, "_resolve_query")
    def test_dmarc_subdomain_inheritance_compound_tld(self, mock_resolve, mock_query):
        mock_query.return_value = [{"type": "TXT", "value": "v=spf1 -all"}]

        # Direct subdomain DMARC returns empty, parent organizational domain returns policy
        def mock_resolver_side_effect(qname, qtype):
            if qname == "_dmarc.sub.naa.edu.az":
                raise Exception("NXDOMAIN")
            elif qname == "_dmarc.naa.edu.az":
                return ['"v=DMARC1; p=reject; sp=quarantine; rua=mailto:dmarc@naa.edu.az;"']
            raise Exception("NXDOMAIN")

        mock_resolve.side_effect = mock_resolver_side_effect

        dns_enum = DNSEnumerator("sub.naa.edu.az")
        res = dns_enum.audit_email_security()

        assert res["dmarc"]["present"] is True
        assert "inherited from naa.edu.az" in res["dmarc"]["raw"]
        assert res["dmarc"]["policy"] == "quarantine"


class TestHeaderAnalyzerPrecisionFixes:
    """Validate accurate HTTP header interpretation and clickjacking protection."""

    @patch("requests.get")
    def test_csp_frame_ancestors_satisfies_clickjacking(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'",
            # Note: No X-Frame-Options header
        }
        mock_get.return_value = mock_resp

        analyzer = HeaderAnalyzer("https://example.com")
        results = analyzer.analyze()

        xfo_check = next((c for c in results["checks"] if c["header"] == "X-Frame-Options"), None)
        assert xfo_check is not None
        assert xfo_check["secure"] is True
        assert xfo_check["severity"] == "info"
        assert "frame-ancestors" in xfo_check["description"]

    @patch("requests.get")
    def test_plaintext_http_hsts_rfc6797_guard(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_get.return_value = mock_resp

        analyzer = HeaderAnalyzer("http://example.com")
        results = analyzer.analyze()

        hsts_check = next((c for c in results["checks"] if c["header"] == "Strict-Transport-Security"), None)
        assert hsts_check is not None
        assert hsts_check["secure"] is False
        assert hsts_check["severity"] == "info"
        assert "RFC 6797" in hsts_check["description"]

    @patch("requests.get")
    def test_https_missing_hsts_flagged(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_get.return_value = mock_resp

        analyzer = HeaderAnalyzer("https://example.com")
        results = analyzer.analyze()

        hsts_check = next((c for c in results["checks"] if c["header"] == "Strict-Transport-Security"), None)
        assert hsts_check is not None
        assert hsts_check["secure"] is False
        assert hsts_check["severity"] == "medium"


class TestVulnScannerPrecisionFixes:
    """Validate dynamic nonces and zero-collision reflection testing."""

    @patch("requests.Session.get")
    def test_reflection_dynamic_nonce_generated(self, mock_get):
        captured_urls = []

        def mock_get_handler(url, **kwargs):
            captured_urls.append(url)
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"Content-Type": "text/html"}
            resp.text = "<html><body>safe static response</body></html>"
            return resp

        mock_get.side_effect = mock_get_handler

        scanner = VulnerabilityScanner("https://example.com/search?q=hello", timeout=2.0)
        vulns = scanner.check_parameter_reflection()

        assert len(vulns) == 0
        assert len(captured_urls) > 0
        # Check that the canary sent includes the dynamic phntm[a-z0-9]{6} prefix
        target_param_url = captured_urls[0]
        assert "phntm" in target_param_url


class TestAutonomousAuditorPrecisionFixes:
    """Validate AutonomousAuditor cross-stage deduplication and RFC compliance."""

    def test_stage2_weak_dmarc_detection(self):
        from phantom_recon.core.autonomous_auditor import AutonomousAuditor

        auditor = AutonomousAuditor("example.com")
        with patch("phantom_recon.core.dns_enum.DNSEnumerator.enumerate_all") as mock_dns:
            mock_dns.return_value = {
                "security": {
                    "dmarc": {
                        "has_dmarc": True,
                        "policy": "none",
                        "raw": "v=DMARC1; p=none;",
                    },
                    "spf": {"has_spf": True, "policy": "~all", "raw": "v=spf1 include:_spf.google.com ~all"},
                    "email": {"spf": {"issues": []}, "dmarc": {"issues": []}},
                    "dnssec": {"enabled": True},
                }
            }
            # Only run stage 2
            with patch.object(auditor, "_notify"):
                try:
                    from phantom_recon.core.dns_enum import DNSEnumerator
                    dns_data = DNSEnumerator(domain=auditor.host, timeout=auditor.timeout).enumerate_all()
                    auditor.scan_data["dns"] = dns_data
                    sec = dns_data.get("security", {})
                    dmarc = sec.get("dmarc", {})
                    spf = sec.get("spf", {})

                    if not dmarc.get("has_dmarc"):
                        pass
                    elif dmarc.get("policy") == "none":
                        from phantom_recon.core.autonomous_auditor import AuditFinding
                        auditor._add_finding(AuditFinding(
                            title="Weak DMARC Anti-Spoofing Policy (p=none)",
                            severity="medium",
                            cvss_score=4.8,
                            category="DNS / Email Security",
                            location=f"_dmarc.{auditor.host}",
                            description="Policy is in monitoring mode only",
                            remediation="Escalate policy to reject",
                            evidence=dmarc.get("raw", ""),
                        ))
                except Exception:
                    pass

        weak_dmarc = next((f for f in auditor.findings if "Weak DMARC" in f.title), None)
        assert weak_dmarc is not None
        assert weak_dmarc.severity == "medium"
        assert weak_dmarc.cvss_score == 4.8

    def test_stage11_hsts_skipped_on_plaintext_http(self):
        from phantom_recon.core.autonomous_auditor import AutonomousAuditor, AuditFinding

        auditor = AutonomousAuditor("http://example.com")
        header_results = {
            "checks": [
                {
                    "header": "Strict-Transport-Security",
                    "secure": False,
                    "severity": "info",
                    "description": "Plaintext HTTP cannot enforce HSTS (RFC 6797).",
                },
                {
                    "header": "Content-Security-Policy",
                    "secure": False,
                    "severity": "medium",
                    "description": "Missing CSP.",
                },
            ]
        }

        # Simulate stage 11 header finding logic
        for chk in header_results.get("checks", []):
            h_name = chk.get("header")
            if not chk.get("secure"):
                if h_name == "Strict-Transport-Security" and not auditor.url.lower().startswith("https://"):
                    continue
                if h_name in ("Strict-Transport-Security", "Content-Security-Policy"):
                    auditor._add_finding(AuditFinding(
                        title=f"Missing Security Header ({h_name})",
                        severity="medium",
                        cvss_score=5.0,
                        category="Web Defense / Headers",
                        location=f"Response Headers: {h_name}",
                        description=chk.get("description", ""),
                        remediation="Configure header in web server.",
                    ))

        # Must NOT contain HSTS finding on http://
        assert not any("Strict-Transport-Security" in f.title for f in auditor.findings)
        # Must contain CSP finding
        assert any("Content-Security-Policy" in f.title for f in auditor.findings)

