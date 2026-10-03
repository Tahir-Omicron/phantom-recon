"""
Unit tests for Phantom Recon v2.2.0 Features.

Tests:
1. Version bump to 2.2.0 and CLI version string.
2. VulnerabilityScanner follow_redirects attribute and check_javascript_secrets invocation.
3. DNSEnumerator multi-resolver fallback on DNS timeout/failure.
4. DNSEnumerator audit_dnssec() with enabled and disabled states.
5. DNSEnumerator enumerate_all() populating security with SPF, DMARC, and DNSSEC.
6. AutonomousAuditor Stage 2 DNSSEC finding generation.
7. AutonomousAuditor DNSSEC finding deduplication.
8. CLI 'dns' command with --dnssec flag.
"""

from unittest.mock import MagicMock, patch
import pytest
from click.testing import CliRunner

from phantom_recon import __version__
from phantom_recon.cli import main
from phantom_recon.core.dns_enum import DNSEnumerator, RECORD_TYPES
from phantom_recon.core.vuln_scanner import VulnerabilityScanner
from phantom_recon.core.autonomous_auditor import AutonomousAuditor, AuditFinding


class TestV220Versioning:
    """Validate v2.2.0 versioning and metadata."""

    def test_version_bumped_to_v220(self):
        assert __version__ == "2.2.0"

    def test_cli_version_output_v220(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "2.2.0" in result.output


class TestVulnScannerFollowRedirects:
    """Validate follow_redirects init attribute on VulnerabilityScanner."""

    def test_follow_redirects_default_and_custom(self):
        scanner_def = VulnerabilityScanner(url="http://example.com")
        assert scanner_def.follow_redirects is True

        scanner_custom = VulnerabilityScanner(url="http://example.com", follow_redirects=False)
        assert scanner_custom.follow_redirects is False

    @patch("phantom_recon.core.web_recon.WebRecon.analyze_javascript_files")
    def test_check_javascript_secrets_no_attribute_error(self, mock_js):
        mock_js.return_value = {
            "secrets": [
                {"type": "API Key", "file": "http://example.com/main.js", "preview": "AIzaSy..."}
            ]
        }
        scanner = VulnerabilityScanner(url="http://example.com")
        vulns = scanner.check_javascript_secrets()
        assert len(vulns) == 1
        assert "Exposed API Key" in vulns[0].title
        assert scanner.follow_redirects is True


class TestDNSEnumeratorV220:
    """Validate DNSEnumerator multi-resolver failover and DNSSEC capabilities."""

    def test_record_types_contain_dnssec(self):
        assert "DNSKEY" in RECORD_TYPES
        assert "DS" in RECORD_TYPES

    @patch("phantom_recon.core.dns_enum.DNSEnumerator._create_resolver")
    def test_multi_resolver_failover_on_timeout(self, mock_create):
        import dns.resolver
        import dns.exception

        primary_resolver = MagicMock()
        primary_resolver.resolve.side_effect = dns.resolver.Timeout("Local DNS timeout")

        fallback_resolver = MagicMock()
        fallback_resolver.resolve.return_value = ["v=spf1 -all"]

        mock_create.side_effect = [primary_resolver, fallback_resolver]

        enumerator = DNSEnumerator(domain="example.com")
        answers = enumerator._resolve_query("example.com", "TXT")
        assert answers == ["v=spf1 -all"]
        assert mock_create.call_count == 2
        # Second call should configure resilient public nameservers
        mock_create.assert_called_with(nameservers=["1.1.1.1", "8.8.8.8", "9.9.9.9"])

    def test_audit_dnssec_enabled(self):
        enumerator = DNSEnumerator(domain="secure-org.example")

        def mock_query(record_type):
            if record_type == "DNSKEY":
                return [{"type": "DNSKEY", "value": "256 3 13 oJMRESz5E4gYzS..."}]
            elif record_type == "DS":
                return [{"type": "DS", "value": "2371 13 2 32996839a6d..."}]
            return []

        enumerator._query_record = mock_query
        result = enumerator.audit_dnssec()

        assert result["enabled"] is True
        assert result["status"] == "Enabled"
        assert result["has_dnskey"] is True
        assert result["has_ds"] is True
        assert len(result["dnskey_records"]) == 1
        assert len(result["ds_records"]) == 1
        assert len(result["issues"]) == 0

    def test_audit_dnssec_disabled(self):
        enumerator = DNSEnumerator(domain="insecure-org.example")
        enumerator._query_record = lambda record_type: []

        result = enumerator.audit_dnssec()

        assert result["enabled"] is False
        assert result["status"] == "Disabled"
        assert result["has_dnskey"] is False
        assert result["has_ds"] is False
        assert len(result["issues"]) == 1
        assert "DNSSEC is not enabled" in result["issues"][0]

    @patch.object(DNSEnumerator, "audit_email_security")
    @patch.object(DNSEnumerator, "audit_dnssec")
    @patch.object(DNSEnumerator, "_query_record")
    def test_enumerate_all_includes_security_block(self, mock_query, mock_dnssec, mock_email):
        mock_query.return_value = [{"type": "A", "value": "93.184.216.34"}]
        mock_email.return_value = {
            "spf": {"present": True, "policy": "-all", "raw": "v=spf1 -all"},
            "dmarc": {"present": True, "policy": "reject", "raw": "v=DMARC1; p=reject"},
        }
        mock_dnssec.return_value = {
            "enabled": True,
            "status": "Enabled",
            "has_dnskey": True,
            "has_ds": True,
        }

        enumerator = DNSEnumerator(domain="example.com")
        results = enumerator.enumerate_all()

        assert "security" in results
        sec = results["security"]
        assert sec["spf"]["has_spf"] is True
        assert sec["dmarc"]["has_dmarc"] is True
        assert sec["dnssec"]["enabled"] is True


class TestAutonomousAuditorDNSSEC:
    """Validate AutonomousAuditor integration with DNSSEC and finding deduplication."""

    @patch("phantom_recon.core.dns_enum.DNSEnumerator.enumerate_all")
    def test_stage2_adds_dnssec_finding_when_disabled(self, mock_enum):
        mock_enum.return_value = {
            "security": {
                "dmarc": {"has_dmarc": True},
                "spf": {"has_spf": True},
                "dnssec": {"enabled": False, "status": "Disabled"},
            }
        }

        auditor = AutonomousAuditor(target="example.com", fast_mode=True)
        # Run only Stage 2 logic
        with patch.object(auditor, "_adapt_web_url_and_check_liveness", return_value=False):
            # Run scan but mock other stages to return quickly
            with patch("phantom_recon.core.whois_lookup.WhoisLookup.lookup", return_value={}):
                with patch("phantom_recon.core.subdomain.SubdomainFinder.find_all", return_value=[]):
                    with patch("phantom_recon.core.takeover.SubdomainTakeoverAuditor.audit_all", return_value=[]):
                        with patch("phantom_recon.core.cloud_auditor.CloudAuditor.run_cloud_audit", return_value={}):
                            with patch("phantom_recon.core.scanner.PortScanner.scan", return_value={"ports": {}}):
                                data = auditor.run_full_audit()

        titles = [f["title"] for f in data["vulnerabilities"]]
        assert any("DNSSEC" in t for t in titles)
        dnssec_finding = next(f for f in data["vulnerabilities"] if "DNSSEC" in f["title"])
        assert dnssec_finding["severity"] == "low"
        assert "DNS Zone:" in dnssec_finding["location"]
        assert "nslookup -type=DNSKEY" in dnssec_finding["reproduce_curl"]

    def test_dnssec_finding_deduplication(self):
        auditor = AutonomousAuditor(target="example.com")
        f1 = AuditFinding(
            title="Missing DNSSEC Cryptographic Zone Signing",
            severity="low",
            cvss_score=3.1,
            category="DNS / Domain Integrity",
            location="DNS Zone: example.com",
            description="DNSSEC is disabled.",
            remediation="Enable DNSSEC at registrar.",
        )
        f2 = AuditFinding(
            title="Missing DNSSEC Validation",
            severity="low",
            cvss_score=3.5,
            category="DNS / Domain Integrity",
            location="DNS Zone: example.com",
            description="DNSSEC is absent.",
            remediation="Configure DS record.",
        )

        auditor._add_finding(f1)
        auditor._add_finding(f2)

        # Should be deduplicated into a single entry with highest cvss_score
        assert len(auditor.findings) == 1
        assert auditor.findings[0].cvss_score == 3.5


class TestCLIDNSSECCommand:
    """Validate CLI execution with --dnssec flag."""

    @patch("phantom_recon.core.dns_enum.DNSEnumerator.audit_dnssec")
    @patch("phantom_recon.core.dns_enum.DNSEnumerator.enumerate_all")
    def test_cli_dns_with_dnssec_flag(self, mock_enum, mock_dnssec):
        mock_enum.return_value = {
            "domain": "example.com",
            "records": {"A": [{"value": "93.184.216.34"}]},
        }
        mock_dnssec.return_value = {
            "enabled": True,
            "has_dnskey": True,
            "has_ds": False,
            "dnskey_records": ["256 3 13 key..."],
            "ds_records": [],
            "status": "Enabled",
        }

        runner = CliRunner()
        result = runner.invoke(main, ["dns", "-d", "example.com", "--dnssec"])
        assert result.exit_code == 0
        assert "DNSSEC Cryptographic Integrity" in result.output
        assert "Enabled" in result.output

    def test_format_poc_command_dnssec(self):
        from phantom_recon.utils.logger import format_poc_command
        v = {
            "title": "Missing DNSSEC Cryptographic Zone Signing",
            "location": "DNS Zone: example.com",
            "category": "DNS / Domain Integrity",
            "reproduce_curl": "nslookup -type=DNSKEY example.com",
        }
        cmd = format_poc_command(v, "example.com")
        assert cmd == "nslookup -type=DNSKEY example.com"
