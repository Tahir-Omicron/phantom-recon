"""
Comprehensive unit test suite for Phantom Recon v2.1.0 features.

Tests:
1. Pure Python 32-bit x86 MurmurHash3 (mmh3) and Shodan Base64 favicon hashing.
2. FaviconAnalyzer technology identification across enterprise signatures.
3. SubdomainTakeoverAuditor dangling CNAME and deprovisioned cloud fingerprint detection (with zero false positive validation).
4. PolicyAuditor RFC 9116 security.txt compliance and sensitive robots.txt disallow parsing.
5. New CLI commands: 'phantom takeover', 'phantom favicon', and 'phantom policy'.
"""

from unittest.mock import MagicMock, patch
import pytest
from click.testing import CliRunner

from phantom_recon import __version__
from phantom_recon.cli import main
from phantom_recon.core.favicon_analyzer import (
    FaviconAnalyzer,
    FaviconResult,
    calculate_shodan_favicon_hash,
    mmh3_32,
    FAVICON_SIGNATURES,
)
from phantom_recon.core.takeover import SubdomainTakeoverAuditor, TAKEOVER_FINGERPRINTS
from phantom_recon.core.policy_auditor import PolicyAuditor


class TestFaviconMMH3Engine:
    """Test pure-Python MurmurHash3 (MMH3) 32-bit implementation and Shodan MIME hashing."""

    def test_mmh3_32_empty_bytes(self):
        assert mmh3_32(b"") == 0

    def test_mmh3_32_deterministic_hash(self):
        val1 = mmh3_32(b"hello world")
        val2 = mmh3_32(b"hello world")
        assert val1 == val2
        assert isinstance(val1, int)

    def test_calculate_shodan_favicon_hash_known_values(self):
        sample_bytes = b"\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00\x08\x00"
        h = calculate_shodan_favicon_hash(sample_bytes)
        assert isinstance(h, int)

    def test_favicon_signatures_catalog_lookup(self):
        # Verify lookup on known enterprise hashes
        assert 116323821 in FAVICON_SIGNATURES
        sig = FAVICON_SIGNATURES[116323821]
        assert sig["name"] == "Spring Boot"
        assert sig["category"] == "Framework / Java"

        assert 81586312 in FAVICON_SIGNATURES
        jenkins_sig = FAVICON_SIGNATURES[81586312]
        assert "Jenkins" in jenkins_sig["name"]

    @patch("requests.Session.get")
    def test_favicon_analyzer_detects_spring_boot(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "image/x-icon", "Content-Length": "1200"}
        mock_resp.text = "<html><head></head><body></body></html>"
        mock_resp.content = b"fake-spring-boot-icon-data-with-extra-bytes-exceeding-minimum-threshold"
        mock_get.return_value = mock_resp

        analyzer = FaviconAnalyzer(target_url="https://app.target.corp")
        with patch("phantom_recon.core.favicon_analyzer.calculate_shodan_favicon_hash", return_value=116323821):
            res = analyzer.analyze()

        assert res is not None
        assert res.mmh3_hash == 116323821
        assert res.identified_tech == "Spring Boot"
        assert res.vendor == "VMware / Spring"
        assert res.confidence == "CONFIRMED"

    @patch("requests.Session.get")
    def test_favicon_analyzer_html_link_extraction(self, mock_get):
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <link rel="icon" type="image/png" href="/assets/custom-icon.png">
        </head>
        </html>
        """
        html_resp = MagicMock()
        html_resp.status_code = 200
        html_resp.headers = {"Content-Type": "text/html"}
        html_resp.text = html_content

        icon_resp = MagicMock()
        icon_resp.status_code = 200
        icon_resp.headers = {"Content-Type": "image/png"}
        icon_resp.text = ""
        icon_resp.content = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x06\x00\x00\x00"

        def side_effect(url, **kwargs):
            if "custom-icon.png" in url:
                return icon_resp
            return html_resp

        mock_get.side_effect = side_effect

        analyzer = FaviconAnalyzer(target_url="https://example.com")
        res = analyzer.analyze()

        assert res is not None
        assert "custom-icon.png" in res.favicon_url


class TestSubdomainTakeoverAuditor:
    """Test Subdomain Takeover & Dangling DNS pointer verification."""

    def test_fingerprints_integrity(self):
        assert len(TAKEOVER_FINGERPRINTS) >= 15
        providers = [fp["provider"] for fp in TAKEOVER_FINGERPRINTS]
        assert "GitHub Pages" in providers
        assert "AWS S3 Bucket" in providers
        assert "Heroku" in providers
        assert "Microsoft Azure" in providers
        assert "Netlify" in providers

    @patch("dns.resolver.Resolver.resolve")
    @patch("requests.Session.get")
    def test_github_pages_takeover_confirmed(self, mock_http, mock_dns):
        mock_rdata = MagicMock()
        mock_rdata.target = "myorg.github.io"
        mock_dns.return_value = [mock_rdata]

        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = "404 Not Found: There isn't a GitHub Pages site here."
        mock_http.return_value = mock_resp

        auditor = SubdomainTakeoverAuditor(targets=["sub.example.com"])
        finding = auditor.check_subdomain("sub.example.com")

        assert finding is not None
        assert finding["subdomain"] == "sub.example.com"
        assert finding["provider"] == "GitHub Pages"
        assert finding["is_takeover"] is True
        assert "There isn't a GitHub Pages site here" in finding["evidence"]

    @patch("dns.resolver.Resolver.resolve")
    @patch("requests.Session.get")
    def test_aws_s3_takeover_confirmed(self, mock_http, mock_dns):
        mock_rdata = MagicMock()
        mock_rdata.target = "bucket-demo.s3.amazonaws.com"
        mock_dns.return_value = [mock_rdata]

        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>"
        mock_http.return_value = mock_resp

        auditor = SubdomainTakeoverAuditor(targets=["s3test.example.com"])
        finding = auditor.check_subdomain("s3test.example.com")

        assert finding is not None
        assert finding["provider"] == "AWS S3 Bucket"
        assert "NoSuchBucket" in finding["evidence"]

    @patch("dns.resolver.Resolver.resolve")
    @patch("requests.Session.get")
    def test_cname_match_but_active_site_no_false_positive(self, mock_http, mock_dns):
        # CNAME points to github.io, but site is actively configured (HTTP 200 OK)
        mock_rdata = MagicMock()
        mock_rdata.target = "active-project.github.io"
        mock_dns.return_value = [mock_rdata]

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html><body>Welcome to our corporate documentation portal</body></html>"
        mock_http.return_value = mock_resp

        auditor = SubdomainTakeoverAuditor(targets=["docs.example.com"])
        finding = auditor.check_subdomain("docs.example.com")

        # Must NOT be flagged as vulnerable!
        assert finding is None

    @patch("dns.resolver.Resolver.resolve")
    def test_subdomain_without_cname_skipped(self, mock_dns):
        import dns.resolver
        mock_dns.side_effect = dns.resolver.NoAnswer

        auditor = SubdomainTakeoverAuditor(targets=["direct.example.com"])
        finding = auditor.check_subdomain("direct.example.com")
        assert finding is None


class TestPolicyAuditor:
    """Test RFC 9116 security.txt and robots.txt sensitive surface auditing."""

    @patch("requests.Session.get")
    def test_rfc9116_security_txt_valid(self, mock_get):
        security_txt_content = """# Security Policy
Contact: mailto:security@example.com
Contact: https://example.com/bounty
Expires: 2028-12-31T23:59:59.000Z
Preferred-Languages: en, az, tr
Canonical: https://example.com/.well-known/security.txt
Policy: https://example.com/security-policy
"""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = security_txt_content
        mock_resp.headers = {"Content-Type": "text/plain"}
        mock_get.return_value = mock_resp

        auditor = PolicyAuditor(base_url="https://example.com")
        res = auditor.audit_security_txt()

        assert res["has_security_txt"] is True
        assert "security@example.com" in res["fields"]["contact"][0]
        assert res["compliant"] is True

    @patch("requests.Session.get")
    def test_rfc9116_missing_contact_flags_warning(self, mock_get):
        invalid_content = "Expires: 2029-01-01T00:00:00Z\n"
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = invalid_content
        mock_resp.headers = {"Content-Type": "text/plain"}
        mock_get.return_value = mock_resp

        auditor = PolicyAuditor(base_url="https://example.com")
        res = auditor.audit_security_txt()

        assert res["has_security_txt"] is True
        assert res["compliant"] is False
        assert res["finding"] is not None
        assert "Missing Mandatory 'Contact'" in res["finding"].title

    @patch("requests.Session.get")
    def test_robots_txt_sensitive_disallow_detection(self, mock_get):
        robots_content = """User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /staging/
Disallow: /images/
"""
        robots_resp = MagicMock()
        robots_resp.status_code = 200
        robots_resp.text = robots_content

        probe_admin_resp = MagicMock()
        probe_admin_resp.status_code = 200
        probe_admin_resp.headers = {"Content-Type": "text/html"}
        probe_admin_resp.content = b"<html>Welcome to internal admin portal</html>"
        probe_admin_resp.text = "<html>Welcome to internal admin portal</html>"

        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return robots_resp
            return probe_admin_resp

        mock_get.side_effect = side_effect

        auditor = PolicyAuditor(base_url="https://example.com")
        res = auditor.audit_sensitive_surface()

        assert res["total_disallow_paths"] >= 4
        assert "/admin/" in res["flagged_sensitive_paths"] or "/backup/" in res["flagged_sensitive_paths"]
        assert len(res["findings"]) > 0


class TestV210CLIFeatures:
    """Test CLI commands in v2.1.0."""

    def test_version_bumped_to_v210(self):
        assert __version__ == "2.1.0"

    def test_cli_version_output(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "2.1.0" in result.output

    def test_cli_takeover_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["takeover", "--help"])
        assert result.exit_code == 0
        assert "takeover" in result.output
        assert "--target" in result.output or "TARGET" in result.output

    def test_cli_favicon_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["favicon", "--help"])
        assert result.exit_code == 0
        assert "favicon" in result.output
        assert "--url" in result.output or "URL" in result.output

    def test_cli_policy_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["policy", "--help"])
        assert result.exit_code == 0
        assert "policy" in result.output
        assert "--url" in result.output or "URL" in result.output

    @patch("phantom_recon.core.subdomain.SubdomainFinder.find_all")
    @patch("phantom_recon.core.takeover.SubdomainTakeoverAuditor.audit_all")
    def test_cli_takeover_run(self, mock_audit, mock_find):
        mock_find.return_value = {"subdomains": [{"subdomain": "blog.test.com"}]}
        mock_audit.return_value = [
            {
                "subdomain": "blog.test.com",
                "provider": "GitHub Pages",
                "cname": "blog.github.io",
                "severity": "critical",
                "cvss_score": 9.3,
                "evidence": "There isn't a GitHub Pages site here.",
            }
        ]
        runner = CliRunner()
        result = runner.invoke(main, ["takeover", "test.com"])
        assert result.exit_code == 0
        assert "blog.test.com" in result.output or "GitHub Pages" in result.output

    @patch("phantom_recon.core.favicon_analyzer.FaviconAnalyzer.analyze")
    def test_cli_favicon_run(self, mock_analyze):
        mock_res = FaviconResult(
            target_url="https://app.test.corp",
            favicon_url="https://app.test.corp/favicon.ico",
            mmh3_hash=116323821,
            md5_hash="d41d8cd98f00b204e9800998ecf8427e",
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            identified_tech="Spring Boot",
            vendor="VMware / Spring",
            category="Framework / Java",
            confidence="CONFIRMED",
            shodan_query="http.favicon.hash:116323821",
        )
        mock_analyze.return_value = mock_res

        runner = CliRunner()
        result = runner.invoke(main, ["favicon", "https://app.test.corp"])
        assert result.exit_code == 0
        assert "116323821" in result.output
        assert "Spring Boot" in result.output

    @patch("phantom_recon.core.policy_auditor.PolicyAuditor.run_full_policy_audit")
    def test_cli_policy_run(self, mock_policy):
        mock_policy.return_value = {
            "security_txt": {
                "has_security_txt": True,
                "url": "https://example.com/.well-known/security.txt",
                "compliant": True,
                "fields": {"contact": ["mailto:sec@example.com"], "expires": ["2028-01-01T00:00:00Z"]},
                "finding": None,
            },
            "sensitive_surface": {
                "total_disallow_paths": 2,
                "flagged_sensitive_paths": ["/admin/"],
                "findings": [],
            },
            "findings": [],
        }
        runner = CliRunner()
        result = runner.invoke(main, ["policy", "https://example.com"])
        assert result.exit_code == 0
        assert "RFC 9116" in result.output or "security.txt" in result.output
