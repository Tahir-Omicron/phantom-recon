"""
Tests for Phantom Recon v2.0.0 Features.

Covers:
- Autonomous Master Audit Engine (AutonomousAuditor)
- Target input normalization (domains, URLs, IPs, IP:port)
- Perimeter risky service/port vulnerability detection (Redis, Telnet, SMB, DBs)
- Unified vulnerability aggregation, deduplication, and severity sorting
- Direct table rendering (print_audit_findings_table) for findings and clean states
- CLI commands: 'phantom audit <target>', 'phantom full <target>', and version check
"""

from unittest.mock import MagicMock, patch
import pytest
from click.testing import CliRunner

from phantom_recon import __version__
from phantom_recon.core.autonomous_auditor import AutonomousAuditor, AuditFinding
from phantom_recon.utils.validators import (
    normalize_target_input,
    DANGEROUS_SERVICES_PORTS,
)
from phantom_recon.utils.logger import print_audit_findings_table
from phantom_recon.cli import main


class TestTargetNormalization:
    """Test suite for normalize_target_input."""

    def test_domain_normalization(self):
        host, base_url, target_type = normalize_target_input("example.com")
        assert host == "example.com"
        assert base_url == "https://example.com"
        assert target_type == "domain"

    def test_url_normalization(self):
        host, base_url, target_type = normalize_target_input("https://target.corp/api/v1/auth?debug=1")
        assert host == "target.corp"
        assert base_url == "https://target.corp"
        assert target_type == "url"

    def test_http_url_with_port(self):
        host, base_url, target_type = normalize_target_input("http://192.168.1.50:8080/admin")
        assert host == "192.168.1.50"
        assert base_url == "http://192.168.1.50:8080"
        assert target_type == "ipv4"

    def test_ipv4_bare(self):
        host, base_url, target_type = normalize_target_input("10.0.0.1")
        assert host == "10.0.0.1"
        assert base_url == "http://10.0.0.1"
        assert target_type == "ipv4"

    def test_empty_target_raises_error(self):
        with pytest.raises(ValueError):
            normalize_target_input("")


class TestDangerousServicesPorts:
    """Test detection rules for dangerous exposed ports."""

    def test_critical_ports_defined(self):
        assert 23 in DANGEROUS_SERVICES_PORTS  # Telnet
        assert 6379 in DANGEROUS_SERVICES_PORTS  # Redis
        assert DANGEROUS_SERVICES_PORTS[23]["risk"] == "critical"
        assert DANGEROUS_SERVICES_PORTS[6379]["risk"] == "critical"

    def test_database_ports_defined(self):
        assert 3306 in DANGEROUS_SERVICES_PORTS  # MySQL
        assert 5432 in DANGEROUS_SERVICES_PORTS  # PostgreSQL
        assert 1433 in DANGEROUS_SERVICES_PORTS  # MSSQL
        assert 27017 in DANGEROUS_SERVICES_PORTS  # MongoDB


class TestAutonomousAuditorPipeline:
    """Test the full autonomous auditor pipeline with mock components."""

    def test_finding_deduplication(self):
        auditor = AutonomousAuditor(target="example.com")
        f1 = AuditFinding(
            title="Exposed Docker Compose Configuration",
            severity="high",
            cvss_score=7.5,
            category="DevOps",
            location="https://example.com/docker-compose.yml",
            description="Docker compose file exposed.",
            remediation="Remove from public root.",
        )
        f2 = AuditFinding(
            title="Exposed Docker Compose Configuration",
            severity="high",
            cvss_score=7.5,
            category="DevOps",
            location="https://example.com/docker-compose.yml",
            description="Duplicate finding at same location.",
            remediation="Remove from public root.",
        )
        auditor._add_finding(f1)
        auditor._add_finding(f2)
        assert len(auditor.findings) == 1

    @patch("phantom_recon.core.whois_lookup.WhoisLookup.lookup")
    @patch("phantom_recon.core.dns_enum.DNSEnumerator.enumerate_all")
    @patch("phantom_recon.core.subdomain.SubdomainFinder.find_all")
    @patch("phantom_recon.core.waf_detector.WAFDetector.run_full_waf_analysis")
    @patch("phantom_recon.core.cloud_auditor.CloudAuditor.run_cloud_audit")
    @patch("phantom_recon.core.scanner.PortScanner.scan")
    @patch("phantom_recon.core.web_recon.WebRecon.run_full_recon")
    @patch("phantom_recon.core.api_scanner.APIScanner.scan_endpoints")
    @patch("phantom_recon.core.cms_auditor.CMSAuditor.run_full_audit")
    @patch("phantom_recon.core.header_analyzer.HeaderAnalyzer.analyze")
    @patch("phantom_recon.core.ssl_analyzer.SSLAnalyzer.analyze")
    @patch("phantom_recon.core.http_methods.HTTPMethodsAuditor.audit_all")
    @patch("phantom_recon.core.vuln_scanner.VulnerabilityScanner.scan_all")
    def test_full_autonomous_audit_execution(
        self,
        mock_vuln,
        mock_methods,
        mock_ssl,
        mock_headers,
        mock_cms,
        mock_api,
        mock_web,
        mock_ports,
        mock_cloud,
        mock_waf,
        mock_subs,
        mock_dns,
        mock_whois,
    ):
        mock_whois.return_value = {"registrar": "GoDaddy", "expires": "2028-01-01"}
        mock_dns.return_value = {
            "records": {},
            "security": {
                "dmarc": {"has_dmarc": False},
                "spf": {"has_spf": True},
            },
        }
        mock_subs.return_value = [{"subdomain": "api.example.com", "ip": "1.2.3.4"}]
        mock_waf.return_value = {
            "has_waf": True,
            "waf_name": "Cloudflare",
            "origin_leakage": {
                "leakage_detected": True,
                "unprotected_origin_candidates": [{"ip": "198.51.100.25", "hostname": "origin.example.com"}],
            },
        }
        mock_cloud.return_value = {"findings": [], "open_buckets_count": 0}
        mock_ports.return_value = {
            "ports": {
                "6379": {"state": "open", "service": "redis", "banner": "Redis 7.0"},
                "443": {"state": "open", "service": "https", "banner": "nginx"},
            }
        }
        mock_web.return_value = {"technologies": ["Nginx", "React"], "directories": []}
        mock_api.return_value = []
        mock_cms.return_value = {"detected_cms": ["WordPress"], "findings": []}
        mock_headers.return_value = {"checks": []}
        mock_ssl.return_value = {"grade": "A", "certificate": {"expired": False}}
        mock_methods.return_value = {"probes": []}
        mock_vuln.return_value = [
            {
                "title": "Exposed Docker Compose Configuration",
                "severity": "high",
                "cvss_score": 7.5,
                "category": "devops",
                "location": "https://example.com/docker-compose.yml",
                "description": "Docker compose exposed.",
                "remediation": "Remove file.",
                "poc_url": "https://example.com/docker-compose.yml",
                "evidence": "version: '3'",
            }
        ]

        stage_logs = []
        auditor = AutonomousAuditor(
            target="example.com",
            fast_mode=True,
            status_callback=lambda s, tot, d: stage_logs.append((s, d)),
        )
        results = auditor.run_full_audit()

        # Check stage progression (15 stages in v2.1.0)
        assert len(stage_logs) == 15
        assert results["target"] == "example.com"
        assert results["url"] == "https://example.com"

        # Check aggregated findings
        vulns = results["vulnerabilities"]
        assert len(vulns) >= 3  # Missing DMARC, WAF Origin Leak, Exposed Redis, Docker compose

        titles = [v["title"] for v in vulns]
        assert "Missing DMARC Anti-Spoofing DNS Policy" in titles
        assert "Potential Backend Origin Server IP Leakage (WAF Bypass)" in titles
        assert "Exposed Redis In-Memory Database (Port 6379)" in titles
        assert "Exposed Docker Compose Configuration" in titles

        # Check severity sorting: Critical (Redis) should precede Medium/Low
        assert vulns[0]["severity"] == "critical"
        assert "Redis" in vulns[0]["title"]

        # Check security health score calculation
        assert "security_score" in results
        assert results["security_score"]["score"] < 100


class TestVisualFindingsTable:
    """Test print_audit_findings_table output rendering."""

    def test_render_table_with_findings(self, capsys):
        vulns = [
            {
                "title": "Exposed Redis In-Memory Database",
                "severity": "critical",
                "cvss_score": 9.8,
                "category": "Network",
                "location": "target.corp:6379",
                "description": "Unauthenticated Redis port.",
                "remediation": "Bind to localhost.",
            }
        ]
        print_audit_findings_table(vulns, "target.corp", duration=4.25)
        # Should execute without throwing error

    def test_render_clean_system_panel(self, capsys):
        print_audit_findings_table([], "clean.corp", duration=2.10)
        # Should execute without throwing error


class TestCLIAuditAndFullCommands:
    """Test single-command CLI invocations for 'phantom audit' and 'phantom full'."""

    def test_version_is_v200(self):
        assert __version__ >= "2.0.0"

    def test_cli_version_flag_200(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "Phantom Recon" in result.output

    def test_cli_audit_missing_target(self):
        runner = CliRunner()
        result = runner.invoke(main, ["audit"])
        assert result.exit_code == 0
        assert "Hədəf təyin edilməyib" in result.output or "phantom audit" in result.output

    @patch("phantom_recon.core.autonomous_auditor.AutonomousAuditor.run_full_audit")
    def test_cli_audit_positional_target(self, mock_audit, tmp_path):
        mock_audit.return_value = {
            "target": "example.com",
            "url": "https://example.com",
            "vulnerabilities": [
                {
                    "title": "Missing DMARC Anti-Spoofing DNS Policy",
                    "severity": "medium",
                    "cvss_score": 5.3,
                    "category": "DNS",
                    "location": "_dmarc.example.com",
                    "description": "Lacks DMARC record.",
                    "remediation": "Add TXT record.",
                    "evidence": "No record.",
                }
            ],
            "duration_seconds": 3.12,
            "security_score": {
                "score": 93,
                "grade": "A",
                "risk_level": "LOW",
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 1,
                "low_count": 0,
                "info_count": 0,
                "total_vulnerabilities": 1,
                "category_breakdown": {"web_app": 100, "cloud": 100, "crypto": 100, "dns": 70, "network": 100},
            },
        }

        report_file = tmp_path / "test_audit.html"
        runner = CliRunner()
        result = runner.invoke(main, ["audit", "example.com", "-o", str(report_file)])
        assert result.exit_code == 0
        assert "Hədəf Host / Domen" in result.output
        assert "DMARC" in result.output
        assert "AUDİT VƏ TƏHLÜKƏSİZLİK BOŞLUQLARI CƏDVƏLİ" in result.output

    @patch("phantom_recon.core.autonomous_auditor.AutonomousAuditor.run_full_audit")
    def test_cli_full_command_alias(self, mock_audit, tmp_path):
        mock_audit.return_value = {
            "target": "target.corp",
            "url": "https://target.corp",
            "vulnerabilities": [],
            "duration_seconds": 1.85,
            "security_score": {
                "score": 100,
                "grade": "A+",
                "risk_level": "CLEAN",
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "info_count": 0,
                "total_vulnerabilities": 0,
                "category_breakdown": {"web_app": 100, "cloud": 100, "crypto": 100, "dns": 100, "network": 100},
            },
        }

        report_file = tmp_path / "full_test.html"
        runner = CliRunner()
        result = runner.invoke(main, ["full", "target.corp", "-o", str(report_file)])
        assert result.exit_code == 0
        assert "target.corp" in result.output
        assert "TƏBƏRÜK" in result.output
