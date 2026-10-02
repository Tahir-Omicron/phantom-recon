"""
Tests for Phantom Recon v1.8.0 Features.

Covers:
- HTTP Methods & Dangerous Verbs Auditor (OPTIONS, PUT, DELETE, TRACE, WebDAV)
- HTTP Method Override header analysis (X-HTTP-Method-Override)
- Executive Security Posture & Health Score Engine (0-100, A+ to F)
- Sleek horizontal ASCII banner & scorecard gauge rendering
- CLI methods command and 12-stage autonomous full pipeline
- Report generator security score and HTTP method table rendering across HTML, MD, and Text
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from click.testing import CliRunner

from phantom_recon import __version__
from phantom_recon.core.http_methods import HTTPMethodsAuditor, MethodProbeResult
from phantom_recon.core.vuln_scanner import VulnerabilityScanner
from phantom_recon.reporting.security_score import calculate_security_score
from phantom_recon.reporting.report_generator import ReportGenerator
from phantom_recon.utils.logger import BANNER, print_banner, print_security_score_gauge
from phantom_recon.cli import main


class TestHTTPMethodsAuditor:
    """Test suite for HTTPMethodsAuditor."""

    @patch("requests.Session.options")
    def test_options_probe_parsing(self, mock_options):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {
            "Allow": "GET, POST, OPTIONS, HEAD, PUT, DELETE",
            "Public": "OPTIONS, TRACE, GET, HEAD",
        }
        mock_options.return_value = mock_resp

        auditor = HTTPMethodsAuditor(url="https://target.corp")
        result = auditor.run_options_probe()

        assert result["status_code"] == 200
        assert "GET" in result["advertised_methods"]
        assert "PUT" in result["advertised_methods"]
        assert "DELETE" in result["advertised_methods"]
        assert "TRACE" in result["advertised_methods"]

    @patch("requests.Session.request")
    def test_trace_xst_vulnerable(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "TRACE / HTTP/1.1\r\nX-Phantom-Verb-Test: phantom_trace_test_tok\r\n"
        mock_req.return_value = mock_resp

        # Have the probe token match
        with patch("hashlib.md5") as mock_md5:
            mock_hash = MagicMock()
            mock_hash.hexdigest.return_value = "test_token"
            mock_md5.return_value = mock_hash

            auditor = HTTPMethodsAuditor(url="https://target.corp")
            probe = auditor.probe_trace_xst()

            assert probe.method == "TRACE"
            assert probe.allowed is True
            assert probe.is_vulnerable is True
            assert probe.risk == "MEDIUM"
            assert "XST" in probe.remediation or "Apache" in probe.remediation

    @patch("requests.Session.request")
    def test_trace_xst_safe(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 405
        mock_resp.text = "Method Not Allowed"
        mock_req.return_value = mock_resp

        auditor = HTTPMethodsAuditor(url="https://target.corp")
        probe = auditor.probe_trace_xst()

        assert probe.is_vulnerable is False
        assert probe.risk == "SAFE"

    @patch("requests.Session.delete")
    @patch("requests.Session.put")
    def test_put_upload_vulnerable(self, mock_put, mock_delete):
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_put.return_value = mock_resp

        auditor = HTTPMethodsAuditor(url="https://target.corp")
        probe = auditor.probe_put_upload()

        assert probe.method == "PUT"
        assert probe.is_vulnerable is True
        assert probe.risk == "CRITICAL"
        assert "Arbitrary file upload" in probe.evidence
        # Assert cleanup was attempted
        mock_delete.assert_called_once()

    @patch("requests.Session.put")
    def test_put_upload_safe(self, mock_put):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_put.return_value = mock_resp

        auditor = HTTPMethodsAuditor(url="https://target.corp")
        probe = auditor.probe_put_upload()

        assert probe.is_vulnerable is False
        assert probe.risk == "SAFE"

    @patch("requests.Session.delete")
    def test_delete_method_vulnerable(self, mock_delete):
        mock_resp = MagicMock()
        mock_resp.status_code = 204
        mock_delete.return_value = mock_resp

        auditor = HTTPMethodsAuditor(url="https://target.corp")
        probe = auditor.probe_delete_method()

        assert probe.method == "DELETE"
        assert probe.is_vulnerable is True
        assert probe.risk == "HIGH"

    @patch("requests.Session.request")
    def test_webdav_propfind_vulnerable(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 207
        mock_resp.text = '<?xml version="1.0"?><D:multistatus xmlns:D="DAV:"><D:response></D:response></D:multistatus>'
        mock_req.return_value = mock_resp

        auditor = HTTPMethodsAuditor(url="https://target.corp")
        probe = auditor.probe_webdav_propfind()

        assert probe.method == "PROPFIND"
        assert probe.is_vulnerable is True
        assert probe.risk == "MEDIUM"

    @patch("requests.Session.post")
    def test_method_override_detection(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_post.return_value = mock_resp

        auditor = HTTPMethodsAuditor(url="https://target.corp")
        override = auditor.probe_method_override()

        assert override["supported"] is True
        assert len(override["findings"]) > 0

    @patch("requests.Session.options")
    @patch("requests.Session.request")
    @patch("requests.Session.put")
    @patch("requests.Session.delete")
    @patch("requests.Session.post")
    def test_audit_all_clean_server(self, mock_post, mock_del, mock_put, mock_req, mock_opt):
        # OPTIONS returns safe methods
        opt_resp = MagicMock()
        opt_resp.status_code = 200
        opt_resp.headers = {"Allow": "GET, POST, OPTIONS, HEAD"}
        mock_opt.return_value = opt_resp

        # TRACE rejected
        trace_resp = MagicMock()
        trace_resp.status_code = 405
        trace_resp.text = ""
        mock_req.return_value = trace_resp

        # PUT rejected
        put_resp = MagicMock()
        put_resp.status_code = 405
        mock_put.return_value = put_resp

        # DELETE rejected
        del_resp = MagicMock()
        del_resp.status_code = 405
        mock_del.return_value = del_resp

        # POST override rejected
        post_resp = MagicMock()
        post_resp.status_code = 405
        mock_post.return_value = post_resp

        auditor = HTTPMethodsAuditor(url="https://safe-target.corp")
        results = auditor.audit_all()

        assert results["url"] == "https://safe-target.corp"
        assert len(results["vulnerabilities"]) == 0
        assert len(results["probes"]) == 4


class TestSecurityScoreEngine:
    """Test suite for Security Posture & Health Score Engine."""

    def test_perfect_score_empty_vulns(self):
        scorecard = calculate_security_score([])
        assert scorecard["score"] == 100
        assert scorecard["grade"] == "A+"
        assert scorecard["deductions"]["total"] == 0
        assert "Fortified Posture" in scorecard["verdict"]

    def test_score_critical_and_high_deductions(self):
        vulns = [
            {"severity": "critical", "category": "web_app", "title": "SQL Injection"},
            {"severity": "high", "category": "cloud", "title": "Exposed S3 Bucket"},
            {"severity": "medium", "category": "crypto_ssl", "title": "Weak Cipher"},
            {"severity": "low", "category": "web_app", "title": "Missing Header"},
        ]
        scorecard = calculate_security_score(vulns)
        # Deductions: 30 + 15 + 7 + 3 = 55 -> Score: 45 (Grade D)
        assert scorecard["score"] == 45
        assert scorecard["grade"] == "D"
        assert scorecard["deductions"]["critical"] == 30
        assert scorecard["deductions"]["high"] == 15
        assert scorecard["deductions"]["medium"] == 7
        assert scorecard["deductions"]["low"] == 3
        assert scorecard["deductions"]["total"] == 55

    def test_grade_thresholds(self):
        # 1 high finding (-15 pts) -> 85 pts -> Grade A
        assert calculate_security_score([{"severity": "high"}])["grade"] == "A"
        # 1 medium finding (-7 pts) -> 93 pts -> Grade A
        assert calculate_security_score([{"severity": "medium"}])["grade"] == "A"
        # 2 high findings (-30 pts) -> 70 pts -> Grade B
        assert calculate_security_score([{"severity": "high"}, {"severity": "high"}])["grade"] == "B"
        # 4 critical findings (-120 pts) -> 0 pts -> Grade F
        assert calculate_security_score([{"severity": "critical"}] * 4)["grade"] == "F"


class TestLoggerAndBanner:
    """Test terminal ASCII banner and Rich UI scorecard."""

    def test_banner_content_and_styling(self):
        assert "PHANTOM" in BANNER or "____" in BANNER
        assert "[bold red]" in BANNER
        assert "[bold green]" in BANNER
        # Verify lines are compact and well-proportioned
        lines = [line for line in BANNER.split("\n") if line.strip()]
        assert len(lines) == 5

    def test_scorecard_gauge_terminal_render(self):
        score_data = {
            "score": 90,
            "grade": "A",
            "verdict": "Hardened Defense",
            "color": "green",
            "deductions": {"critical": 0, "high": 0, "medium": 7, "low": 3, "total": 10},
            "findings_count": {"critical": 0, "high": 0, "medium": 1, "low": 1, "info": 2},
            "category_scores": {
                "web_app": {"score": 90, "grade": "A"},
                "cloud": {"score": 100, "grade": "A+"},
            },
        }
        # Call print_security_score_gauge to ensure no exceptions or formatting crashes
        print_security_score_gauge(score_data)
        print_banner()


class TestReportGeneratorv180:
    """Test report generation with security scorecard and HTTP methods."""

    def test_markdown_and_text_reports_contain_score(self, tmp_path):
        scan_data = {
            "target": "example.corp",
            "vulnerabilities": [
                {
                    "title": "Exposed .env Credentials",
                    "severity": "critical",
                    "location": "/.env",
                    "cvss_score": 9.8,
                    "description": "Environment file disclosed.",
                    "remediation": "Block .env access.",
                }
            ],
            "http_methods": {
                "advertised_methods": ["GET", "POST", "OPTIONS"],
                "options": {"allow_header": "GET, POST, OPTIONS"},
                "probes": [
                    {
                        "method": "PUT",
                        "status_code": 405,
                        "risk": "SAFE",
                        "is_vulnerable": False,
                        "evidence": "Method rejected.",
                    }
                ],
            },
        }

        generator = ReportGenerator(scan_data=scan_data)

        # Markdown test
        md_file = tmp_path / "report.md"
        generator.generate_markdown(str(md_file))
        md_text = md_file.read_text(encoding="utf-8")
        assert "Executive Summary & Security Health Posture" in md_text
        assert "Security Health Score" in md_text
        assert "HTTP Methods & Dangerous Verbs Audit" in md_text
        assert "70 / 100" in md_text  # 100 - 30 = 70

        # Text test
        txt_file = tmp_path / "report.txt"
        generator.generate_text(str(txt_file))
        txt_text = txt_file.read_text(encoding="utf-8")
        assert "SECURITY HEALTH SCORE: 70/100" in txt_text
        assert "EXECUTIVE VERDICT:" in txt_text

        # HTML test
        html_file = tmp_path / "report.html"
        generator.generate_html(str(html_file))
        html_text = html_file.read_text(encoding="utf-8")
        assert "Phantom Recon v" in html_text
        assert "HTTP Methods & Dangerous Verbs Audit" in html_text


class TestCLICommandsv180:
    """Test CLI commands in v1.8.0."""

    def test_version_matches(self):
        assert __version__ >= "1.8.0"

    @patch("phantom_recon.core.http_methods.HTTPMethodsAuditor.audit_all")
    def test_cli_methods_command(self, mock_audit):
        mock_audit.return_value = {
            "url": "https://test.corp",
            "options": {"allow_header": "GET, POST, OPTIONS"},
            "advertised_methods": ["GET", "POST", "OPTIONS"],
            "probes": [
                {
                    "method": "PUT",
                    "status_code": 405,
                    "allowed": False,
                    "is_vulnerable": False,
                    "risk": "SAFE",
                    "evidence": "Rejected",
                    "poc_curl": "curl -X PUT",
                }
            ],
            "method_override": {"supported": False, "findings": []},
            "vulnerabilities": [],
        }

        runner = CliRunner()
        result = runner.invoke(main, ["methods", "-u", "https://test.corp"])
        assert result.exit_code == 0
        assert "HTTP Methods" in result.output
        assert "Advertised Methods" in result.output

    def test_cli_help_palette_has_methods_and_full(self):
        runner = CliRunner()
        result = runner.invoke(main, ["help"])
        assert result.exit_code == 0
        assert "methods" in result.output
        assert "Master 12-step" in result.output or "full" in result.output
