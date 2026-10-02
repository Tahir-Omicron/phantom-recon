"""
Tests for Phantom Recon v1.9.0 Features.

Covers:
- CMS & Framework Security Auditor (WordPress, Laravel, Django, Next.js, Drupal, Joomla, Spring Boot)
- WordPress REST API user enumeration (/wp-json/wp/v2/users)
- WordPress XML-RPC exposure (/xmlrpc.php) & debug log leaks (/wp-content/debug.log)
- Laravel application log leaks (/storage/logs/laravel.log) & Telescope dashboard (/telescope)
- Frontend JavaScript Source Map disclosures (.js.map)
- DevOps & Cloud infrastructure files in VulnScanner (/docker-compose.yml, /terraform.tfstate, /Dockerfile)
- Soft-404 canary verification and zero-false-positive guarantees
- CLI cms command & 13-stage autonomous pipeline
- Report generator templates for CMS & Framework security
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from click.testing import CliRunner

from phantom_recon import __version__
from phantom_recon.core.cms_auditor import CMSAuditor, CMSFinding
from phantom_recon.core.vuln_scanner import VulnerabilityScanner, SENSITIVE_FILES_DATABASE
from phantom_recon.reporting.report_generator import ReportGenerator
from phantom_recon.cli import main


class TestCMSAuditorFingerprinting:
    """Test fingerprinting capabilities of CMSAuditor."""

    @patch("requests.Session.get")
    def test_fingerprint_wordpress(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<html><head><meta name="generator" content="WordPress 6.4.2"></head><body><script src="/wp-content/themes/twentytwentyfour/index.js"></script></body></html>'
        mock_resp.headers = {"X-Powered-By": "PHP/8.1"}
        mock_get.return_value = mock_resp

        auditor = CMSAuditor(url="https://wp.example.com")
        fp = auditor.fingerprint_cms()

        assert "WordPress" in fp["detected_cms"]
        assert fp["primary_cms"] == "WordPress"
        assert fp["details"]["WordPress"]["version"] == "6.4.2"

    @patch("requests.Session.get")
    def test_fingerprint_laravel(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<html><body><h1>Welcome</h1></body></html>'
        mock_resp.headers = {"Set-Cookie": "laravel_session=eyJpdiI6In...; path=/; HttpOnly"}
        mock_get.return_value = mock_resp

        auditor = CMSAuditor(url="https://laravel.example.com")
        fp = auditor.fingerprint_cms()

        assert "Laravel" in fp["detected_cms"]
        assert fp["primary_cms"] == "Laravel"

    @patch("requests.Session.get")
    def test_fingerprint_django(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<html><body><form><input type="hidden" name="csrfmiddlewaretoken" value="abc123xyz"></form></body></html>'
        mock_resp.headers = {}
        mock_get.return_value = mock_resp

        auditor = CMSAuditor(url="https://django.example.com")
        fp = auditor.fingerprint_cms()

        assert "Django" in fp["detected_cms"]
        assert fp["primary_cms"] == "Django"

    @patch("requests.Session.get")
    def test_fingerprint_nextjs(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<html><body><script id="__NEXT_DATA__" type="application/json">{"props":{}}</script></body></html>'
        mock_resp.headers = {}
        mock_get.return_value = mock_resp

        auditor = CMSAuditor(url="https://next.example.com")
        fp = auditor.fingerprint_cms()

        assert "Next.js" in fp["detected_cms"]
        assert fp["primary_cms"] == "Next.js"


class TestCMSAuditorWordPressVulnerabilities:
    """Test WordPress vulnerability checks in CMSAuditor."""

    @patch("requests.Session.get")
    def test_wp_rest_api_user_enumeration(self, mock_get):
        def mock_side_effect(url, **kwargs):
            resp = MagicMock()
            if "/wp-json/wp/v2/users" in url:
                resp.status_code = 200
                resp.headers = {"Content-Type": "application/json; charset=UTF-8"}
                resp.json.return_value = [
                    {"id": 1, "name": "Site Admin", "slug": "admin_phantom"},
                    {"id": 2, "name": "Editor Dave", "slug": "dave_editor"},
                ]
            else:
                resp.status_code = 404
                resp.text = "Not Found"
                resp.content = b"Not Found"
            return resp

        mock_get.side_effect = mock_side_effect
        auditor = CMSAuditor(url="https://target.corp")
        findings = auditor.audit_wordpress()

        user_enum = next((f for f in findings if "User Enumeration" in f.title), None)
        assert user_enum is not None
        assert user_enum.severity == "medium"
        assert "admin_phantom" in user_enum.evidence
        assert "dave_editor" in user_enum.evidence

    @patch("requests.Session.get")
    def test_wp_xmlrpc_exposure(self, mock_get):
        def mock_side_effect(url, **kwargs):
            resp = MagicMock()
            if "/xmlrpc.php" in url:
                resp.status_code = 200
                resp.text = "XML-RPC server accepts POST requests only."
                resp.content = resp.text.encode()
            else:
                resp.status_code = 404
                resp.text = "Not Found"
                resp.content = b"Not Found"
            return resp

        mock_get.side_effect = mock_side_effect
        auditor = CMSAuditor(url="https://target.corp")
        findings = auditor.audit_wordpress()

        xmlrpc = next((f for f in findings if "XML-RPC" in f.title), None)
        assert xmlrpc is not None
        assert xmlrpc.severity == "low"
        assert "/xmlrpc.php" in xmlrpc.url

    @patch("requests.Session.get")
    def test_wp_debug_log_exposure(self, mock_get):
        def mock_side_effect(url, **kwargs):
            resp = MagicMock()
            if "/wp-content/debug.log" in url:
                resp.status_code = 200
                resp.text = "[02-Oct-2026 14:22:10 UTC] PHP Fatal error: Uncaught Error in /var/www/html/wp-config.php:12"
                resp.content = resp.text.encode()
            else:
                resp.status_code = 404
                resp.text = "Not Found"
                resp.content = b"Not Found"
            return resp

        mock_get.side_effect = mock_side_effect
        auditor = CMSAuditor(url="https://target.corp")
        findings = auditor.audit_wordpress()

        debug_log = next((f for f in findings if "Debug Log" in f.title), None)
        assert debug_log is not None
        assert debug_log.severity == "high"
        assert debug_log.cvss == 7.5


class TestCMSAuditorLaravelAndSourceMaps:
    """Test Laravel and Source Map detection."""

    @patch("requests.Session.get")
    def test_laravel_log_exposure(self, mock_get):
        def mock_side_effect(url, **kwargs):
            resp = MagicMock()
            if "/storage/logs/laravel.log" in url:
                resp.status_code = 200
                resp.text = "[2026-10-02 12:00:00] local.ERROR: SQLSTATE[HY000] [2002] Connection refused"
                resp.content = resp.text.encode()
            else:
                resp.status_code = 404
                resp.text = "Not Found"
                resp.content = b"Not Found"
            return resp

        mock_get.side_effect = mock_side_effect
        auditor = CMSAuditor(url="https://target.corp")
        findings = auditor.audit_laravel()

        log_finding = next((f for f in findings if "Application Log" in f.title), None)
        assert log_finding is not None
        assert log_finding.severity == "high"

    @patch("requests.Session.get")
    def test_source_map_exposure(self, mock_get):
        def mock_side_effect(url, **kwargs):
            resp = MagicMock()
            if url == "https://target.corp":
                resp.status_code = 200
                resp.text = '<html><head><script src="/static/js/bundle.main.123.js"></script></head><body></body></html>'
                resp.headers = {}
                resp.content = resp.text.encode()
            elif url == "https://target.corp/static/js/bundle.main.123.js.map":
                resp.status_code = 200
                resp.text = '{"version": 3, "file": "bundle.js", "sources": ["src/App.tsx", "src/auth/jwt.ts"]}'
                resp.content = resp.text.encode()
            else:
                resp.status_code = 404
                resp.text = "Not Found"
                resp.content = b"Not Found"
            return resp

        mock_get.side_effect = mock_side_effect
        auditor = CMSAuditor(url="https://target.corp")
        findings = auditor.audit_source_maps()

        assert len(findings) == 1
        f = findings[0]
        assert "Source Map" in f.title
        assert f.severity == "medium"
        assert f.cvss == 5.3
        assert ".js.map" in f.url

    @patch("requests.Session.get")
    def test_source_map_soft_404_prevention(self, mock_get):
        """Ensure SPA soft-404 HTML pages do not trigger false positive source map findings."""
        spa_html = "<html><body><div id='root'>SPA Page Not Found</div></body></html>"

        def mock_side_effect(url, **kwargs):
            resp = MagicMock()
            if "__phantom_cms_probe_" in url:
                # Canary returns 200 HTML (classic SPA catch-all)
                resp.status_code = 200
                resp.text = spa_html
                resp.content = spa_html.encode()
            elif url == "https://target.corp":
                resp.status_code = 200
                resp.text = '<html><head><script src="/app.js"></script></head><body></body></html>'
                resp.headers = {}
                resp.content = resp.text.encode()
            elif url == "https://target.corp/app.js.map":
                # Returns 200 with SPA catch-all HTML instead of JSON
                resp.status_code = 200
                resp.text = spa_html
                resp.content = spa_html.encode()
            else:
                resp.status_code = 200
                resp.text = spa_html
                resp.content = spa_html.encode()
            return resp

        mock_get.side_effect = mock_side_effect
        auditor = CMSAuditor(url="https://target.corp")
        findings = auditor.audit_source_maps()

        # Must NOT report source map finding because content is HTML soft-404, not JSON
        assert len(findings) == 0


class TestDevOpsArtifactsInVulnScanner:
    """Test Docker and Terraform infrastructure exposure checks in VulnerabilityScanner."""

    def test_sensitive_database_contains_devops_rules(self):
        paths = [item["path"] for item in SENSITIVE_FILES_DATABASE]
        assert "/docker-compose.yml" in paths
        assert "/terraform.tfstate" in paths
        assert "/Dockerfile" in paths

    @patch("requests.Session.get")
    def test_docker_compose_exposure_detected(self, mock_get):
        compose_content = """version: '3.8'
services:
  web:
    image: nginx:alpine
    ports:
      - "80:80"
  db:
    image: postgres:15
    environment:
      POSTGRES_PASSWORD: supersecretpassword
"""
        def mock_side_effect(url, **kwargs):
            resp = MagicMock()
            if "/docker-compose.yml" in url:
                resp.status_code = 200
                resp.text = compose_content
                resp.content = compose_content.encode()
            else:
                resp.status_code = 404
                resp.text = "Not Found"
                resp.content = b"Not Found"
            return resp

        mock_get.side_effect = mock_side_effect
        scanner = VulnerabilityScanner(url="https://devops.corp")
        vulns = scanner.check_sensitive_files()

        docker_vuln = next((v for v in vulns if "docker-compose.yml" in v.title), None)
        assert docker_vuln is not None
        assert docker_vuln.severity == "high"
        assert docker_vuln.cvss_score == 7.5

    @patch("requests.Session.get")
    def test_terraform_tfstate_exposure_detected(self, mock_get):
        tfstate_content = """{
  "version": 4,
  "terraform_version": "1.5.0",
  "serial": 1,
  "lineage": "e6a2b84d-1234-5678-abcd-ef0123456789",
  "resources": [
    {
      "mode": "managed",
      "type": "aws_instance",
      "name": "web"
    }
  ]
}"""
        def mock_side_effect(url, **kwargs):
            resp = MagicMock()
            if "/terraform.tfstate" in url:
                resp.status_code = 200
                resp.text = tfstate_content
                resp.content = tfstate_content.encode()
            else:
                resp.status_code = 404
                resp.text = "Not Found"
                resp.content = b"Not Found"
            return resp

        mock_get.side_effect = mock_side_effect
        scanner = VulnerabilityScanner(url="https://cloud.corp")
        vulns = scanner.check_sensitive_files()

        tf_vuln = next((v for v in vulns if "terraform.tfstate" in v.title), None)
        assert tf_vuln is not None
        assert tf_vuln.severity == "critical"
        assert tf_vuln.cvss_score == 9.8


class TestCLIAndReportingV190:
    """Test CLI commands and report rendering for v1.9.0."""

    def test_version_bump_to_190(self):
        assert __version__ == "1.9.0"

    def test_cli_version_flag(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "1.9.0" in result.output

    @patch("phantom_recon.core.cms_auditor.CMSAuditor.run_full_audit")
    def test_cli_cms_command(self, mock_audit):
        mock_audit.return_value = {
            "url": "https://cms.target.corp",
            "detected_cms": ["WordPress"],
            "primary_cms": "WordPress",
            "details": {"WordPress": {"version": "6.4.2"}},
            "findings": [
                {
                    "title": "WordPress XML-RPC Interface Exposed (/xmlrpc.php)",
                    "cms_name": "WordPress",
                    "severity": "low",
                    "cvss_score": 4.3,
                    "description": "XML-RPC is accessible.",
                    "location": "URL: /xmlrpc.php",
                    "url": "https://cms.target.corp/xmlrpc.php",
                    "poc_url": "https://cms.target.corp/xmlrpc.php",
                    "evidence": "XML-RPC accepts POST requests only",
                    "reproduce_curl": "curl -i -k 'https://cms.target.corp/xmlrpc.php'",
                }
            ],
            "vulnerabilities": [],
        }

        runner = CliRunner()
        result = runner.invoke(main, ["cms", "-u", "https://cms.target.corp"])
        assert result.exit_code == 0
        assert "WordPress" in result.output
        assert "XML-RPC" in result.output

    def test_report_generator_html_cms_section(self, tmp_path):
        scan_data = {
            "target": "target.corp",
            "cms": {
                "detected_cms": ["WordPress", "Next.js"],
                "primary_cms": "WordPress",
                "findings": [
                    {
                        "title": "WordPress User Enumeration via REST API",
                        "cms_name": "WordPress",
                        "severity": "medium",
                        "location": "/wp-json/wp/v2/users",
                        "url": "https://target.corp/wp-json/wp/v2/users",
                        "evidence": "Exposed users: admin, editor",
                    }
                ],
            },
        }

        out_html = tmp_path / "report_cms.html"
        gen = ReportGenerator(scan_data=scan_data)
        gen.generate_html(str(out_html))

        content = out_html.read_text(encoding="utf-8")
        assert "CMS &amp; Framework Architecture Audit" in content or "CMS & Framework Architecture Audit" in content
        assert "WordPress" in content
        assert "User Enumeration" in content

    def test_report_generator_markdown_cms_section(self, tmp_path):
        scan_data = {
            "target": "target.corp",
            "cms": {
                "detected_cms": ["Laravel"],
                "primary_cms": "Laravel",
                "findings": [
                    {
                        "title": "Exposed Laravel Application Log",
                        "cms_name": "Laravel",
                        "severity": "high",
                        "location": "/storage/logs/laravel.log",
                        "url": "https://target.corp/storage/logs/laravel.log",
                        "evidence": "[2026-10-02] local.ERROR",
                    }
                ],
            },
        }

        out_md = tmp_path / "report_cms.md"
        gen = ReportGenerator(scan_data=scan_data)
        gen.generate_markdown(str(out_md))

        content = out_md.read_text(encoding="utf-8")
        assert "## 🧩 CMS & Framework Architecture Audit" in content
        assert "Laravel" in content
        assert "Exposed Laravel Application Log" in content
