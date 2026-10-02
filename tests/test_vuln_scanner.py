"""
Tests for Phantom Recon — Ultra-Precision Vulnerability Scanner (v1.2.0).

Verifies zero-false-positive engineering, soft-404 baseline protection,
semantic file signature matching, dual-origin CORS validation, and exact location tracking.
"""

from unittest.mock import MagicMock, patch
from urllib.parse import unquote
import pytest
import requests

from phantom_recon.core.vuln_scanner import (
    Vulnerability,
    VulnerabilityScanner,
    SECURITY_HEADERS,
    SENSITIVE_FILES_DATABASE,
)


class TestVulnerabilityDataClass:
    """Tests for the enhanced Vulnerability dataclass."""

    def test_vulnerability_creation_with_location_and_poc(self):
        v = Vulnerability(
            title="Exposed Database Config",
            severity="critical",
            description="Found exposed .env file",
            location="Exposed URL Path: /.env",
            url="https://example.com",
            poc_url="https://example.com/.env",
            reproduce_curl="curl -i -k 'https://example.com/.env'",
            evidence="DB_PASSWORD=secret",
            remediation="Deny public access to .env",
            confidence="CONFIRMED",
            cvss_score=9.8,
            category="sensitive_data",
        )
        assert v.severity == "critical"
        assert v.location == "Exposed URL Path: /.env"
        assert v.poc_url == "https://example.com/.env"
        assert "curl" in v.reproduce_curl
        assert v.cvss_score == 9.8
        assert v.confidence == "CONFIRMED"

    def test_vulnerability_to_dict_keys(self):
        v = Vulnerability(
            title="Missing HSTS",
            severity="medium",
            description="HSTS header is absent",
            location="HTTP Response Header: 'Strict-Transport-Security'",
            url="https://example.com",
        )
        data = v.to_dict()
        assert "location" in data
        assert "poc_url" in data
        assert "reproduce_curl" in data
        assert "cvss_score" in data
        assert "confidence" in data
        assert data["location"] == "HTTP Response Header: 'Strict-Transport-Security'"


class TestZeroFalsePositiveGuards:
    """Tests ensuring no false positives occur on edge cases."""

    @patch("requests.Session.get")
    def test_soft_404_prevents_false_positive_sensitive_file(self, mock_get):
        """If server returns 200 OK with same body for 404s, scanner must NOT flag .env."""
        custom_404_html = "<html><body><h1>Page Not Found</h1><p>Sorry, this page does not exist</p></body></html>"
        
        def mock_request(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200  # Soft-404! Returns 200 for everything
            resp.content = custom_404_html.encode()
            resp.text = custom_404_html
            return resp

        mock_get.side_effect = mock_request

        scanner = VulnerabilityScanner(url="https://spa-app.example.com")
        vulns = scanner.check_sensitive_files()

        # Should be empty because it was identified as soft-404!
        assert len(vulns) == 0

    @patch("requests.Session.get")
    def test_sensitive_file_confirmed_with_genuine_secrets(self, mock_get):
        """Genuine .env file containing real config keys must be confirmed."""
        def mock_request(url, **kwargs):
            resp = MagicMock()
            if "/.env" in url:
                resp.status_code = 200
                real_env = "APP_NAME=Laravel\nAPP_KEY=base64:982348234=\nDB_PASSWORD=secret_db_pass_123\n"
                resp.content = real_env.encode()
                resp.text = real_env
            else:
                resp.status_code = 404
                resp.content = b"Not found"
                resp.text = "Not found"
            return resp

        mock_get.side_effect = mock_request

        scanner = VulnerabilityScanner(url="https://target.example.com")
        vulns = scanner.check_sensitive_files()

        assert len(vulns) == 1
        assert vulns[0].title == "Exposed Environment Configuration File (.env)"
        assert vulns[0].severity == "critical"
        assert "DB_PASSWORD" in vulns[0].evidence
        assert vulns[0].location == "Exposed URL Path: /.env"
        assert vulns[0].confidence == "CONFIRMED"

    @patch("requests.Session.get")
    def test_open_redirect_ignores_internal_redirection(self, mock_get):
        """If server redirects back to internal path like /login, it is NOT an open redirect."""
        mock_response = MagicMock()
        mock_response.status_code = 302
        # Internal redirect carrying external url as benign param
        mock_response.headers = {"Location": "https://target.example.com/login?next=https://example.org"}
        mock_get.return_value = mock_response

        scanner = VulnerabilityScanner(url="https://target.example.com")
        vulns = scanner.check_open_redirect()

        # Must NOT flag as open redirect!
        assert len(vulns) == 0

    @patch("requests.Session.get")
    def test_open_redirect_confirms_external_destination(self, mock_get):
        """If server genuinely redirects client to example.org, flag as confirmed."""
        mock_response = MagicMock()
        mock_response.status_code = 302
        mock_response.headers = {"Location": "https://example.org/phantom_redirect_verification"}
        mock_get.return_value = mock_response

        scanner = VulnerabilityScanner(url="https://target.example.com")
        vulns = scanner.check_open_redirect()

        assert len(vulns) >= 1
        assert "Open Redirect" in vulns[0].title
        assert vulns[0].confidence == "CONFIRMED"
        assert "Location: https://example.org" in vulns[0].evidence

    @patch("requests.Session.get")
    def test_cors_dual_origin_reflection_confirmed(self, mock_get):
        """Confirms dynamic reflection with both alpha and beta origins."""
        def mock_request(url, headers=None, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            origin = (headers or {}).get("Origin", "")
            resp.headers = {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            }
            return resp

        mock_get.side_effect = mock_request

        scanner = VulnerabilityScanner(url="https://api.example.com")
        vulns = scanner.check_cors()

        assert len(vulns) == 1
        assert "CORS: Arbitrary Origin Dynamic Reflection" in vulns[0].title
        assert vulns[0].severity == "critical"
        assert vulns[0].confidence == "CONFIRMED"

    @patch("requests.Session.get")
    def test_xss_requires_html_context(self, mock_get):
        """Reflecting input inside application/json is not flagged as HTML XSS."""
        def mock_request(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"Content-Type": "application/json"}
            resp.text = '{"query": "phantom<xss\'probe\\"789>"}'
            return resp

        mock_get.side_effect = mock_request

        scanner = VulnerabilityScanner(url="https://api.example.com/search?q=test")
        vulns = scanner.check_parameter_reflection()

        # In JSON API context, no HTML XSS should be flagged
        assert len(vulns) == 0

    @patch("requests.Session.get")
    def test_xss_confirmed_in_html_context(self, mock_get):
        """Unescaped reflection in text/html context must be flagged and confirmed."""
        canary = "phantom<xss'probe\"789>"

        def mock_request(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"Content-Type": "text/html; charset=utf-8"}
            decoded_url = unquote(url)
            if canary in decoded_url:
                resp.text = f"<div>Search results for: {canary}</div>"
            else:
                resp.text = "<div>Normal</div>"
            return resp

        mock_get.side_effect = mock_request

        scanner = VulnerabilityScanner(url="https://web.example.com/search?q=apple")
        vulns = scanner.check_parameter_reflection()

        assert len(vulns) == 1
        assert "Reflected Cross-Site Scripting (XSS)" in vulns[0].title
        assert vulns[0].confidence == "CONFIRMED"
        assert vulns[0].severity == "high"
        assert "Query Parameter: 'q'" in vulns[0].location

    @patch("requests.Session.get")
    def test_directory_listing_detected_with_valid_index(self, mock_get):
        """Web server directory indexing must be detected and verified."""
        def mock_request(url, **kwargs):
            resp = MagicMock()
            if "/uploads/" in url:
                resp.status_code = 200
                resp.text = "<html><head><title>Index of /uploads</title></head><body><pre><a href=\"test.pdf\">test.pdf</a></pre></body></html>"
                resp.content = resp.text.encode()
            else:
                resp.status_code = 404
                resp.text = "Not found"
                resp.content = b"Not found"
            return resp

        mock_get.side_effect = mock_request

        scanner = VulnerabilityScanner(url="https://example.com")
        vulns = scanner.check_directory_listing()

        assert len(vulns) == 1
        assert "Insecure Directory Listing Enabled on '/uploads/'" in vulns[0].title
        assert vulns[0].severity == "medium"
        assert vulns[0].category == "info_disclosure"

    @patch("requests.Session.get")
    def test_directory_listing_ignored_on_soft_404(self, mock_get):
        """Soft-404 catch-alls must not trigger directory listing findings."""
        spa_html = "<html><body><h1>App Not Found</h1></body></html>"
        def mock_request(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.text = spa_html
            resp.content = spa_html.encode()
            return resp

        mock_get.side_effect = mock_request

        scanner = VulnerabilityScanner(url="https://spa.example.com")
        vulns = scanner.check_directory_listing()

        assert len(vulns) == 0

    @patch("requests.Session.get")
    def test_sensitive_file_backup_sql_detected(self, mock_get):
        """Exposed SQL dump must be detected and flagged as critical."""
        def mock_request(url, **kwargs):
            resp = MagicMock()
            if "/backup.sql" in url:
                resp.status_code = 200
                sql_dump = "-- MySQL dump 10.13\nCREATE TABLE users (id int, password varchar(255));\nINSERT INTO users VALUES (1, 'admin_pass');"
                resp.text = sql_dump
                resp.content = sql_dump.encode()
            else:
                resp.status_code = 404
                resp.text = "Not found"
                resp.content = b"Not found"
            return resp

        mock_get.side_effect = mock_request

        scanner = VulnerabilityScanner(url="https://example.com")
        vulns = scanner.check_sensitive_files()

        assert any("backup.sql" in v.poc_url for v in vulns)
        sql_vuln = next(v for v in vulns if "backup.sql" in v.poc_url)
        assert sql_vuln.severity == "critical"
        assert sql_vuln.cvss_score == 9.8


class TestReportGeneratorFormats:
    """Tests for CSV and Markdown reporting features in ReportGenerator."""

    def test_csv_report_generation(self, tmp_path):
        from phantom_recon.reporting.report_generator import ReportGenerator

        sample_data = {
            "target": "https://test-audit.local",
            "vulnerabilities": [
                {
                    "title": "Exposed Database Dump",
                    "severity": "critical",
                    "cvss_score": 9.8,
                    "confidence": "CONFIRMED",
                    "category": "sensitive_data",
                    "location": "URL Path: /backup.sql",
                    "poc_url": "https://test-audit.local/backup.sql",
                    "reproduce_curl": "curl -i -k 'https://test-audit.local/backup.sql'",
                    "evidence": "CREATE TABLE users",
                    "remediation": "Delete backup.sql",
                    "description": "Sensitive DB dump found.",
                }
            ]
        }

        output_csv = tmp_path / "findings.csv"
        gen = ReportGenerator(scan_data=sample_data)
        gen.generate_csv(str(output_csv))

        assert output_csv.exists()
        content = output_csv.read_text(encoding="utf-8-sig")
        assert "Exposed Database Dump" in content
        assert "CRITICAL" in content
        assert "9.8" in content

    def test_markdown_report_generation(self, tmp_path):
        from phantom_recon.reporting.report_generator import ReportGenerator

        sample_data = {
            "target": "https://test-audit.local",
            "ports": {"80": {"state": "open", "service": "http", "banner": "nginx"}},
            "vulnerabilities": [
                {
                    "title": "XSS in Search",
                    "severity": "high",
                    "cvss_score": 7.5,
                    "confidence": "CONFIRMED",
                    "location": "Query Parameter: 'q'",
                    "poc_url": "https://test-audit.local?q=xss",
                    "reproduce_curl": "curl -i 'https://test-audit.local?q=xss'",
                    "evidence": "<script>alert(1)</script>",
                    "remediation": "HTML encode output.",
                    "description": "Reflected XSS finding.",
                }
            ]
        }

        output_md = tmp_path / "findings.md"
        gen = ReportGenerator(scan_data=sample_data)
        gen.generate_markdown(str(output_md))

        assert output_md.exists()
        content = output_md.read_text(encoding="utf-8")
        assert "# 🔥 Phantom Recon — Penetration Testing Report" in content
        assert "XSS in Search" in content
        assert "```bash" in content
        assert "curl -i 'https://test-audit.local?q=xss'" in content
        assert "| `80/tcp` | `open` | `http` | nginx |" in content


class TestV140AdvancedAuditing:
    """Tests for v1.4.0 Cookie Security, CORS null origin, and Subdomain Takeover."""

    @patch("requests.Session.get")
    def test_cookie_security_missing_flags(self, mock_get):
        """Cookies missing Secure, HttpOnly, and SameSite must be identified."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "text/html"}
        
        # Create a mock cookie
        mock_cookie = MagicMock()
        mock_cookie.name = "session_id"
        mock_cookie.secure = False
        mock_cookie._rest = {}  # Missing HttpOnly and SameSite
        
        mock_resp.cookies = [mock_cookie]
        mock_get.return_value = mock_resp

        scanner = VulnerabilityScanner(url="https://secure-portal.com")
        scanner._response = mock_resp
        vulns = scanner.check_cookie_security()

        assert len(vulns) == 3
        titles = [v.title for v in vulns]
        assert any("Missing 'Secure' Flag on 'session_id'" in t for t in titles)
        assert any("Missing 'HttpOnly' Flag on 'session_id'" in t for t in titles)
        assert any("Missing 'SameSite' Attribute on 'session_id'" in t for t in titles)

    @patch("requests.Session.get")
    def test_cors_null_origin_detected(self, mock_get):
        """Server trusting Origin: null must be flagged as high/medium CORS vulnerability."""
        def mock_request(url, headers=None, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            if headers and headers.get("Origin") == "null":
                resp.headers = {
                    "Access-Control-Allow-Origin": "null",
                    "Access-Control-Allow-Credentials": "true"
                }
            else:
                resp.headers = {}
            return resp

        mock_get.side_effect = mock_request

        scanner = VulnerabilityScanner(url="https://api.test-cors.com")
        vulns = scanner.check_cors()

        assert any("Insecure 'null' Origin Whitelist" in v.title for v in vulns)
        null_vuln = next(v for v in vulns if "null" in v.title)
        assert null_vuln.severity == "high"
        assert null_vuln.confidence == "CONFIRMED"

    @patch("socket.gethostbyname")
    @patch("requests.get")
    def test_subdomain_takeover_detection(self, mock_requests_get, mock_gethostbyname):
        """Subdomain returning dangling third-party service fingerprint must flag takeover risk."""
        from phantom_recon.core.subdomain import SubdomainFinder

        mock_gethostbyname.return_value = "192.0.2.1"
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = "There isn't a GitHub Pages site here."
        mock_requests_get.return_value = mock_resp

        finder = SubdomainFinder(domain="acme-corp.com")
        res = finder._resolve_subdomain("docs")

        assert res is not None
        assert res["takeover_risk"] is True
        assert res["takeover_service"] == "GitHub Pages"
        assert "GitHub Pages site here" in res["takeover_evidence"]


