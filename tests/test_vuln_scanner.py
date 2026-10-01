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
