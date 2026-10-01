"""
Tests for Phantom Recon — Advanced Vulnerability Scanner (v1.1.0).

Verifies exact location tracking, direct clickable PoC URLs,
cURL generation, and sensitive file checks.
"""

from unittest.mock import MagicMock, patch
import pytest
import requests

from phantom_recon.core.vuln_scanner import (
    Vulnerability,
    VulnerabilityScanner,
    SECURITY_HEADERS,
    SENSITIVE_TARGETS,
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


class TestVulnerabilityScannerChecks:
    """Tests for scanner detection logic and location tagging."""

    @patch("requests.Session.get")
    def test_missing_security_headers_includes_location(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}  # No security headers
        mock_get.return_value = mock_response

        scanner = VulnerabilityScanner(url="https://testsite.com")
        vulns = scanner.check_security_headers()

        assert len(vulns) > 0
        hsts_vuln = next((v for v in vulns if "Strict-Transport-Security" in v.title), None)
        assert hsts_vuln is not None
        assert "HTTP Response Header" in hsts_vuln.location
        assert hsts_vuln.poc_url == "https://testsite.com"
        assert "curl" in hsts_vuln.reproduce_curl

    @patch("requests.Session.get")
    def test_cors_reflection_generates_exploit_poc(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            "Access-Control-Allow-Origin": "https://evil-attacker.example.com",
            "Access-Control-Allow-Credentials": "true",
        }
        mock_get.return_value = mock_response

        scanner = VulnerabilityScanner(url="https://api.testsite.com")
        vulns = scanner.check_cors()

        assert len(vulns) >= 1
        cors_vuln = vulns[0]
        assert cors_vuln.severity == "critical"
        assert "Origin" in cors_vuln.location
        assert "curl -i -k -H 'Origin:" in cors_vuln.reproduce_curl
        assert cors_vuln.confidence == "CONFIRMED"

    @patch("requests.Session.get")
    def test_sensitive_file_detection_with_signature(self, mock_get):
        def side_effect(url, **kwargs):
            resp = MagicMock()
            if "/.env" in url:
                resp.status_code = 200
                resp.text = "APP_NAME=Laravel\nAPP_KEY=base64:abcd1234efgh\nDB_PASSWORD=rootpass\n"
            else:
                resp.status_code = 404
                resp.text = "Not Found"
            return resp

        mock_get.side_effect = side_effect

        scanner = VulnerabilityScanner(url="https://app.testsite.com")
        vulns = scanner.check_sensitive_files()

        env_vuln = next((v for v in vulns if ".env" in v.title), None)
        assert env_vuln is not None
        assert env_vuln.severity == "critical"
        assert env_vuln.poc_url == "https://app.testsite.com/.env"
        assert "DB_PASSWORD" in env_vuln.evidence
        assert "Exposed URL Path: /.env" in env_vuln.location
        assert "curl -i -k 'https://app.testsite.com/.env'" in env_vuln.reproduce_curl

    @patch("requests.Session.get")
    def test_parameter_reflection_generates_direct_link(self, mock_get):
        from urllib.parse import unquote

        def side_effect(url, **kwargs):
            resp = MagicMock()
            decoded_url = unquote(url)
            if "phantom<xss>probe789" in decoded_url:
                resp.status_code = 200
                resp.text = "Search results for: phantom<xss>probe789 found 0 items."
            else:
                resp.status_code = 200
                resp.text = "Normal response"
            return resp

        mock_get.side_effect = side_effect

        scanner = VulnerabilityScanner(url="https://search.testsite.com/find?q=apple")
        vulns = scanner.check_parameter_reflection()

        xss_vuln = next((v for v in vulns if "Reflected Input" in v.title), None)
        assert xss_vuln is not None
        assert xss_vuln.param == "q"
        assert "Query Parameter: 'q'" in xss_vuln.location
        assert "phantom%3Cxss%3Eprobe789" in xss_vuln.poc_url or "phantom<xss>probe789" in unquote(xss_vuln.poc_url)
        assert "curl" in xss_vuln.reproduce_curl

    @patch("requests.Session.get")
    def test_open_redirect_detection(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 302
        mock_response.headers = {"Location": "https://example.org/phantom_redirect_test"}
        mock_get.return_value = mock_response

        scanner = VulnerabilityScanner(url="https://auth.testsite.com/login")
        vulns = scanner.check_open_redirect()

        assert len(vulns) >= 1
        redir_vuln = vulns[0]
        assert "Open Redirect" in redir_vuln.title
        assert "Query Parameter" in redir_vuln.location
        assert "phantom_redirect_test" in redir_vuln.poc_url
