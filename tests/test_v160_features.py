"""
Tests for Phantom Recon v1.6.0 — API Scanner, CSP Deep Evaluator, and CLI Help Palette.
"""

from unittest.mock import MagicMock, patch
import pytest

from phantom_recon.core.api_scanner import APIScanner
from phantom_recon.core.header_analyzer import HeaderAnalyzer
from phantom_recon.core.vuln_scanner import VulnerabilityScanner
from phantom_recon.utils.logger import print_command_palette


class TestAPIScanner:
    """Tests for API & Architecture Discovery Engine."""

    def test_api_scanner_normalization(self):
        scanner = APIScanner(url="api.example.com")
        assert scanner.url == "https://api.example.com"

    @patch("phantom_recon.core.api_scanner.APIScanner._profile_baseline")
    def test_detect_swagger_json(self, mock_baseline):
        scanner = APIScanner(url="https://api.example.com")
        scanner._baseline_status = 404
        scanner._baseline_length = 500

        with patch.object(scanner.session, "get") as mock_get:
            def get_side_effect(url, **kwargs):
                resp = MagicMock()
                if url == "https://api.example.com/swagger.json":
                    resp.status_code = 200
                    resp.headers = {"Content-Type": "application/json"}
                    resp.text = '{"swagger": "2.0", "paths": {"/users": {}}, "info": {"title": "App API"}}'
                    resp.content = resp.text.encode()
                else:
                    resp.status_code = 404
                    resp.headers = {}
                    resp.text = "Not Found"
                    resp.content = resp.text.encode()
                return resp

            mock_get.side_effect = get_side_effect
            findings = scanner.scan_endpoints()

            assert len(findings) == 1
            finding = findings[0]
            assert finding["path"] == "/swagger.json"
            assert "Swagger" in finding["type"]
            assert finding["status_code"] == 200

    @patch("phantom_recon.core.api_scanner.APIScanner._profile_baseline")
    def test_detect_swagger_ui_docs(self, mock_baseline):
        scanner = APIScanner(url="https://api.example.com")
        scanner._baseline_status = 404
        scanner._baseline_length = 200

        with patch.object(scanner.session, "get") as mock_get:
            def get_side_effect(url, **kwargs):
                resp = MagicMock()
                if "swagger-ui.html" in url:
                    resp.status_code = 200
                    resp.headers = {"Content-Type": "text/html"}
                    resp.text = '<html><head><title>Swagger UI</title></head><body><div id="swagger-ui"></div></body></html>'
                    resp.content = resp.text.encode()
                else:
                    resp.status_code = 404
                    resp.headers = {}
                    resp.text = "404 Not Found"
                    resp.content = resp.text.encode()
                return resp

            mock_get.side_effect = get_side_effect
            findings = scanner.scan_endpoints()

            assert len(findings) == 1
            finding = findings[0]
            assert finding["path"] == "/swagger-ui.html"
            assert finding["category"] == "docs"

    @patch("phantom_recon.core.api_scanner.APIScanner._profile_baseline")
    def test_soft_404_ignored(self, mock_baseline):
        scanner = APIScanner(url="https://spa-app.com")
        # SPA returns 200 with 1500 bytes for every URL
        scanner._baseline_status = 200
        scanner._baseline_length = 1500

        with patch.object(scanner.session, "get") as mock_get:
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"Content-Type": "text/html"}
            resp.text = '<html><body>App Root Container</body></html>'
            resp.content = b"A" * 1500
            mock_get.return_value = resp

            findings = scanner.scan_endpoints()
            assert len(findings) == 0


class TestCSPDeepEvaluation:
    """Tests for Content-Security-Policy deep policy audit."""

    def test_insecure_csp_detected(self):
        insecure_policy = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' *;"
        result = HeaderAnalyzer.evaluate_csp_deep(insecure_policy)

        assert result["configured"] is True
        assert result["is_strict"] is False
        assert result["score"] < 50
        issues = " ".join(result["issues"])
        assert "unsafe-inline" in issues
        assert "unsafe-eval" in issues
        assert "wildcard '*'" in issues

    def test_strict_csp_passes(self):
        strict_policy = "default-src 'self'; script-src 'self' https://trusted.cdn.com; object-src 'none'; base-uri 'self';"
        result = HeaderAnalyzer.evaluate_csp_deep(strict_policy)

        assert result["configured"] is True
        assert result["is_strict"] is True
        assert result["score"] == 100
        assert len(result["issues"]) == 0

    def test_missing_csp_handled(self):
        result = HeaderAnalyzer.evaluate_csp_deep("")
        assert result["configured"] is False
        assert result["score"] == 0


class TestVulnScannerAPIIntegration:
    """Tests for VulnerabilityScanner API endpoint finding integration."""

    @patch("phantom_recon.core.api_scanner.APIScanner.scan_endpoints")
    def test_vuln_scanner_flags_api_endpoints(self, mock_scan):
        mock_scan.return_value = [
            {
                "url": "https://target.com/swagger.json",
                "path": "/swagger.json",
                "type": "OpenAPI / Swagger JSON",
                "category": "schema",
                "status_code": 200,
                "evidence": "Valid JSON schema with keys: ['swagger', 'paths']",
                "remediation": "Restrict schema in production.",
            }
        ]

        scanner = VulnerabilityScanner(url="https://target.com")
        findings = scanner.check_api_and_docs()

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == "medium"
        assert "OpenAPI / Swagger JSON at '/swagger.json'" in finding.title
        assert "curl -i -k 'https://target.com/swagger.json'" in finding.reproduce_curl


class TestCLIHelpPalette:
    """Test CLI Command Palette output generator."""

    def test_print_command_palette_runs_cleanly(self):
        # Should execute without throwing any exception
        print_command_palette()
