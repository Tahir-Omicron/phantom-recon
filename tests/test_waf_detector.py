"""
Tests for Phantom Recon — WAF & CDN Detector and Origin IP Discovery Engine.
"""

from unittest.mock import MagicMock, patch
import pytest

from phantom_recon.core.waf_detector import WAFDetector, OriginCandidate
from phantom_recon.core.scanner import PortScanner
from phantom_recon.core.vuln_scanner import VulnerabilityScanner


class TestWAFDetectorCIDR:
    """Tests for zero-request IP CIDR matching."""

    def test_cloudflare_cidr_match(self):
        is_waf, provider = WAFDetector.is_ip_in_waf_cidr("104.16.1.1")
        assert is_waf is True
        assert provider == "Cloudflare"

    def test_fastly_cidr_match(self):
        is_waf, provider = WAFDetector.is_ip_in_waf_cidr("151.101.65.140")
        assert is_waf is True
        assert provider == "Fastly"

    def test_akamai_cidr_match(self):
        is_waf, provider = WAFDetector.is_ip_in_waf_cidr("23.32.0.5")
        assert is_waf is True
        assert provider == "Akamai"

    def test_imperva_cidr_match(self):
        is_waf, provider = WAFDetector.is_ip_in_waf_cidr("199.83.128.10")
        assert is_waf is True
        assert provider == "Imperva / Incapsula"

    def test_sucuri_cidr_match(self):
        is_waf, provider = WAFDetector.is_ip_in_waf_cidr("192.88.134.25")
        assert is_waf is True
        assert provider == "Sucuri"

    def test_clean_non_waf_ip(self):
        is_waf, provider = WAFDetector.is_ip_in_waf_cidr("93.184.216.34")
        assert is_waf is False
        assert provider == ""

    def test_invalid_ip_handled(self):
        is_waf, provider = WAFDetector.is_ip_in_waf_cidr("not.an.ip.address")
        assert is_waf is False
        assert provider == ""


class TestWAFDetectorHTTP:
    """Tests for HTTP banner and fingerprint signature detection."""

    @patch("phantom_recon.core.waf_detector.WAFDetector.resolve_target_ips")
    def test_detect_waf_by_cidr(self, mock_resolve):
        mock_resolve.return_value = ["104.16.20.1"]
        detector = WAFDetector(target="https://cloudflare-site.com")
        with patch.object(detector.session, "get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.headers = {}
            mock_resp.cookies = []
            mock_resp.text = "Hello world"
            mock_get.return_value = mock_resp

            result = detector.detect_waf()
            assert result["has_waf"] is True
            assert result["waf_name"] == "Cloudflare"
            assert "proxy network" in result["indicators"][0]
            assert "⚠️ Target is fronted by Cloudflare" in result["warning"]

    @patch("phantom_recon.core.waf_detector.WAFDetector.resolve_target_ips")
    def test_detect_waf_by_header(self, mock_resolve):
        mock_resolve.return_value = ["192.0.2.1"]  # Non-WAF IP
        detector = WAFDetector(target="https://protected.com")
        with patch.object(detector.session, "get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.headers = {
                "server": "cloudflare",
                "cf-ray": "84381830182301",
            }
            mock_resp.cookies = []
            mock_resp.text = "OK"
            mock_get.return_value = mock_resp

            result = detector.detect_waf()
            assert result["has_waf"] is True
            assert result["waf_name"] == "Cloudflare"

    @patch("phantom_recon.core.waf_detector.WAFDetector.resolve_target_ips")
    def test_detect_waf_by_cookie(self, mock_resolve):
        mock_resolve.return_value = ["192.0.2.1"]
        detector = WAFDetector(target="https://imperva-site.com")
        with patch.object(detector.session, "get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.headers = {}
            cookie_mock = MagicMock()
            cookie_mock.name = "visid_incap_12345"
            mock_resp.cookies = [cookie_mock]
            mock_resp.text = "OK"
            mock_get.return_value = mock_resp

            result = detector.detect_waf()
            assert result["has_waf"] is True
            assert result["waf_name"] == "Imperva / Incapsula"

    @patch("phantom_recon.core.waf_detector.WAFDetector.resolve_target_ips")
    def test_detect_waf_none(self, mock_resolve):
        mock_resolve.return_value = ["192.0.2.1"]
        detector = WAFDetector(target="https://direct-site.com")
        with patch.object(detector.session, "get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.headers = {"server": "Apache/2.4.52"}
            mock_resp.cookies = []
            mock_resp.text = "Hello world welcome"
            mock_get.return_value = mock_resp

            result = detector.detect_waf()
            assert result["has_waf"] is False
            assert result["waf_name"] == "None"


class TestOriginLeakage:
    """Tests for passive origin IP exposure discovery."""

    @patch("phantom_recon.core.waf_detector.WAFDetector.resolve_target_ips")
    @patch("phantom_recon.core.dns_enum.DNSEnumerator.enumerate_type")
    @patch("socket.gethostbyname")
    def test_find_origin_candidates_mx_and_spf(self, mock_gethost, mock_dns_enum, mock_resolve):
        mock_resolve.return_value = ["104.16.1.1"]  # Cloudflare edge IP
        
        # Mock MX and SPF
        def dns_side_effect(rtype):
            if rtype == "MX":
                return [{"exchange": "mail.target.com", "preference": 10}]
            if rtype == "TXT":
                return [{"value": "v=spf1 ip4:203.0.113.50 ~all"}]
            return []

        mock_dns_enum.side_effect = dns_side_effect

        def gethost_side_effect(host):
            if host == "mail.target.com":
                return "198.51.100.25"  # Direct unproxied origin server IP
            raise OSError("Host not found")

        mock_gethost.side_effect = gethost_side_effect

        detector = WAFDetector(target="target.com")
        candidates = detector.find_origin_candidates()

        assert len(candidates) >= 2
        ips = [c["ip"] for c in candidates]
        assert "198.51.100.25" in ips
        assert "203.0.113.50" in ips

        # Ensure unprotected status
        mx_cand = next(c for c in candidates if c["ip"] == "198.51.100.25")
        assert mx_cand["is_waf_ip"] is False
        assert "DIRECT IP" in mx_cand["evidence"]


class TestPortScannerWAFIntegration:
    """Tests for PortScanner WAF edge proxy warnings."""

    @patch("socket.gethostbyname")
    def test_port_scanner_detects_waf_proxy(self, mock_resolve):
        mock_resolve.return_value = "104.16.1.1"  # Cloudflare
        scanner = PortScanner(target="cloudflare-test.com", ports="80")

        with patch.object(scanner, "_tcp_connect_scan") as mock_scan:
            mock_scan.return_value = MagicMock(port=80, state="open", service="http", to_dict=lambda: {"port": 80, "state": "open"})
            results = scanner.scan()

            assert results["is_waf_proxy"] is True
            assert results["waf_provider"] == "Cloudflare"
            assert "Cloudflare Anycast edge nodes" in results["waf_warning"]


class TestVulnScannerWAFIntegration:
    """Tests for VulnerabilityScanner WAF and origin leakage checks."""

    @patch("phantom_recon.core.waf_detector.WAFDetector.run_full_waf_analysis")
    def test_waf_origin_leakage_reported_as_high(self, mock_waf_analysis):
        mock_waf_analysis.return_value = {
            "has_waf": True,
            "waf_name": "Cloudflare",
            "resolved_ips": ["104.16.1.1"],
            "origin_leakage": {
                "unprotected_origin_candidates": [
                    {
                        "ip": "198.51.100.25",
                        "hostname": "mail.target.com",
                        "source": "DNS MX Record (mail.target.com)",
                        "evidence": "MX host mail.target.com resolves to 198.51.100.25 (DIRECT IP)",
                    }
                ]
            },
            "indicators": ["Resolved IP in Cloudflare CIDR"],
        }

        scanner = VulnerabilityScanner(url="https://target.com")
        findings = scanner.check_waf_and_origin_leakage()

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == "high"
        assert finding.cvss_score == 7.5
        assert "WAF Bypass Exposure" in finding.title
        assert "198.51.100.25" in finding.evidence
        assert "curl -i -k -H 'Host: target.com' 'https://198.51.100.25/'" in finding.reproduce_curl

    @patch("phantom_recon.core.waf_detector.WAFDetector.run_full_waf_analysis")
    def test_waf_without_leakage_reported_as_info(self, mock_waf_analysis):
        mock_waf_analysis.return_value = {
            "has_waf": True,
            "waf_name": "AWS CloudFront / AWS WAF",
            "resolved_ips": ["13.32.1.1"],
            "origin_leakage": {
                "unprotected_origin_candidates": []
            },
            "indicators": ["Via header cloudfront.net"],
        }

        scanner = VulnerabilityScanner(url="https://aws-site.com")
        findings = scanner.check_waf_and_origin_leakage()

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == "info"
        assert finding.cvss_score == 0.0
        assert "Target Fronted by AWS CloudFront / AWS WAF" in finding.title
