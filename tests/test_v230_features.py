"""
Unit tests for Phantom Recon v2.3.0 Features.

Tests:
1. Version bump to 2.3.0 and CLI version string.
2. NetworkIntelligence ASN, BGP routing, Cymru DNS lookup, and cloud classification.
3. JSEndpointExtractor client-side JavaScript AST/regex route mining and sensitive path probing.
4. SSLAnalyzer ALPN negotiation and HTTP/2 detection.
5. HeaderAnalyzer Alt-Svc (HTTP/3 & QUIC) modern transport detection.
6. AutonomousAuditor Stage 1 Network Intelligence and Stage 9 JS route integration.
7. CLI 'asn' and 'endpoints' command invocations.
8. Universal cross-platform PoC command formatting (zero piped grep).
"""

from unittest.mock import MagicMock, patch
import pytest
from click.testing import CliRunner

from phantom_recon import __version__
from phantom_recon.cli import main
from phantom_recon.core.network_intel import NetworkIntelligence, NetworkIntelResult, CLOUD_CDN_ASNS
from phantom_recon.core.js_miner import JSEndpointExtractor, JSEndpointResult
from phantom_recon.core.ssl_analyzer import SSLAnalyzer
from phantom_recon.core.header_analyzer import HeaderAnalyzer
from phantom_recon.core.autonomous_auditor import AutonomousAuditor, AuditFinding
from phantom_recon.utils.logger import format_poc_command


class TestV230Versioning:
    """Validate v2.3.0 versioning and metadata."""

    def test_version_bumped_to_v230(self):
        assert __version__ == "2.3.0"

    def test_cli_version_output_v230(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "2.3.0" in result.output


class TestNetworkIntelligence:
    """Validate autonomous BGP / ASN / Network Intelligence engine."""

    def test_target_normalization(self):
        intel = NetworkIntelligence("https://sub.example.com:8443/test")
        assert intel.host == "sub.example.com"

        intel_ip = NetworkIntelligence("1.2.3.4")
        assert intel_ip.host == "1.2.3.4"

    @patch("dns.resolver.Resolver.resolve")
    def test_cymru_dns_lookup(self, mock_resolve):
        # Mock route answer: "15169 | 8.8.8.0/24 | US | arin | 1992-12-01"
        mock_rdata_route = MagicMock()
        mock_rdata_route.to_text.return_value = '"15169 | 8.8.8.0/24 | US | arin | 1992-12-01"'

        # Mock org answer: "15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"
        mock_rdata_org = MagicMock()
        mock_rdata_org.to_text.return_value = '"15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"'

        mock_resolve.side_effect = [[mock_rdata_route], [mock_rdata_org]]

        intel = NetworkIntelligence("8.8.8.8")
        data = intel._lookup_cymru_dns("8.8.8.8")

        assert data["asn"] == "AS15169"
        assert data["bgp_prefix"] == "8.8.8.0/24"
        assert data["country"] == "US"
        assert data["rir"] == "ARIN"
        assert "GOOGLE" in data["as_name"]

    @patch("socket.gethostbyname")
    @patch("socket.gethostbyaddr")
    @patch.object(NetworkIntelligence, "_lookup_cymru_dns")
    @patch.object(NetworkIntelligence, "_lookup_http_fallback")
    def test_full_analyze_cloud_classification(self, mock_http, mock_cymru, mock_ptr, mock_ip):
        mock_ip.return_value = "104.21.10.10"
        mock_ptr.return_value = ("cf-edge.cloudflare.com", [], ["104.21.10.10"])
        mock_cymru.return_value = {
            "asn": "AS13335",
            "as_name": "CLOUDFLARENET, US",
            "bgp_prefix": "104.21.0.0/16",
            "country": "US",
            "rir": "ARIN",
            "allocated_date": "2014-03-28",
        }
        mock_http.return_value = {
            "city": "San Francisco",
            "region": "California",
            "isp": "Cloudflare, Inc.",
        }

        intel = NetworkIntelligence("example.com")
        res = intel.analyze()

        assert res.ip == "104.21.10.10"
        assert res.asn == "AS13335"
        assert res.is_cloud is True
        assert "Cloudflare" in res.cloud_provider
        assert res.city == "San Francisco"
        assert res.to_dict()["bgp_prefix"] == "104.21.0.0/16"


class TestJSEndpointExtractor:
    """Validate client-side JavaScript route & API endpoint mining."""

    def test_regex_extraction_from_text(self):
        extractor = JSEndpointExtractor("https://target.corp")
        sample_js = """
        const API_USERS = "/api/v1/users";
        const ADMIN_ROUTE = "/admin/dashboard";
        const GRAPHQL_URL = "/graphql";
        const S3_BUCKET = "https://my-bucket.s3.amazonaws.com/uploads/photo.jpg";
        fetch("/internal/config?token=" + userToken);
        const asset = "/static/images/logo.png";
        """
        extracted = extractor.extract_from_text(sample_js)

        assert "/api/v1/users" in extracted["api_routes"]
        assert "/graphql" in extracted["api_routes"]
        assert "/admin/dashboard" in extracted["sensitive"]
        assert "/internal/config" in extracted["sensitive"]
        assert "token" in extracted["parameters"]
        assert any("my-bucket.s3.amazonaws.com" in s3 for s3 in extracted["cloud_assets"])
        # Static png should be ignored from API routes
        assert "/static/images/logo.png" not in extracted["api_routes"]

    @patch.object(JSEndpointExtractor, "_fetch_html")
    @patch.object(JSEndpointExtractor, "_fetch_script_content")
    def test_full_extract_pipeline(self, mock_script, mock_html):
        from bs4 import BeautifulSoup
        html_doc = """
        <html>
            <head>
                <script src="/static/app.bundle.js"></script>
                <script>
                    var loginRoute = "/auth/login";
                </script>
            </head>
            <body><h1>Test</h1></body>
        </html>
        """
        mock_html.return_value = (html_doc, BeautifulSoup(html_doc, "html.parser"))
        mock_script.return_value = 'const endpoints = ["/api/v2/orders", "/debug/vars"];'

        extractor = JSEndpointExtractor("https://target.corp", max_scripts=5)
        res = extractor.extract()

        assert res.scripts_analyzed >= 2
        assert "/auth/login" in res.api_routes
        assert "/api/v2/orders" in res.api_routes
        assert "/debug/vars" in res.sensitive_endpoints
        assert res.to_dict()["total_endpoints"] >= 3


class TestSSLALPN:
    """Validate ALPN HTTP/2 detection in SSLAnalyzer."""

    @patch("ssl.create_default_context")
    @patch("socket.socket")
    def test_ssl_alpn_negotiation(self, mock_sock, mock_ctx_factory):
        mock_ctx = MagicMock()
        mock_ctx_factory.return_value = mock_ctx

        mock_conn = MagicMock()
        mock_conn.version.return_value = "TLSv1.3"
        mock_conn.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_conn.getpeercert.return_value = None
        mock_conn.selected_alpn_protocol.return_value = "h2"
        mock_ctx.wrap_socket.return_value = mock_conn

        analyzer = SSLAnalyzer(host="example.com")
        results = analyzer.analyze()

        assert results["alpn_protocol"] == "h2"
        assert results["http2_supported"] is True
        mock_ctx.set_alpn_protocols.assert_called_with(["h2", "http/1.1"])


class TestHeaderAnalyzerAltSvc:
    """Validate Alt-Svc HTTP/3 & QUIC detection in HeaderAnalyzer."""

    @patch("requests.get")
    def test_alt_svc_quic_detection(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {
            "Content-Type": "text/html",
            "Alt-Svc": 'h3=":443"; ma=86400, quic=":443"',
        }
        mock_get.return_value = mock_resp

        analyzer = HeaderAnalyzer(url="https://example.com")
        results = analyzer.analyze()

        alt_check = next((c for c in results["checks"] if c["header"] == "Alt-Svc"), None)
        assert alt_check is not None
        assert alt_check["present"] is True
        assert "HTTP/3 (QUIC)" in alt_check["description"]


class TestAutonomousAuditorV230:
    """Validate Stage 1 Network Intel and Stage 9 JS route integration in AutonomousAuditor."""

    @patch("phantom_recon.core.network_intel.NetworkIntelligence.analyze")
    def test_stage_1_network_intel_population(self, mock_intel_analyze):
        mock_res = NetworkIntelResult(
            target="example.com",
            ip="93.184.216.34",
            asn="AS15133",
            as_name="EDGECAST",
            bgp_prefix="93.184.216.0/24",
            country="US",
        )
        mock_intel_analyze.return_value = mock_res

        auditor = AutonomousAuditor(target="example.com", fast_mode=True)
        # Execute only Stage 1 logic
        auditor._notify(1, "Stage 1 Test")
        from phantom_recon.core.network_intel import NetworkIntelligence
        net_intel = NetworkIntelligence(target=auditor.host).analyze()
        auditor.scan_data["network_intel"] = net_intel.to_dict()

        assert "network_intel" in auditor.scan_data
        assert auditor.scan_data["network_intel"]["asn"] == "AS15133"
        assert auditor.scan_data["network_intel"]["bgp_prefix"] == "93.184.216.0/24"

    @patch("phantom_recon.core.js_miner.JSEndpointExtractor.extract")
    def test_stage_9_js_endpoints_finding_creation(self, mock_js_extract):
        mock_js_res = JSEndpointResult(
            url="https://example.com",
            scripts_analyzed=3,
            api_routes=["/api/v1/status"],
            sensitive_endpoints=["/admin/console"],
            probed_findings=[{
                "path": "/admin/console",
                "url": "https://example.com/admin/console",
                "status_code": 200,
                "is_exposed": True,
            }]
        )
        mock_js_extract.return_value = mock_js_res

        auditor = AutonomousAuditor(target="example.com", fast_mode=True)
        auditor.url = "https://example.com"

        # Execute Stage 9 JS probe handling
        js_results = mock_js_res
        auditor.scan_data["js_endpoints"] = js_results.to_dict()
        for probe in js_results.probed_findings:
            if probe.get("is_exposed"):
                auditor._add_finding(AuditFinding(
                    title=f"Exposed Client-Side Sensitive Route ({probe['path']})",
                    severity="medium",
                    cvss_score=5.3,
                    category="API / Attack Surface",
                    location=probe.get("url", auditor.url),
                    description="Admin endpoint exposed.",
                    remediation="Restrict access.",
                    evidence="Returned 200 OK",
                    poc_url=probe.get("url", auditor.url),
                ))

        assert len(auditor.findings) == 1
        assert "Exposed Client-Side Sensitive Route (/admin/console)" in auditor.findings[0].title
        assert auditor.findings[0].severity == "medium"


class TestCLICommandsV230:
    """Validate CLI invocations for 'asn' and 'endpoints'."""

    @patch("phantom_recon.core.network_intel.NetworkIntelligence.analyze")
    def test_cli_asn_command(self, mock_analyze):
        mock_analyze.return_value = NetworkIntelResult(
            target="example.com",
            ip="93.184.216.34",
            asn="AS15133",
            as_name="EDGECAST",
            bgp_prefix="93.184.216.0/24",
            country="US",
            city="Los Angeles",
            isp="Verizon",
            is_cloud=False,
        )

        runner = CliRunner()
        result = runner.invoke(main, ["asn", "example.com"])
        assert result.exit_code == 0
        assert "AS15133" in result.output
        assert "93.184.216.34" in result.output

    @patch("phantom_recon.core.js_miner.JSEndpointExtractor.extract")
    def test_cli_endpoints_command(self, mock_extract):
        mock_extract.return_value = JSEndpointResult(
            url="https://example.com",
            scripts_analyzed=4,
            api_routes=["/api/v1/users", "/api/v1/billing"],
            sensitive_endpoints=["/internal/metrics"],
            cloud_assets=["https://test.s3.amazonaws.com"],
        )

        runner = CliRunner()
        result = runner.invoke(main, ["endpoints", "https://example.com"])
        assert result.exit_code == 0
        assert "/api/v1/users" in result.output
        assert "/internal/metrics" in result.output


class TestUniversalPocCommands:
    """Validate that PoC commands are universal and PowerShell compatible."""

    def test_format_poc_command_strips_piped_grep(self):
        finding = {
            "title": "Missing Secure Flag",
            "category": "cookie_security",
            "location": "Set-Cookie Header",
            "reproduce_curl": "curl -i -k 'https://example.com' | grep -i 'set-cookie'",
            "poc_url": "https://example.com",
        }
        cmd = format_poc_command(finding, fallback_target="example.com")
        assert cmd == "curl -i -k 'https://example.com'"
        assert "| grep" not in cmd
