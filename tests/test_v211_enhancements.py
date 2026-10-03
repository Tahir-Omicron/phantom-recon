"""
Unit tests for Phantom Recon v2.1.1 Enhancements:
1. SubdomainFinder passive HackerTarget fallback and DNS IP enrichment.
2. AutonomousAuditor subdomain takeover candidate list extraction.
3. Formatter & PoC command verification (nslookup for DNS/DMARC/SPF, curl -I for headers).
4. Concrete, non-vague remediation directives and configuration snippets.
"""

from unittest.mock import MagicMock, patch
import pytest

from phantom_recon.core.subdomain import SubdomainFinder
from phantom_recon.core.autonomous_auditor import AutonomousAuditor, AuditFinding
from phantom_recon.core.header_analyzer import HeaderAnalyzer
from phantom_recon.core.policy_auditor import PolicyAuditor
from phantom_recon.utils.logger import format_poc_command


class TestSubdomainPassiveEnhancements:
    """Test passive subdomain discovery and HackerTarget fallback."""

    @patch("requests.get")
    def test_search_hackertarget_parsing(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = (
            "cpanel.target.corp,85.187.145.250\n"
            "mail.target.corp,85.187.145.251\n"
            "invalid.otherdomain.com,1.2.3.4\n"
        )
        mock_get.return_value = mock_resp

        finder = SubdomainFinder(domain="target.corp")
        results = finder._search_hackertarget()

        assert len(results) == 2
        subs = [r["subdomain"] for r in results]
        assert "cpanel.target.corp" in subs
        assert "mail.target.corp" in subs
        assert results[0]["ip"] == "85.187.145.250"
        assert results[0]["source"] == "passive_intel"

    @patch("requests.get")
    @patch("socket.gethostbyname")
    def test_ct_search_combines_sources_and_resolves_ips(self, mock_gethostbyname, mock_get):
        mock_gethostbyname.return_value = "192.168.1.100"

        # Mock crt.sh returning docs.target.corp, and hackertarget returning api.target.corp
        def side_effect(url, **kwargs):
            mock_r = MagicMock()
            if "crt.sh" in url:
                mock_r.status_code = 200
                mock_r.json.return_value = [{"name_value": "docs.target.corp"}]
            elif "hackertarget.com" in url:
                mock_r.status_code = 200
                mock_r.text = "api.target.corp,10.0.0.5\n"
            else:
                mock_r.status_code = 404
            return mock_r

        mock_get.side_effect = side_effect

        finder = SubdomainFinder(domain="target.corp")
        results = finder.ct_search()

        subs = {r["subdomain"]: r for r in results}
        assert "docs.target.corp" in subs
        assert "api.target.corp" in subs
        # docs had no IP from crt.sh, so it was resolved via mock_gethostbyname
        assert subs["docs.target.corp"]["ip"] == "192.168.1.100"
        # api had IP from hackertarget
        assert subs["api.target.corp"]["ip"] == "10.0.0.5"


class TestAuditorTakeoverCandidateExtraction:
    """Verify Stage 4 receives discovered subdomains whether list or dict."""

    @patch("phantom_recon.core.whois_lookup.WhoisLookup.lookup")
    @patch("phantom_recon.core.dns_enum.DNSEnumerator.enumerate_all")
    @patch("phantom_recon.core.subdomain.SubdomainFinder.find_all")
    @patch("phantom_recon.core.takeover.SubdomainTakeoverAuditor.audit_all")
    def test_subdomains_fed_to_takeover_auditor(
        self, mock_takeover, mock_subs, mock_dns, mock_whois
    ):
        mock_whois.return_value = {}
        mock_dns.return_value = {"security": {"dmarc": {"has_dmarc": True}, "spf": {"has_spf": True}}}
        mock_subs.return_value = [
            {"subdomain": "admin.target.corp", "ip": "1.2.3.4", "source": "ct_logs"},
            {"subdomain": "portal.target.corp", "ip": "1.2.3.5", "source": "passive_intel"},
        ]
        mock_takeover.return_value = []

        auditor = AutonomousAuditor(target="target.corp", fast_mode=True)
        with patch.object(auditor, "_adapt_web_url_and_check_liveness", return_value=False):
            auditor.run_full_audit()

        # Check that takeover auditor was called with the candidates
        assert mock_takeover.called
        call_targets = auditor.scan_data.get("subdomains", [])
        assert len(call_targets) == 2


class TestActionablePoCCommands:
    """Ensure format_poc_command outputs exact, verifiable terminal commands."""

    def test_dmarc_finding_uses_nslookup(self):
        v = {
            "title": "Missing DMARC Anti-Spoofing DNS Policy",
            "category": "DNS / Email Security",
            "location": "_dmarc.target.corp",
            "reproduce_curl": "curl -i -k 'https://mxtoolbox.com/dmarc'",
        }
        cmd = format_poc_command(v, fallback_target="target.corp")
        assert cmd == "nslookup -type=TXT _dmarc.target.corp"
        assert "curl" not in cmd

    def test_spf_finding_uses_nslookup(self):
        v = {
            "title": "Missing SPF Email Authentication DNS Record",
            "category": "DNS / Email Security",
            "location": "DNS TXT: target.corp",
            "reproduce_curl": "curl -i -k 'https://mxtoolbox.com/spf'",
        }
        cmd = format_poc_command(v, fallback_target="target.corp")
        assert cmd == "nslookup -type=TXT target.corp"
        assert "curl" not in cmd

    def test_web_header_finding_uses_curl_head(self):
        v = {
            "title": "Missing Security Header (Content-Security-Policy)",
            "category": "Web Defense / Headers",
            "location": "Response Headers: Content-Security-Policy",
            "reproduce_curl": "curl -I -k 'https://target.corp'",
            "poc_url": "https://target.corp",
        }
        cmd = format_poc_command(v, fallback_target="target.corp")
        assert cmd == "curl -I -k 'https://target.corp'"


class TestActionableRemediations:
    """Verify that remediations provide exact server/DNS directives."""

    def test_header_analyzer_remediation_contains_nginx_directive(self):
        with patch("requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.headers = {}
            mock_get.return_value = mock_resp

            analyzer = HeaderAnalyzer(url="https://site.corp")
            res = analyzer.analyze()

            csp_check = next(c for c in res["checks"] if c["header"] == "Content-Security-Policy")
            assert "add_header Content-Security-Policy" in csp_check["recommendation"]
            assert "Header always set" in csp_check["recommendation"]

    def test_security_txt_contains_rfc9116_fields(self):
        with patch("requests.Session.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 404
            mock_resp.text = "Not found"
            mock_get.return_value = mock_resp

            auditor = PolicyAuditor(base_url="https://site.corp")
            res = auditor.audit_security_txt()

            finding = res["finding"]
            assert finding is not None
            assert "Contact: mailto:security@" in finding.remediation
            assert "Expires:" in finding.remediation
