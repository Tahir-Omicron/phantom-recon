"""
Phantom Recon — Report Generator.

Generates professional HTML, JSON, and plain text reports from scan data
with severity-sorted findings and remediation recommendations.

⚠️ DISCLAIMER: For authorized security testing only.
"""

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from phantom_recon import __version__
from phantom_recon.utils.logger import get_logger, console

logger = get_logger(__name__)


class ReportGenerator:
    """
    Scan report generator.

    Creates professional reports in HTML, JSON, and plain text formats
    from scan results data.

    Usage:
        report = ReportGenerator(scan_data=results)
        report.generate_html("report.html")
    """

    def __init__(self, scan_data: Optional[dict[str, Any]] = None):
        """
        Initialize the report generator.

        Args:
            scan_data: Dictionary containing all scan results.
        """
        self.scan_data = scan_data or {}
        self.timestamp = datetime.now().isoformat()

    def generate_html(self, output_path: str) -> str:
        """
        Generate an HTML report.

        Args:
            output_path: File path for the HTML report.

        Returns:
            Path to the generated report.
        """
        from phantom_recon.reporting.templates import HTML_REPORT_TEMPLATE

        try:
            from jinja2 import Template
            template = Template(HTML_REPORT_TEMPLATE)
            html_content = template.render(
                data=self.scan_data,
                timestamp=self.timestamp,
                generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        except ImportError:
            # Fallback without Jinja2
            html_content = self._generate_html_fallback()

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html_content, encoding="utf-8")

        logger.info(f"HTML report saved to [bold]{output_path}[/bold]")
        return str(path.absolute())

    def generate_json(self, output_path: str) -> str:
        """
        Generate a JSON report.

        Args:
            output_path: File path for the JSON report.

        Returns:
            Path to the generated report.
        """
        report = {
            "report_metadata": {
                "tool": "Phantom Recon",
                "version": __version__,
                "generated_at": self.timestamp,
                "report_format": "json",
            },
            "scan_results": self.scan_data,
        }

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(report, indent=2, default=str),
            encoding="utf-8",
        )

        logger.info(f"JSON report saved to [bold]{output_path}[/bold]")
        return str(path.absolute())

    def generate_csv(self, output_path: str) -> str:
        """
        Generate a CSV report of verified vulnerabilities and findings.
        Uses UTF-8 with BOM for native compatibility with Microsoft Excel,
        Google Sheets, Jira, DefectDojo, and SIEM ingestion.

        Args:
            output_path: File path for the CSV report.

        Returns:
            Path to the generated report.
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        vulns = self.scan_data.get("vulnerabilities", [])
        fieldnames = [
            "ID",
            "Title",
            "Severity",
            "CVSS_Score",
            "Confidence",
            "Category",
            "Location",
            "Target_URL",
            "Direct_PoC_URL",
            "PoC_cURL",
            "Evidence",
            "Remediation",
            "Description",
        ]

        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f, quoting=csv.QUOTE_ALL)
            writer.writerow(fieldnames)

            for idx, vuln in enumerate(vulns, 1):
                if isinstance(vuln, dict):
                    writer.writerow([
                        idx,
                        vuln.get("title", ""),
                        vuln.get("severity", "info").upper(),
                        vuln.get("cvss_score", 0.0),
                        vuln.get("confidence", "CONFIRMED"),
                        vuln.get("category", ""),
                        vuln.get("location", ""),
                        vuln.get("url", self.scan_data.get("target", "")),
                        vuln.get("poc_url", ""),
                        vuln.get("reproduce_curl", ""),
                        vuln.get("evidence", ""),
                        vuln.get("remediation", ""),
                        vuln.get("description", ""),
                    ])

        logger.info(f"CSV report saved to [bold]{output_path}[/bold]")
        return str(path.absolute())

    def generate_markdown(self, output_path: str) -> str:
        """
        Generate a GitHub-flavored Markdown report.
        Ideal for GitHub/GitLab issues, bug bounty reports (HackerOne/Bugcrowd),
        and documentation repositories.

        Args:
            output_path: File path for the Markdown report.

        Returns:
            Path to the generated report.
        """
        target = self.scan_data.get("target") or self.scan_data.get("url", "N/A")
        vulns = self.scan_data.get("vulnerabilities", [])

        # Count severities
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in vulns:
            if isinstance(v, dict):
                sev = v.get("severity", "info").lower()
                sev_counts[sev] = sev_counts.get(sev, 0) + 1

        md_lines = []
        md_lines.append("# 🔥 Phantom Recon — Penetration Testing Report")
        md_lines.append("")
        md_lines.append(f"> **Target:** `{target}`  ")
        md_lines.append(f"> **Generated:** `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`  ")
        md_lines.append(f"> **Toolkit Version:** `v{__version__}`  ")
        md_lines.append("")
        md_lines.append("---")
        md_lines.append("")
        md_lines.append("## 📊 Executive Summary")
        md_lines.append("")
        md_lines.append("| Severity | Count | Status |")
        md_lines.append("| :--- | :---: | :--- |")
        md_lines.append(f"| 🔴 **Critical** | {sev_counts['critical']} | Immediate Action Required |")
        md_lines.append(f"| 🟠 **High** | {sev_counts['high']} | Priority Remediation |")
        md_lines.append(f"| 🟡 **Medium** | {sev_counts['medium']} | Moderate Risk |")
        md_lines.append(f"| 🔵 **Low** | {sev_counts['low']} | Low Risk |")
        md_lines.append(f"| ⚪ **Info** | {sev_counts['info']} | Informational / Best Practice |")
        md_lines.append("")

        if vulns:
            md_lines.append("---")
            md_lines.append("")
            md_lines.append("## 🛡️ Vulnerability Findings Overview & Technical Matrix")
            md_lines.append("")
            md_lines.append("| # | Severity | Vulnerability Name | Location | CVSS | What It Is (Description & Impact) | Remediation Guidance |")
            md_lines.append("| :-: | :--- | :--- | :--- | :-: | :--- | :--- |")
            for idx, v in enumerate(vulns, 1):
                if isinstance(v, dict):
                    sev = v.get("severity", "info").upper()
                    title = v.get("title", "Finding")
                    loc = v.get("location", "Global")
                    cvss = v.get("cvss_score", "N/A")
                    desc = v.get("description", "").replace("\n", " ").replace("|", "\\|")
                    remedy = v.get("remediation", "").replace("\n", " ").replace("|", "\\|")
                    poc_url = v.get("poc_url", "")
                    link_title = f"[{title}]({poc_url})" if poc_url else title
                    md_lines.append(f"| {idx} | **{sev}** | {link_title} | `{loc}` | {cvss} | {desc} | {remedy} |")
            md_lines.append("")

            md_lines.append("---")
            md_lines.append("")
            md_lines.append("## 🔍 Detailed Vulnerability Breakdown")
            md_lines.append("")
            for idx, v in enumerate(vulns, 1):
                if isinstance(v, dict):
                    sev = v.get("severity", "info").upper()
                    title = v.get("title", "Finding")
                    loc = v.get("location", "Global")
                    poc_url = v.get("poc_url", "")
                    reproduce_curl = v.get("reproduce_curl", "")
                    evidence = v.get("evidence", "")
                    desc = v.get("description", "")
                    remedy = v.get("remediation", "")
                    cvss = v.get("cvss_score", "N/A")

                    md_lines.append(f"### #{idx}. {title} `[{sev}]`")
                    md_lines.append("")
                    md_lines.append(f"- **Severity:** `{sev}` (CVSS: `{cvss}`)")
                    md_lines.append(f"- **Location:** `{loc}`")
                    if poc_url:
                        md_lines.append(f"- **Direct Jump Link:** [{poc_url}]({poc_url})")
                    md_lines.append("")
                    md_lines.append(f"**Description:**  \n{desc}")
                    md_lines.append("")
                    if reproduce_curl:
                        md_lines.append("**Reproduction Proof of Concept (cURL):**")
                        md_lines.append("```bash")
                        md_lines.append(reproduce_curl)
                        md_lines.append("```")
                        md_lines.append("")
                    if evidence:
                        md_lines.append("**Verified Evidence:**")
                        md_lines.append("```text")
                        md_lines.append(evidence)
                        md_lines.append("```")
                        md_lines.append("")
                    if remedy:
                        md_lines.append(f"**💡 Remediation:**  \n{remedy}")
                        md_lines.append("")
                    md_lines.append("---")
                    md_lines.append("")

        # WAF / CDN Analysis
        waf_data = self.scan_data.get("waf")
        if waf_data and isinstance(waf_data, dict):
            md_lines.append("## 🛡️ Web Application Firewall & CDN Analysis")
            md_lines.append("")
            has_waf = waf_data.get("has_waf", False)
            waf_name = waf_data.get("waf_name", "None")
            status = "Protected" if has_waf else "Direct / Unprotected"
            md_lines.append(f"- **WAF / CDN Status:** `{status}`")
            md_lines.append(f"- **Identified Provider:** `{waf_name}`")
            resolved_ips = waf_data.get("resolved_ips", [])
            if resolved_ips:
                md_lines.append(f"- **Resolved Edge IPs:** `{', '.join(resolved_ips)}`")
            if waf_data.get("warning"):
                md_lines.append(f"- **Notice:** {waf_data.get('warning')}")

            origin_leak = waf_data.get("origin_leakage", {})
            unprot = origin_leak.get("unprotected_origin_candidates", [])
            if unprot:
                md_lines.append("")
                md_lines.append("### 🚨 Potential Unproxied Origin IP Candidates (WAF Bypass Risk)")
                md_lines.append("")
                md_lines.append("| Candidate IP | Hostname | Discovery Source | Evidence |")
                md_lines.append("| :--- | :--- | :--- | :--- |")
                for c in unprot:
                    md_lines.append(f"| `{c.get('ip')}` | `{c.get('hostname')}` | `{c.get('source')}` | {c.get('evidence')} |")
            md_lines.append("")

        # Cloud Storage Findings
        cloud_data = self.scan_data.get("cloud_storage", {})
        if cloud_data and isinstance(cloud_data, dict):
            cloud_findings = cloud_data.get("findings", [])
            if cloud_findings:
                md_lines.append("## ☁️ Cloud Storage & Bucket Exposure Audit")
                md_lines.append("")
                md_lines.append(f"- **Tested Permutations:** `{cloud_data.get('total_tested', 0)}`")
                md_lines.append(f"- **Publicly Listable Buckets:** `{cloud_data.get('open_buckets_count', 0)}`")
                md_lines.append(f"- **Protected Buckets Identified:** `{cloud_data.get('protected_buckets_count', 0)}`")
                md_lines.append("")
                md_lines.append("| Provider | Bucket / Container | Status | Severity | Direct URL | Evidence |")
                md_lines.append("| :--- | :--- | :---: | :---: | :--- | :--- |")
                for f in cloud_findings:
                    if isinstance(f, dict):
                        is_open = f.get("is_open", False)
                        st = "🚨 **OPEN**" if is_open else "🔒 Protected"
                        sev = f.get("severity", "INFO")
                        url_link = f"[{f.get('url')}]({f.get('url')})"
                        md_lines.append(f"| `{f.get('provider')}` | `{f.get('bucket_name')}` | {st} | `{sev}` | {url_link} | {f.get('evidence', '')[:60]} |")
                md_lines.append("")

        # Port scan
        ports = self.scan_data.get("ports", {})
        if ports and isinstance(ports, dict):
            md_lines.append("## 🔍 Open Network Ports")
            md_lines.append("")
            md_lines.append("| Port | State | Service | Banner |")
            md_lines.append("| :--- | :--- | :--- | :--- |")
            for port, info in ports.items():
                if isinstance(info, dict):
                    p_state = info.get("state", "open")
                    p_serv = info.get("service", "unknown")
                    p_banner = info.get("banner", "")[:40]
                    md_lines.append(f"| `{port}/tcp` | `{p_state}` | `{p_serv}` | {p_banner} |")
            md_lines.append("")

        # Technologies
        techs = self.scan_data.get("technologies", [])
        if techs:
            md_lines.append("## 🌐 Detected Technologies")
            md_lines.append("")
            for t in techs:
                md_lines.append(f"- `{t}`")
            md_lines.append("")

        # API Endpoints
        api_eps = self.scan_data.get("api_endpoints", [])
        if api_eps:
            md_lines.append("## 🔌 Discovered API Schemas & Documentation")
            md_lines.append("")
            md_lines.append("| API Path | Architecture Type | Status | Evidence |")
            md_lines.append("| :--- | :--- | :---: | :--- |")
            for ep in api_eps:
                if isinstance(ep, dict):
                    md_lines.append(f"| `{ep.get('path')}` | `{ep.get('type')}` | `{ep.get('status_code', 200)}` | {ep.get('evidence', '')[:60]} |")
            md_lines.append("")

        # Security Headers
        headers_data = self.scan_data.get("headers", {})
        if headers_data and isinstance(headers_data, dict):
            md_lines.append("## 📋 Security Headers")
            md_lines.append("")
            md_lines.append(f"**Overall Grade:** `{headers_data.get('grade', 'N/A')}`")
            md_lines.append("")
            md_lines.append("| Status | Header | Value | Recommendation |")
            md_lines.append("| :---: | :--- | :--- | :--- |")
            for chk in headers_data.get("checks", []):
                if isinstance(chk, dict):
                    icon = "✅" if chk.get("secure") else "❌"
                    hdr = chk.get("header", "")
                    val = chk.get("value", "") or "*missing*"
                    rec = chk.get("recommendation", "")
                    md_lines.append(f"| {icon} | `{hdr}` | `{val[:30]}` | {rec[:50]} |")
            md_lines.append("")

        md_content = "\n".join(md_lines)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(md_content, encoding="utf-8")

        logger.info(f"Markdown report saved to [bold]{output_path}[/bold]")
        return str(path.absolute())

    def generate_text(self, output_path: str) -> str:
        """
        Generate a plain text report.

        Args:
            output_path: File path for the text report.

        Returns:
            Path to the generated report.
        """
        lines = []
        lines.append("=" * 70)
        lines.append("  PHANTOM RECON — PENETRATION TESTING REPORT")
        lines.append("=" * 70)
        lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"  Tool Version: {__version__}")
        lines.append("=" * 70)
        lines.append("")

        # Target info
        target = self.scan_data.get("target", "N/A")
        lines.append(f"TARGET: {target}")
        lines.append("-" * 70)
        lines.append("")

        # Port scan results
        if "ports" in self.scan_data:
            lines.append("PORT SCAN RESULTS")
            lines.append("-" * 40)
            ports = self.scan_data["ports"]
            if isinstance(ports, dict):
                for port, info in ports.items():
                    if isinstance(info, dict):
                        state = info.get("state", "unknown")
                        service = info.get("service", "")
                        banner = info.get("banner", "")[:50]
                        lines.append(f"  {port}/tcp  {state:10s}  {service:15s}  {banner}")
            lines.append("")

        # Vulnerabilities
        vulns = self.scan_data.get("vulnerabilities", [])
        if vulns:
            lines.append("VULNERABILITY FINDINGS MATRIX")
            lines.append("=" * 80)
            lines.append(f"{'#':<4} {'SEVERITY':<10} {'VULNERABILITY':<28} {'LOCATION':<22} {'CVSS':<6}")
            lines.append("-" * 80)
            for i, vuln in enumerate(vulns, 1):
                if isinstance(vuln, dict):
                    severity = vuln.get("severity", "info").upper()
                    title = vuln.get("title", "Unknown")[:26]
                    loc = vuln.get("location", "Global")[:20]
                    cvss = str(vuln.get("cvss_score", "N/A"))
                    lines.append(f"{i:<4} {severity:<10} {title:<28} {loc:<22} {cvss:<6}")
            lines.append("=" * 80)
            lines.append("")
            lines.append("DETAILED VULNERABILITY DOSSIERS & REMEDIATION")
            lines.append("-" * 80)
            for i, vuln in enumerate(vulns, 1):
                if isinstance(vuln, dict):
                    severity = vuln.get("severity", "info").upper()
                    title = vuln.get("title", "Unknown")
                    location = vuln.get("location", "Global Application")
                    poc_url = vuln.get("poc_url", vuln.get("url", ""))
                    reproduce_curl = vuln.get("reproduce_curl", "")
                    evidence = vuln.get("evidence", "")
                    desc = vuln.get("description", "")
                    remedy = vuln.get("remediation", "")
                    cvss = vuln.get("cvss_score", "N/A")

                    lines.append(f"[#{i}] {title} — [{severity}] (CVSS: {cvss})")
                    lines.append(f"  • Location:           {location}")
                    lines.append(f"  • What It Is & Risk:  {desc}")
                    lines.append(f"  • Remediation:        {remedy}")
                    if poc_url:
                        lines.append(f"  • Direct Jump Link:   {poc_url}")
                    if reproduce_curl:
                        lines.append(f"  • PoC cURL Command:   {reproduce_curl}")
                    if evidence:
                        lines.append(f"  • Verified Evidence:  {evidence}")
                    lines.append("-" * 80)
            lines.append("")

        # DNS records
        if "dns" in self.scan_data:
            lines.append("DNS RECORDS")
            lines.append("-" * 40)
            dns_data = self.scan_data["dns"]
            if isinstance(dns_data, dict):
                for record_type, records in dns_data.get("records", {}).items():
                    for record in records:
                        value = record.get("value", "") if isinstance(record, dict) else str(record)
                        lines.append(f"  {record_type:8s}  {value}")
            lines.append("")

        # Headers
        if "headers" in self.scan_data:
            lines.append("SECURITY HEADERS")
            lines.append("-" * 40)
            headers_data = self.scan_data["headers"]
            if isinstance(headers_data, dict):
                grade = headers_data.get("grade", "N/A")
                lines.append(f"  Grade: {grade}")
                for check in headers_data.get("checks", []):
                    if isinstance(check, dict):
                        status = "✓" if check.get("secure") else "✗"
                        lines.append(f"  {status} {check.get('header', '')}: {check.get('value', 'missing')}")
            lines.append("")

        # WAF & Origin IP Audit
        if "waf" in self.scan_data:
            lines.append("WAF & ORIGIN IP AUDIT")
            lines.append("-" * 40)
            waf_data = self.scan_data["waf"]
            if isinstance(waf_data, dict):
                lines.append(f"  Protected: {waf_data.get('has_waf', False)}")
                lines.append(f"  Provider:  {waf_data.get('waf_name', 'None')}")
                if waf_data.get("warning"):
                    lines.append(f"  Notice:    {waf_data.get('warning')}")
                origin_leak = waf_data.get("origin_leakage", {})
                unprot = origin_leak.get("unprotected_origin_candidates", [])
                if unprot:
                    lines.append("  Unprotected Origin Candidates:")
                    for c in unprot:
                        lines.append(f"    - IP: {c.get('ip')} | Host: {c.get('hostname')} | Source: {c.get('source')}")
            lines.append("")

        # API Endpoints
        if "api_endpoints" in self.scan_data:
            lines.append("API & ARCHITECTURE DISCOVERY")
            lines.append("-" * 40)
            for ep in self.scan_data.get("api_endpoints", []):
                if isinstance(ep, dict):
                    lines.append(f"  [{ep.get('status_code', 200)}] {ep.get('path', '')} ({ep.get('type', '')})")
            lines.append("")

        # Cloud Storage Findings
        if "cloud_storage" in self.scan_data:
            lines.append("CLOUD STORAGE & BUCKET AUDIT")
            lines.append("-" * 40)
            cloud_data = self.scan_data["cloud_storage"]
            if isinstance(cloud_data, dict):
                lines.append(f"  Tested Permutations: {cloud_data.get('total_tested', 0)}")
                lines.append(f"  Open Buckets:        {cloud_data.get('open_buckets_count', 0)}")
                lines.append(f"  Protected Buckets:   {cloud_data.get('protected_buckets_count', 0)}")
                for f in cloud_data.get("findings", []):
                    if isinstance(f, dict):
                        st = "OPEN [!]" if f.get("is_open") else "PROTECTED"
                        lines.append(f"    - [{f.get('provider')}] {f.get('bucket_name')}: {st} -> {f.get('url')}")
            lines.append("")

        # SSL
        if "ssl" in self.scan_data:
            lines.append("SSL/TLS ANALYSIS")
            lines.append("-" * 40)
            ssl_data = self.scan_data["ssl"]
            if isinstance(ssl_data, dict):
                lines.append(f"  Grade: {ssl_data.get('grade', 'N/A')}")
                lines.append(f"  Protocol: {ssl_data.get('protocol', 'N/A')}")
                lines.append(f"  Cipher: {ssl_data.get('cipher_suite', 'N/A')}")
                cert = ssl_data.get("certificate", {})
                if isinstance(cert, dict):
                    lines.append(f"  Issuer: {cert.get('issuer', {}).get('common_name', 'N/A')}")
                    lines.append(f"  Expires: {cert.get('not_after', 'N/A')}")
            lines.append("")

        lines.append("=" * 70)
        lines.append("  END OF REPORT")
        lines.append("=" * 70)

        text_content = "\n".join(lines)

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text_content, encoding="utf-8")

        logger.info(f"Text report saved to [bold]{output_path}[/bold]")
        return str(path.absolute())

    def _generate_html_fallback(self) -> str:
        """Generate basic HTML report without Jinja2."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Phantom Recon Report</title>
    <style>
        body {{ background: #0a0a0f; color: #e0e0e0; font-family: 'Segoe UI', sans-serif; padding: 40px; }}
        h1 {{ color: #ff4444; text-align: center; }}
        h2 {{ color: #00bcd4; border-bottom: 1px solid #333; padding-bottom: 10px; }}
        pre {{ background: #1a1a2e; padding: 20px; border-radius: 8px; overflow-x: auto; }}
        .badge {{ padding: 4px 12px; border-radius: 4px; font-weight: bold; }}
        .critical {{ background: #d32f2f; }}
        .high {{ background: #f44336; }}
        .medium {{ background: #ff9800; color: #000; }}
        .low {{ background: #2196f3; }}
    </style>
</head>
<body>
    <h1>🔥 Phantom Recon Report</h1>
    <p style="text-align:center; color: #888;">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <h2>Raw Scan Data</h2>
    <pre>{json.dumps(self.scan_data, indent=2, default=str)}</pre>
</body>
</html>"""
