"""
Phantom Recon — Report Generator.

Generates professional HTML, JSON, and plain text reports from scan data
with severity-sorted findings and remediation recommendations.

⚠️ DISCLAIMER: For authorized security testing only.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

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
                "version": "1.0.0",
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
        lines.append(f"  Tool Version: 1.0.0")
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
            lines.append("VULNERABILITIES")
            lines.append("-" * 40)
            for i, vuln in enumerate(vulns, 1):
                if isinstance(vuln, dict):
                    severity = vuln.get("severity", "info").upper()
                    title = vuln.get("title", "Unknown")
                    desc = vuln.get("description", "")
                    remedy = vuln.get("remediation", "")
                    lines.append(f"  [{severity}] {title}")
                    lines.append(f"    Description: {desc}")
                    if remedy:
                        lines.append(f"    Remediation: {remedy}")
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
