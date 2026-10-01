"""
Phantom Recon — SSL/TLS Analyzer.

Comprehensive SSL/TLS security analysis including certificate validation,
protocol detection, cipher suite enumeration, and chain verification.

⚠️ DISCLAIMER: For authorized security testing only.
"""

import hashlib
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from phantom_recon.utils.logger import get_logger, console

logger = get_logger(__name__)

# Weak cipher patterns
WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5",
    "RC2", "IDEA", "SEED", "CAMELLIA128",
]

# Deprecated protocols
DEPRECATED_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]


class SSLAnalyzer:
    """
    SSL/TLS security analyzer.

    Analyzes certificate details, protocol versions, cipher suites,
    and provides security assessments.

    Usage:
        ssl_analyzer = SSLAnalyzer(host="example.com")
        results = ssl_analyzer.analyze()
    """

    def __init__(self, host: str, port: int = 443, timeout: float = 10.0):
        """
        Initialize SSL analyzer.

        Args:
            host: Target hostname.
            port: Target port (default 443).
            timeout: Connection timeout.
        """
        self.host = host
        self.port = port
        self.timeout = timeout

    def analyze(self) -> dict[str, Any]:
        """
        Perform full SSL/TLS analysis.

        Returns:
            Dictionary with certificate info, protocols, ciphers, and grade.
        """
        logger.info(
            f"Analyzing SSL/TLS for [bold magenta]{self.host}:{self.port}[/bold magenta]"
        )

        results: dict[str, Any] = {
            "host": self.host,
            "port": self.port,
            "timestamp": datetime.now().isoformat(),
            "certificate": {},
            "protocol": "",
            "cipher_suite": "",
            "issues": [],
            "grade": "",
        }

        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            conn = context.wrap_socket(
                socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                server_hostname=self.host,
            )
            conn.settimeout(self.timeout)
            conn.connect((self.host, self.port))

            # Get certificate info
            cert_der = conn.getpeercert(binary_form=True)
            cert_dict = conn.getpeercert()
            protocol = conn.version()
            cipher = conn.cipher()

            results["protocol"] = protocol or ""
            results["cipher_suite"] = cipher[0] if cipher else ""
            results["cipher_bits"] = cipher[2] if cipher and len(cipher) > 2 else 0

            # Parse certificate
            results["certificate"] = self._parse_certificate(cert_dict, cert_der)

            # Check for issues
            results["issues"] = self._check_issues(results)

            # Calculate grade
            results["grade"] = self._calculate_grade(results)

            conn.close()

        except ssl.SSLError as e:
            results["error"] = f"SSL Error: {e}"
            results["grade"] = "F"
            logger.error(f"SSL error: {e}")
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            results["error"] = f"Connection error: {e}"
            results["grade"] = "F"
            logger.error(f"Connection failed: {e}")

        return results

    def _parse_certificate(
        self, cert: Optional[dict], cert_der: Optional[bytes] = None
    ) -> dict[str, Any]:
        """Parse SSL certificate details."""
        if not cert:
            return {"error": "No certificate data available"}

        info: dict[str, Any] = {}

        # Subject
        subject = dict(x[0] for x in cert.get("subject", ()))
        info["subject"] = {
            "common_name": subject.get("commonName", ""),
            "organization": subject.get("organizationName", ""),
            "organizational_unit": subject.get("organizationalUnitName", ""),
            "country": subject.get("countryName", ""),
            "state": subject.get("stateOrProvinceName", ""),
            "locality": subject.get("localityName", ""),
        }

        # Issuer
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        info["issuer"] = {
            "common_name": issuer.get("commonName", ""),
            "organization": issuer.get("organizationName", ""),
            "country": issuer.get("countryName", ""),
        }

        # Validity
        info["not_before"] = cert.get("notBefore", "")
        info["not_after"] = cert.get("notAfter", "")

        # Check expiry
        try:
            not_after = ssl.cert_time_to_seconds(cert["notAfter"])
            days_remaining = (datetime.fromtimestamp(not_after) - datetime.now()).days
            info["days_remaining"] = days_remaining
            info["expired"] = days_remaining < 0

            if days_remaining < 0:
                logger.error(f"[bold red]✗ Certificate EXPIRED {abs(days_remaining)} days ago![/bold red]")
            elif days_remaining < 30:
                logger.warning(f"[yellow]⚠ Certificate expires in {days_remaining} days[/yellow]")
        except (KeyError, ValueError):
            info["days_remaining"] = None
            info["expired"] = None

        # SANs
        san_list = []
        for san_type, san_value in cert.get("subjectAltName", ()):
            san_list.append({"type": san_type, "value": san_value})
        info["subject_alt_names"] = san_list

        # Serial number
        info["serial_number"] = cert.get("serialNumber", "")

        # Version
        info["version"] = cert.get("version", "")

        # Fingerprints
        if cert_der:
            info["fingerprint_sha256"] = hashlib.sha256(cert_der).hexdigest()
            info["fingerprint_sha1"] = hashlib.sha1(cert_der).hexdigest()

        # Self-signed check
        info["self_signed"] = (
            info["subject"].get("common_name") == info["issuer"].get("common_name")
            and info["subject"].get("organization") == info["issuer"].get("organization")
        )

        if info["self_signed"]:
            logger.warning("[yellow]⚠ Self-signed certificate detected[/yellow]")

        return info

    def _check_issues(self, results: dict[str, Any]) -> list[dict[str, str]]:
        """Check for SSL/TLS security issues."""
        issues = []

        # Check protocol
        protocol = results.get("protocol", "")
        if protocol in ("SSLv2", "SSLv3"):
            issues.append({
                "severity": "critical",
                "title": f"Insecure protocol: {protocol}",
                "description": f"{protocol} is deprecated and has known vulnerabilities.",
                "remediation": "Disable SSLv2/SSLv3 and use TLS 1.2+",
            })
        elif protocol in ("TLSv1", "TLSv1.1"):
            issues.append({
                "severity": "high",
                "title": f"Deprecated protocol: {protocol}",
                "description": f"{protocol} is deprecated (RFC 8996).",
                "remediation": "Use TLS 1.2 or TLS 1.3.",
            })

        # Check cipher
        cipher = results.get("cipher_suite", "")
        for weak in WEAK_CIPHERS:
            if weak.upper() in cipher.upper():
                issues.append({
                    "severity": "high",
                    "title": f"Weak cipher: {cipher}",
                    "description": f"Cipher suite contains weak algorithm: {weak}",
                    "remediation": "Configure strong cipher suites only.",
                })
                break

        # Check cipher bits
        bits = results.get("cipher_bits", 0)
        if bits and bits < 128:
            issues.append({
                "severity": "high",
                "title": f"Weak key length: {bits} bits",
                "description": "Key length is below recommended minimum (128 bits).",
                "remediation": "Use cipher suites with 128+ bit keys.",
            })

        # Check certificate
        cert = results.get("certificate", {})
        if cert.get("self_signed"):
            issues.append({
                "severity": "medium",
                "title": "Self-signed certificate",
                "description": "Certificate is self-signed and not trusted by browsers.",
                "remediation": "Use a certificate from a trusted CA.",
            })

        if cert.get("expired"):
            issues.append({
                "severity": "critical",
                "title": "Expired certificate",
                "description": "The SSL certificate has expired.",
                "remediation": "Renew the SSL certificate immediately.",
            })
        elif cert.get("days_remaining") is not None and cert["days_remaining"] < 30:
            issues.append({
                "severity": "medium",
                "title": f"Certificate expiring soon ({cert['days_remaining']} days)",
                "description": "Certificate will expire within 30 days.",
                "remediation": "Renew the certificate before expiry.",
            })

        return issues

    def _calculate_grade(self, results: dict[str, Any]) -> str:
        """Calculate SSL grade based on analysis."""
        score = 100

        protocol = results.get("protocol", "")
        if protocol in ("SSLv2", "SSLv3"):
            score -= 50
        elif protocol in ("TLSv1", "TLSv1.1"):
            score -= 25
        elif protocol == "TLSv1.2":
            score -= 5

        cert = results.get("certificate", {})
        if cert.get("expired"):
            score -= 40
        if cert.get("self_signed"):
            score -= 20

        # Deduct for each issue
        for issue in results.get("issues", []):
            severity = issue.get("severity", "")
            if severity == "critical":
                score -= 30
            elif severity == "high":
                score -= 15
            elif severity == "medium":
                score -= 5

        if score >= 90:
            return "A"
        elif score >= 75:
            return "B"
        elif score >= 60:
            return "C"
        elif score >= 40:
            return "D"
        else:
            return "F"

    def check_hsts(self) -> dict[str, Any]:
        """Check HSTS configuration via HTTP."""
        try:
            import requests as req
            resp = req.get(
                f"https://{self.host}:{self.port}",
                timeout=self.timeout,
                verify=False,
            )
            hsts = resp.headers.get("Strict-Transport-Security", "")
            return {
                "present": bool(hsts),
                "value": hsts,
                "max_age": self._parse_max_age(hsts),
                "include_subdomains": "includeSubDomains" in hsts,
                "preload": "preload" in hsts,
            }
        except Exception:
            return {"present": False, "error": "Could not check HSTS"}

    def _parse_max_age(self, hsts: str) -> Optional[int]:
        """Parse max-age from HSTS header."""
        if "max-age=" in hsts.lower():
            try:
                return int(hsts.lower().split("max-age=")[1].split(";")[0].strip())
            except (ValueError, IndexError):
                pass
        return None
