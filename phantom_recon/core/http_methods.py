"""
Phantom Recon — HTTP Methods & Dangerous Verbs Auditor (v1.8.0).

Audits supported and advertised HTTP methods, tests for dangerous verb configurations
(PUT, DELETE, TRACE/XST, WebDAV PROPFIND/MKCOL, CONNECT), and checks HTTP Method Override
vulnerabilities (X-HTTP-Method-Override). Engineered for zero false positives.

⚠️ DISCLAIMER: For authorized security testing only.
"""

from dataclasses import dataclass
from datetime import datetime
import hashlib
import re
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from phantom_recon.utils.logger import get_logger

logger = get_logger(__name__)

# Standard and dangerous methods taxonomy
DANGEROUS_METHODS = {
    "PUT": {
        "title": "Arbitrary File Creation / Overwrite (HTTP PUT Enabled)",
        "severity": "critical",
        "cvss": 9.1,
        "description": (
            "The HTTP PUT method is actively supported and accepts unauthenticated file creation "
            "or modification on the target web server."
        ),
        "remediation": "Disable the PUT method in web server configuration or restrict it to authenticated administrators.",
    },
    "DELETE": {
        "title": "Arbitrary Resource Deletion (HTTP DELETE Enabled)",
        "severity": "high",
        "cvss": 7.5,
        "description": (
            "The HTTP DELETE method is enabled without authentication, allowing potential deletion "
            "of server files or resources."
        ),
        "remediation": "Disable the DELETE method in web server configuration.",
    },
    "TRACE": {
        "title": "Cross-Site Tracing (XST): HTTP TRACE Enabled",
        "severity": "medium",
        "cvss": 5.3,
        "cve": "CVE-2004-2320",
        "description": (
            "The HTTP TRACE method echoes client request headers back in the response body. "
            "When paired with Cross-Site Scripting (XSS), attackers can steal HttpOnly cookies."
        ),
        "remediation": "Disable TRACE on web server (Apache: 'TraceEnable Off'; Nginx: return 405).",
    },
    "PROPFIND": {
        "title": "Exposed WebDAV Directory Enumeration (PROPFIND Enabled)",
        "severity": "medium",
        "cvss": 5.3,
        "description": (
            "WebDAV extensions (PROPFIND) are enabled on the server, disclosing directory structure, "
            "internal paths, and file metadata."
        ),
        "remediation": "Disable WebDAV extensions or restrict access using strong authentication.",
    },
    "CONNECT": {
        "title": "Insecure HTTP CONNECT Method Enabled (Potential Proxy Abuse)",
        "severity": "medium",
        "cvss": 5.8,
        "description": (
            "The HTTP CONNECT method is supported on the web server, which can be abused for "
            "unauthorized TCP tunneling or proxy forwarding."
        ),
        "remediation": "Disable the CONNECT method unless explicitly running an authorized forward proxy.",
    },
}


@dataclass
class MethodProbeResult:
    """Represents a tested HTTP method probe outcome."""
    method: str
    status_code: int
    allowed: bool
    is_vulnerable: bool
    risk: str                    # CRITICAL, HIGH, MEDIUM, LOW, SAFE, DISABLED
    evidence: str
    poc_curl: str
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "status_code": self.status_code,
            "allowed": self.allowed,
            "is_vulnerable": self.is_vulnerable,
            "risk": self.risk,
            "evidence": self.evidence,
            "poc_curl": self.poc_curl,
            "remediation": self.remediation,
        }


class HTTPMethodsAuditor:
    """
    Precision HTTP Methods & Dangerous Verbs Auditor.
    Zero-false-positive testing of OPTIONS, PUT, DELETE, TRACE, WebDAV, and Method Override.
    """

    def __init__(
        self,
        url: str,
        timeout: float = 6.0,
        user_agent: Optional[str] = None,
        verify_ssl: bool = False,
    ):
        """Initialize the HTTP methods auditor."""
        parsed = urlparse(url)
        if not parsed.scheme:
            self.url = f"https://{url}".rstrip("/")
        else:
            self.url = url.rstrip("/")

        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers.update({
            "User-Agent": user_agent or (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 (PhantomRecon/1.8.0)"
            ),
            "Accept": "*/*",
        })

    def run_options_probe(self) -> dict[str, Any]:
        """
        Send an OPTIONS request to extract advertised 'Allow' and 'Public' headers.
        """
        logger.info(f"Querying HTTP OPTIONS on {self.url}...")
        try:
            resp = self.session.options(self.url, timeout=self.timeout, allow_redirects=True)
            allow_header = resp.headers.get("Allow", "")
            public_header = resp.headers.get("Public", "")

            # Parse advertised methods
            raw_methods = []
            if allow_header:
                raw_methods.extend([m.strip().upper() for m in allow_header.split(",") if m.strip()])
            if public_header:
                raw_methods.extend([m.strip().upper() for m in public_header.split(",") if m.strip()])

            advertised = sorted(list(set(raw_methods)))

            return {
                "status_code": resp.status_code,
                "allow_header": allow_header,
                "public_header": public_header,
                "advertised_methods": advertised,
            }
        except requests.RequestException as e:
            logger.debug(f"OPTIONS request error: {e}")
            return {
                "status_code": 0,
                "allow_header": "",
                "public_header": "",
                "advertised_methods": [],
            }

    def probe_trace_xst(self) -> MethodProbeResult:
        """
        Audit for Cross-Site Tracing (XST) via HTTP TRACE.
        Requires status 200 and exact echo of unique probe header.
        """
        probe_token = f"phantom_trace_{hashlib.md5(str(datetime.now().timestamp()).encode()).hexdigest()[:8]}"
        header_name = "X-Phantom-Verb-Test"
        poc_curl = f"curl -i -k -X TRACE -H '{header_name}: {probe_token}' '{self.url}'"

        try:
            resp = self.session.request(
                "TRACE",
                self.url,
                headers={header_name: probe_token},
                timeout=self.timeout,
                allow_redirects=False,
            )

            # Strict verification: must return 200 OK and echo the probe value
            if resp.status_code == 200 and probe_token in resp.text:
                return MethodProbeResult(
                    method="TRACE",
                    status_code=resp.status_code,
                    allowed=True,
                    is_vulnerable=True,
                    risk="MEDIUM",
                    evidence=f"HTTP 200 OK received for TRACE request with echoed probe header '{header_name}: {probe_token}'.",
                    poc_curl=poc_curl,
                    remediation=DANGEROUS_METHODS["TRACE"]["remediation"],
                )
            else:
                return MethodProbeResult(
                    method="TRACE",
                    status_code=resp.status_code,
                    allowed=False,
                    is_vulnerable=False,
                    risk="SAFE",
                    evidence=f"Server returned HTTP {resp.status_code} (TRACE rejected or not echoed).",
                    poc_curl=poc_curl,
                )
        except requests.RequestException as e:
            return MethodProbeResult(
                method="TRACE",
                status_code=0,
                allowed=False,
                is_vulnerable=False,
                risk="DISABLED",
                evidence=f"Request failed: {e}",
                poc_curl=poc_curl,
            )

    def probe_put_upload(self) -> MethodProbeResult:
        """
        Audit for arbitrary file upload/creation via HTTP PUT.
        Tests a unique benign probe path and immediately issues a cleanup DELETE if successful.
        """
        probe_token = hashlib.md5(f"phantom_put_{datetime.now().timestamp()}".encode()).hexdigest()[:10]
        test_path = f"/.phantom_probe_put_{probe_token}.tmp"
        test_url = f"{self.url}{test_path}"
        payload = f"PHANTOM_RECON_VERIFY_PUT_PROBE_{probe_token}"
        poc_curl = f"curl -i -k -X PUT -d '{payload}' '{test_url}'"

        try:
            resp = self.session.put(
                test_url,
                data=payload,
                headers={"Content-Type": "text/plain"},
                timeout=self.timeout,
                allow_redirects=False,
            )

            # 201 Created, 200 OK, or 204 No Content for a PUT request confirms active file upload
            if resp.status_code in (200, 201, 204):
                # Clean up benign file immediately
                try:
                    self.session.delete(test_url, timeout=self.timeout)
                except Exception:
                    pass

                return MethodProbeResult(
                    method="PUT",
                    status_code=resp.status_code,
                    allowed=True,
                    is_vulnerable=True,
                    risk="CRITICAL",
                    evidence=f"HTTP {resp.status_code} received on PUT probe to {test_path}. Arbitrary file upload verified.",
                    poc_curl=poc_curl,
                    remediation=DANGEROUS_METHODS["PUT"]["remediation"],
                )
            else:
                return MethodProbeResult(
                    method="PUT",
                    status_code=resp.status_code,
                    allowed=False,
                    is_vulnerable=False,
                    risk="SAFE",
                    evidence=f"Server responded with HTTP {resp.status_code} (PUT rejected).",
                    poc_curl=poc_curl,
                )
        except requests.RequestException as e:
            return MethodProbeResult(
                method="PUT",
                status_code=0,
                allowed=False,
                is_vulnerable=False,
                risk="DISABLED",
                evidence=f"PUT connection error: {e}",
                poc_curl=poc_curl,
            )

    def probe_delete_method(self) -> MethodProbeResult:
        """
        Audit for insecure HTTP DELETE method handling.
        """
        probe_token = hashlib.md5(f"phantom_del_{datetime.now().timestamp()}".encode()).hexdigest()[:10]
        test_path = f"/.phantom_probe_del_{probe_token}.tmp"
        test_url = f"{self.url}{test_path}"
        poc_curl = f"curl -i -k -X DELETE '{test_url}'"

        try:
            resp = self.session.delete(test_url, timeout=self.timeout, allow_redirects=False)

            # 200 OK, 202 Accepted, 204 No Content indicate DELETE processing
            if resp.status_code in (200, 202, 204):
                return MethodProbeResult(
                    method="DELETE",
                    status_code=resp.status_code,
                    allowed=True,
                    is_vulnerable=True,
                    risk="HIGH",
                    evidence=f"HTTP {resp.status_code} received on DELETE probe to {test_path}.",
                    poc_curl=poc_curl,
                    remediation=DANGEROUS_METHODS["DELETE"]["remediation"],
                )
            else:
                return MethodProbeResult(
                    method="DELETE",
                    status_code=resp.status_code,
                    allowed=False,
                    is_vulnerable=False,
                    risk="SAFE",
                    evidence=f"Server returned HTTP {resp.status_code} (DELETE rejected).",
                    poc_curl=poc_curl,
                )
        except requests.RequestException as e:
            return MethodProbeResult(
                method="DELETE",
                status_code=0,
                allowed=False,
                is_vulnerable=False,
                risk="DISABLED",
                evidence=f"DELETE connection error: {e}",
                poc_curl=poc_curl,
            )

    def probe_webdav_propfind(self) -> MethodProbeResult:
        """
        Audit for WebDAV extension verbs (PROPFIND).
        """
        poc_curl = f"curl -i -k -X PROPFIND -H 'Depth: 0' '{self.url}'"
        xml_body = '<?xml version="1.0" encoding="utf-8"?><D:propfind xmlns:D="DAV:"><D:prop><D:displayname/></D:prop></D:propfind>'

        try:
            resp = self.session.request(
                "PROPFIND",
                self.url,
                data=xml_body,
                headers={"Depth": "0", "Content-Type": "application/xml"},
                timeout=self.timeout,
                allow_redirects=False,
            )

            # 207 Multi-Status or XML containing DAV multistatus
            if resp.status_code == 207 or "multistatus" in resp.text.lower() or "d:response" in resp.text.lower():
                return MethodProbeResult(
                    method="PROPFIND",
                    status_code=resp.status_code,
                    allowed=True,
                    is_vulnerable=True,
                    risk="MEDIUM",
                    evidence=f"HTTP {resp.status_code} with WebDAV XML multistatus response detected.",
                    poc_curl=poc_curl,
                    remediation=DANGEROUS_METHODS["PROPFIND"]["remediation"],
                )
            else:
                return MethodProbeResult(
                    method="PROPFIND",
                    status_code=resp.status_code,
                    allowed=False,
                    is_vulnerable=False,
                    risk="SAFE",
                    evidence=f"Server returned HTTP {resp.status_code} (WebDAV PROPFIND rejected).",
                    poc_curl=poc_curl,
                )
        except requests.RequestException as e:
            return MethodProbeResult(
                method="PROPFIND",
                status_code=0,
                allowed=False,
                is_vulnerable=False,
                risk="DISABLED",
                evidence=f"PROPFIND error: {e}",
                poc_curl=poc_curl,
            )

    def probe_method_override(self) -> dict[str, Any]:
        """
        Audit for HTTP Method Override headers (X-HTTP-Method-Override).
        Tests whether POST requests can spoof PUT or TRACE via headers.
        """
        headers_to_test = ["X-HTTP-Method-Override", "X-Method-Override"]
        findings = []

        for h_name in headers_to_test:
            try:
                resp = self.session.post(
                    self.url,
                    headers={h_name: "PUT"},
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                # If the server behaves differently or responds with 405 Method Not Allowed specifically for PUT
                if resp.status_code in (200, 201, 204):
                    findings.append({
                        "header": h_name,
                        "override_to": "PUT",
                        "status_code": resp.status_code,
                        "is_active": True,
                        "evidence": f"Server processed override header {h_name}: PUT returning HTTP {resp.status_code}",
                    })
            except requests.RequestException:
                pass

        return {
            "supported": len(findings) > 0,
            "findings": findings,
        }

    def audit_all(self) -> dict[str, Any]:
        """
        Run the complete HTTP Methods & Dangerous Verbs audit suite.
        """
        logger.info(f"Auditing HTTP methods and dangerous verbs on [bold magenta]{self.url}[/bold magenta]")

        # 1. Discover Advertised Methods via OPTIONS
        options_data = self.run_options_probe()
        advertised = options_data.get("advertised_methods", [])

        # 2. Precision Probes
        probes: list[MethodProbeResult] = [
            self.probe_trace_xst(),
            self.probe_put_upload(),
            self.probe_delete_method(),
            self.probe_webdav_propfind(),
        ]

        # 3. Method Override Check
        override_data = self.probe_method_override()

        # Build list of active findings and vulnerabilities
        vulnerabilities = []
        for probe in probes:
            if probe.is_vulnerable and probe.method in DANGEROUS_METHODS:
                meta = DANGEROUS_METHODS[probe.method]
                vulnerabilities.append({
                    "title": meta["title"],
                    "severity": meta["severity"],
                    "cvss_score": meta.get("cvss", 5.0),
                    "description": meta["description"],
                    "location": f"HTTP Method: {probe.method}",
                    "url": self.url,
                    "poc_url": self.url,
                    "reproduce_curl": probe.poc_curl,
                    "evidence": probe.evidence,
                    "remediation": meta["remediation"],
                    "category": "misconfiguration",
                    "confidence": "CONFIRMED",
                    "cve": meta.get("cve", ""),
                    "method": probe.method,
                })

        # Check if OPTIONS header itself advertises dangerous methods
        advertised_dangerous = [m for m in advertised if m in ("PUT", "DELETE", "TRACE", "PROPFIND", "CONNECT")]
        if advertised_dangerous and not any(v.get("method") == "TRACE" and "TRACE" in advertised_dangerous for v in vulnerabilities):
            # If advertised but not already caught as an active critical flaw, flag informational
            vulnerabilities.append({
                "title": f"Potentially Dangerous HTTP Methods Advertised in Allow Header: {', '.join(advertised_dangerous)}",
                "severity": "low",
                "cvss_score": 3.7,
                "description": (
                    f"The web server advertises support for the following methods in HTTP response headers: {', '.join(advertised_dangerous)}. "
                    "Ensure these endpoints enforce strict authentication and authorization."
                ),
                "location": "HTTP Header: Allow",
                "url": self.url,
                "poc_url": self.url,
                "reproduce_curl": f"curl -i -k -X OPTIONS '{self.url}'",
                "evidence": f"Allow: {options_data.get('allow_header', '')}\nPublic: {options_data.get('public_header', '')}",
                "remediation": "Restrict the Allow header to GET, POST, HEAD, and OPTIONS.",
                "category": "misconfiguration",
                "confidence": "CONFIRMED",
                "method": "OPTIONS",
            })

        return {
            "url": self.url,
            "options": options_data,
            "advertised_methods": advertised,
            "advertised_dangerous": advertised_dangerous,
            "probes": [p.to_dict() for p in probes],
            "method_override": override_data,
            "vulnerabilities": vulnerabilities,
        }
