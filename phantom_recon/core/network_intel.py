"""
Phantom Recon — Autonomous ASN & BGP Network Intelligence Engine (v2.3.0).

Performs autonomous reconnaissance of BGP routing prefixes, Autonomous System Numbers (ASN),
Regional Internet Registry (RIR) allocations, Reverse DNS (PTR), and IP Geolocation.
Uses Team Cymru DNS-based mapping (RFC standard) with failover to public RDAP and IP endpoints.

⚠️ DISCLAIMER: For authorized security testing & defensive reconnaissance only.
"""

from dataclasses import dataclass, field
from datetime import datetime
import ipaddress
import re
import socket
from typing import Any, Optional
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from phantom_recon.utils.logger import get_logger, console
from phantom_recon.utils.validators import validate_ip, validate_domain

logger = get_logger(__name__)

# Known Cloud and CDN Provider ASNs for infrastructure classification
CLOUD_CDN_ASNS: dict[str, str] = {
    "13335": "Cloudflare, Inc.",
    "209242": "Cloudflare London",
    "15169": "Google LLC",
    "396982": "Google Cloud",
    "16509": "Amazon.com, Inc. (AWS)",
    "14618": "Amazon.com, Inc. (AWS)",
    "8075": "Microsoft Corporation (Azure)",
    "8068": "Microsoft Corporation",
    "20940": "Akamai Technologies, Inc.",
    "16625": "Akamai Technologies, Inc.",
    "54113": "Fastly, Inc.",
    "14061": "DigitalOcean, LLC",
    "24940": "Hetzner Online GmbH",
    "16276": "OVH SAS",
    "63949": "Linode, LLC (Akamai)",
    "31898": "Oracle Cloud Infrastructure",
}


@dataclass
class NetworkIntelResult:
    """Standardized BGP routing and network intelligence data."""
    target: str
    ip: str = ""
    hostname: str = ""
    ptr: str = ""
    asn: str = ""
    as_name: str = ""
    bgp_prefix: str = ""
    rir: str = ""
    country: str = ""
    city: str = ""
    region: str = ""
    isp: str = ""
    is_cloud: bool = False
    cloud_provider: str = ""
    allocated_date: str = ""
    ptr_matches_target: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "ip": self.ip,
            "hostname": self.hostname,
            "ptr": self.ptr,
            "asn": self.asn,
            "as_name": self.as_name,
            "bgp_prefix": self.bgp_prefix,
            "rir": self.rir,
            "country": self.country,
            "city": self.city,
            "region": self.region,
            "isp": self.isp,
            "is_cloud": self.is_cloud,
            "cloud_provider": self.cloud_provider,
            "allocated_date": self.allocated_date,
            "ptr_matches_target": self.ptr_matches_target,
            "details": self.details,
        }


class NetworkIntelligence:
    """
    Autonomous ASN & BGP Network Intelligence Reconnaissance Engine.
    
    Discovers IP address routing prefixes, ASNs, Reverse DNS, and network topology.
    """

    def __init__(self, target: str, timeout: float = 6.0):
        self.raw_target = target.strip()
        self.timeout = timeout
        self.host = self._normalize_target(self.raw_target)

    def _normalize_target(self, target: str) -> str:
        """Extract clean hostname or IP from target input."""
        if target.startswith(("http://", "https://")):
            parsed = urlparse(target)
            return parsed.netloc.split(":")[0]
        return target.split(":")[0].strip().rstrip("/")

    def _resolve_ip(self, host: str) -> Optional[str]:
        """Resolve target host to an IPv4 address."""
        if validate_ip(host):
            return host
        try:
            return socket.gethostbyname(host)
        except (socket.gaierror, socket.herror, OSError):
            return None

    def _get_reverse_dns(self, ip: str) -> str:
        """Perform reverse DNS PTR lookup."""
        try:
            ptr_name, _, _ = socket.gethostbyaddr(ip)
            return ptr_name.strip()
        except (socket.herror, socket.gaierror, OSError):
            return ""

    def _lookup_cymru_dns(self, ip: str) -> dict[str, str]:
        """
        Query Team Cymru DNS service for BGP route and ASN.
        RFC-standard, zero rate-limit, millisecond latency network mapping.
        """
        data: dict[str, str] = {
            "asn": "",
            "as_name": "",
            "bgp_prefix": "",
            "country": "",
            "rir": "",
            "allocated_date": "",
        }
        try:
            import dns.resolver

            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            # Use reliable DNS failover
            resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

            # 1. Reverse IP for route query: 8.8.8.8 -> 8.8.8.8.origin.asn.cymru.com
            octets = ip.split(".")
            if len(octets) != 4:
                return data
            rev_ip = ".".join(reversed(octets))
            query_name = f"{rev_ip}.origin.asn.cymru.com"

            answers = resolver.resolve(query_name, "TXT")
            for rdata in answers:
                text = rdata.to_text().strip('"')
                parts = [p.strip() for p in text.split("|")]
                if len(parts) >= 5:
                    raw_asn = parts[0]
                    # Handle multi-origin ASN if space-separated
                    asn_num = raw_asn.split()[0]
                    data["asn"] = f"AS{asn_num}"
                    data["bgp_prefix"] = parts[1]
                    data["country"] = parts[2]
                    data["rir"] = parts[3].upper()
                    data["allocated_date"] = parts[4]
                    break

            # 2. Query AS Name if ASN is found: AS15169.asn.cymru.com
            if data["asn"]:
                asn_clean = data["asn"].replace("AS", "")
                as_name_query = f"AS{asn_clean}.asn.cymru.com"
                try:
                    as_answers = resolver.resolve(as_name_query, "TXT")
                    for rdata in as_answers:
                        text = rdata.to_text().strip('"')
                        parts = [p.strip() for p in text.split("|")]
                        if len(parts) >= 5:
                            data["as_name"] = parts[4]
                            break
                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"Team Cymru DNS query failed: {e}")

        return data

    def _lookup_http_fallback(self, ip: str) -> dict[str, Any]:
        """
        Fallback HTTP lookup via ip-api or RDAP for geolocation & ISP enrichment.
        """
        fallback_data: dict[str, Any] = {}
        try:
            resp = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,isp,org,as,query",
                timeout=min(self.timeout, 4.0),
            )
            if resp.status_code == 200:
                js = resp.json()
                if js.get("status") == "success":
                    fallback_data = {
                        "country": js.get("country", ""),
                        "country_code": js.get("countryCode", ""),
                        "city": js.get("city", ""),
                        "region": js.get("regionName", ""),
                        "isp": js.get("isp", ""),
                        "org": js.get("org", ""),
                        "as_str": js.get("as", ""),
                    }
        except Exception as e:
            logger.debug(f"HTTP network intel fallback failed: {e}")

        return fallback_data

    def analyze(self) -> NetworkIntelResult:
        """
        Execute comprehensive ASN, BGP routing, and network perimeter analysis.
        """
        logger.info(f"Gathering BGP & Network Intelligence for [bold magenta]{self.host}[/bold magenta]")

        ip = self._resolve_ip(self.host)
        if not ip:
            logger.warning(f"Unable to resolve host '{self.host}' to an IP address.")
            return NetworkIntelResult(
                target=self.host,
                hostname=self.host,
                details={"error": f"Failed to resolve hostname '{self.host}'"},
            )

        # 1. Reverse DNS (PTR)
        ptr = self._get_reverse_dns(ip)

        # 2. Cymru DNS BGP lookup (primary)
        cymru = self._lookup_cymru_dns(ip)

        # 3. HTTP Geolocation / ISP fallback & enrichment
        http_data = self._lookup_http_fallback(ip)

        # Merge findings
        asn = cymru.get("asn") or ""
        as_name = cymru.get("as_name") or ""
        bgp_prefix = cymru.get("bgp_prefix") or ""
        rir = cymru.get("rir") or ""
        country = cymru.get("country") or http_data.get("country_code") or ""
        city = http_data.get("city") or ""
        region = http_data.get("region") or ""
        isp = http_data.get("isp") or http_data.get("org") or ""
        allocated = cymru.get("allocated_date") or ""

        # If ASN wasn't in Cymru, extract from HTTP fallback: 'AS203622 GSP LLC'
        if not asn and http_data.get("as_str"):
            as_match = re.search(r"(AS\d+)\s*(.*)", http_data["as_str"])
            if as_match:
                asn = as_match.group(1)
                if not as_name:
                    as_name = as_match.group(2).strip()

        # Classify Cloud / CDN infrastructure
        is_cloud = False
        cloud_provider = ""
        asn_clean = asn.replace("AS", "")
        if asn_clean in CLOUD_CDN_ASNS:
            is_cloud = True
            cloud_provider = CLOUD_CDN_ASNS[asn_clean]
        else:
            combined_text = f"{as_name} {isp}".lower()
            for kw, prov in [
                ("cloudflare", "Cloudflare"),
                ("amazon", "Amazon AWS"),
                ("aws", "Amazon AWS"),
                ("google", "Google Cloud"),
                ("microsoft", "Microsoft Azure"),
                ("akamai", "Akamai"),
                ("fastly", "Fastly"),
                ("digitalocean", "DigitalOcean"),
                ("hetzner", "Hetzner Online"),
                ("ovh", "OVH"),
            ]:
                if kw in combined_text:
                    is_cloud = True
                    cloud_provider = prov
                    break

        ptr_matches_target = False
        if ptr and self.host:
            ptr_clean = ptr.lower().rstrip(".")
            host_clean = self.host.lower().rstrip(".")
            if ptr_clean == host_clean or ptr_clean.endswith(f".{host_clean}") or host_clean.endswith(f".{ptr_clean}"):
                ptr_matches_target = True

        result = NetworkIntelResult(
            target=self.host,
            ip=ip,
            hostname=self.host,
            ptr=ptr,
            asn=asn,
            as_name=as_name,
            bgp_prefix=bgp_prefix,
            rir=rir,
            country=country,
            city=city,
            region=region,
            isp=isp,
            is_cloud=is_cloud,
            cloud_provider=cloud_provider,
            allocated_date=allocated,
            ptr_matches_target=ptr_matches_target,
            details={
                "ip_version": 4 if ":" not in ip else 6,
                "cymru_resolved": bool(cymru.get("asn")),
                "http_fallback_used": bool(http_data),
            },
        )

        return result
