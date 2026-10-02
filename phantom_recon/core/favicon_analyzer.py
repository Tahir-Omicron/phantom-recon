"""
Phantom Recon — Favicon MurmurHash3 Technology Fingerprinting Engine (v2.1.0).

Calculates 100% Shodan & Censys-compatible MurmurHash3 (MMH3), MD5, and SHA256 hashes
of web application favicons to identify enterprise technologies, frameworks, and hidden
administrative consoles without triggering WAF rules.

⚠️ DISCLAIMER: For authorized security testing and defensive asset inventory only.
"""

import base64
from dataclasses import dataclass
import hashlib
import re
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from phantom_recon.utils.logger import get_logger

logger = get_logger(__name__)


def mmh3_32(data: bytes, seed: int = 0) -> int:
    """
    Pure Python 32-bit x86 signed MurmurHash3 algorithm.
    Produces identical hash values to C-extension mmh3.hash() and Shodan/httpx favicon hashes.
    """
    length = len(data)
    nblocks = length // 4
    h1 = seed
    c1 = 0xcc9e2d51
    c2 = 0x1b873593

    for i in range(0, nblocks * 4, 4):
        k1 = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24)
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF

        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xe6546b64) & 0xFFFFFFFF

    tail = data[nblocks * 4:]
    k1 = 0
    tlen = len(tail)
    if tlen >= 3:
        k1 ^= tail[2] << 16
    if tlen >= 2:
        k1 ^= tail[1] << 8
    if tlen >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85ebca6b) & 0xFFFFFFFF
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
    h1 ^= (h1 >> 16)

    # Convert to 32-bit signed integer
    if h1 >= 0x80000000:
        h1 -= 0x100000000
    return h1


def calculate_shodan_favicon_hash(raw_bytes: bytes) -> int:
    """
    Computes Shodan-compatible favicon MurmurHash3.
    Shodan encodes bytes using MIME base64 with newlines every 76 characters.
    """
    b64_encoded = base64.encodebytes(raw_bytes)
    return mmh3_32(b64_encoded)


# Verified MMH3 Signatures Database for Enterprise & Web Stacks
FAVICON_SIGNATURES: dict[int, dict[str, str]] = {
    # Spring Boot Actuator / Web
    116323821: {"name": "Spring Boot", "category": "Framework / Java", "vendor": "VMware / Spring"},
    -127886975: {"name": "Spring Boot", "category": "Framework / Java", "vendor": "VMware / Spring"},
    -1305273827: {"name": "Spring Boot", "category": "Framework / Java", "vendor": "VMware / Spring"},

    # CI/CD & DevOps
    81586312: {"name": "Jenkins CI/CD", "category": "DevOps / Automation", "vendor": "Jenkins"},
    1278323651: {"name": "GitLab", "category": "DevOps / Git Portal", "vendor": "GitLab"},
    -2052399901: {"name": "GitLab", "category": "DevOps / Git Portal", "vendor": "GitLab"},
    -305179312: {"name": "Atlassian Jira", "category": "Issue Tracker / Enterprise", "vendor": "Atlassian"},
    999357577: {"name": "Atlassian Confluence", "category": "Knowledge Base", "vendor": "Atlassian"},
    -1577717650: {"name": "Grafana Dashboard", "category": "Monitoring & Observability", "vendor": "Grafana Labs"},
    -1011409277: {"name": "Kibana Console", "category": "Log Analytics", "vendor": "Elasticsearch"},

    # VPN & Network Firewalls
    945408572: {"name": "Fortinet FortiGate SSL-VPN", "category": "Network Gateway / VPN", "vendor": "Fortinet"},
    -719128607: {"name": "Fortinet FortiGate Web Management", "category": "Network Gateway / Admin", "vendor": "Fortinet"},
    -2046890257: {"name": "Palo Alto GlobalProtect VPN", "category": "Network Gateway / VPN", "vendor": "Palo Alto Networks"},
    -1089874836: {"name": "cPanel / WebHost Manager", "category": "Server Control Panel", "vendor": "cPanel"},
    -1049755225: {"name": "Webmin Admin Console", "category": "Server Control Panel", "vendor": "Webmin"},

    # Databases & Identity
    1465243176: {"name": "phpMyAdmin", "category": "Database Administration", "vendor": "phpMyAdmin"},
    -1228516053: {"name": "phpMyAdmin", "category": "Database Administration", "vendor": "phpMyAdmin"},
    -866416568: {"name": "Keycloak IAM", "category": "Identity & Access Management", "vendor": "Red Hat"},
    -1823901334: {"name": "Joomla CMS", "category": "Content Management", "vendor": "Joomla"},

    # Web Servers & Frameworks
    -1345437690: {"name": "Apache Tomcat", "category": "Java Application Server", "vendor": "Apache Software Foundation"},
    -1588763857: {"name": "Django Administration", "category": "Web Framework / Python", "vendor": "Django Software Foundation"},
    -1444555374: {"name": "WordPress", "category": "Content Management", "vendor": "Automattic"},
    -1854619371: {"name": "Drupal", "category": "Content Management", "vendor": "Drupal Community"},
    -732386348: {"name": "nginx Welcome Page", "category": "Web Server", "vendor": "F5 / nginx"},
    -1498104595: {"name": "Apache Web Server", "category": "Web Server", "vendor": "Apache Software Foundation"},
}


@dataclass
class FaviconResult:
    """Structured favicon fingerprinting result."""
    target_url: str
    favicon_url: str
    mmh3_hash: int
    md5_hash: str
    sha256_hash: str
    identified_tech: Optional[str] = None
    category: Optional[str] = None
    vendor: Optional[str] = None
    confidence: str = "LOW"
    shodan_query: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "favicon_url": self.favicon_url,
            "mmh3_hash": self.mmh3_hash,
            "md5_hash": self.md5_hash,
            "sha256_hash": self.sha256_hash,
            "identified_tech": self.identified_tech,
            "category": self.category,
            "vendor": self.vendor,
            "confidence": self.confidence,
            "shodan_query": self.shodan_query,
        }


class FaviconAnalyzer:
    """
    High-precision Favicon MurmurHash3 Fingerprinting Engine.
    Discovers icons from HTML tags or common root paths and correlates with vendor signatures.
    """

    def __init__(self, target_url: str, timeout: float = 5.0, verify_ssl: bool = False):
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            self.target_url = f"https://{target_url}"
        else:
            self.target_url = target_url.rstrip("/")

        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 PhantomRecon/2.1.0"
            ),
            "Accept": "image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
        })

    def _discover_favicon_url(self) -> list[str]:
        """Discover potential favicon URLs from HTML markup and standard locations."""
        candidates = []

        try:
            resp = self.session.get(self.target_url, timeout=self.timeout, allow_redirects=True)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                for link in soup.find_all("link"):
                    rel = [r.lower() for r in link.get("rel", [])]
                    if any("icon" in r for r in rel):
                        href = link.get("href")
                        if href:
                            abs_url = urljoin(self.target_url, href)
                            if abs_url not in candidates:
                                candidates.append(abs_url)
        except requests.RequestException:
            pass

        # Always include default fallback paths
        default_ico = urljoin(self.target_url + "/", "favicon.ico")
        if default_ico not in candidates:
            candidates.append(default_ico)

        return candidates

    def analyze(self) -> Optional[FaviconResult]:
        """
        Download the favicon, calculate MMH3 and crypto hashes, and identify technology stack.
        """
        candidates = self._discover_favicon_url()
        for cand_url in candidates:
            try:
                resp = self.session.get(cand_url, timeout=self.timeout, allow_redirects=True)
                if resp.status_code == 200 and len(resp.content) > 16:
                    raw_content = resp.content

                    # Check that response looks like an image/icon, not a generic HTML 404 page
                    content_type = resp.headers.get("Content-Type", "").lower()
                    if "html" in content_type and b"<html" in raw_content.lower()[:200]:
                        continue

                    # Calculate hashes
                    mmh3_val = calculate_shodan_favicon_hash(raw_content)
                    md5_val = hashlib.md5(raw_content).hexdigest()
                    sha256_val = hashlib.sha256(raw_content).hexdigest()

                    identified = None
                    category = None
                    vendor = None
                    confidence = "CONFIRMED" if mmh3_val in FAVICON_SIGNATURES else "FINGERPRINTED"

                    if mmh3_val in FAVICON_SIGNATURES:
                        sig = FAVICON_SIGNATURES[mmh3_val]
                        identified = sig["name"]
                        category = sig["category"]
                        vendor = sig["vendor"]

                    return FaviconResult(
                        target_url=self.target_url,
                        favicon_url=cand_url,
                        mmh3_hash=mmh3_val,
                        md5_hash=md5_val,
                        sha256_hash=sha256_val,
                        identified_tech=identified,
                        category=category,
                        vendor=vendor,
                        confidence=confidence,
                        shodan_query=f"http.favicon.hash:{mmh3_val}",
                    )
            except requests.RequestException as e:
                logger.debug(f"Failed to fetch favicon candidate {cand_url}: {e}")

        return None
