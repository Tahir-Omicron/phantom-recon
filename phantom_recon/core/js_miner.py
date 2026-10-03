"""
Phantom Recon — Client-Side JavaScript Route & API Endpoint Extractor (v2.3.0).

Automated static analysis of client-side JavaScript bundles and inline scripts
to discover hidden REST API routes, microservice endpoints, cloud storage URLs,
and administrative paths (LinkFinder / Katana architecture).

⚠️ DISCLAIMER: For authorized security testing & defensive reconnaissance only.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
import re
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from phantom_recon.utils.logger import get_logger, console

logger = get_logger(__name__)

# Heuristic regular expressions for endpoint mining (LinkFinder-inspired)
REGEX_API_ROUTES = re.compile(
    r"""(?:["'`])(\/(?:api(?:/v[0-9]+)?|v[0-9]+|graphql|rest|auth|oauth|webhook)[a-zA-Z0-9_\-\./?=&]*)(?:["'`])""",
    re.IGNORECASE,
)

REGEX_GENERAL_PATHS = re.compile(
    r"""(?:["'`])(\/(?:[a-zA-Z0-9_\-]+(?:\.[a-zA-Z0-9]+)?\/)+[a-zA-Z0-9_\-\./?=&]*)(?:["'`])"""
)

REGEX_CLOUD_STORAGE = re.compile(
    r"""https?://(?:[a-zA-Z0-9_\-\.]+\.s3(?:\.[a-zA-Z0-9_\-]+)?\.amazonaws\.com|storage\.googleapis\.com/[a-zA-Z0-9_\-\.]+|[a-zA-Z0-9_\-\.]+\.blob\.core\.windows\.net/[a-zA-Z0-9_\-\.]+)[a-zA-Z0-9_\-\./]*""",
    re.IGNORECASE,
)

REGEX_PARAMETERS = re.compile(
    r"""[?&]([a-zA-Z_][a-zA-Z0-9_]{1,30})=""",
)

# Common extensions to filter out from discovered API routes
IGNORE_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".woff", ".woff2",
    ".ttf", ".eot", ".mp4", ".webm", ".mp3", ".wav", ".map",
)

# High-risk sensitive keywords in route paths
SENSITIVE_KEYWORDS = [
    "admin", "administrator", "internal", "debug", "config", "configuration",
    "secret", "private", "backup", "dump", "metrics", "actuator", "env",
    "staging", "manage/", "/manage", "/root", "token", "auth/admin",
    "/dev/", "dev-", "/test/", "test-",
]


@dataclass
class JSEndpointResult:
    """Consolidated findings from JavaScript static endpoint analysis."""
    url: str
    scripts_analyzed: int = 0
    api_routes: list[str] = field(default_factory=list)
    sensitive_endpoints: list[str] = field(default_factory=list)
    cloud_assets: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    all_endpoints: list[str] = field(default_factory=list)
    probed_findings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "scripts_analyzed": self.scripts_analyzed,
            "api_routes": self.api_routes,
            "sensitive_endpoints": self.sensitive_endpoints,
            "cloud_assets": self.cloud_assets,
            "parameters": self.parameters,
            "all_endpoints": self.all_endpoints,
            "probed_findings": self.probed_findings,
            "total_endpoints": len(self.all_endpoints),
        }


class JSEndpointExtractor:
    """
    Client-Side JavaScript Route & API Endpoint Extractor.
    
    Crawls HTML for script tags, downloads client-side bundles, extracts
    API routes, S3 references, and performs non-intrusive accessibility verification.
    """

    def __init__(
        self,
        url: str,
        timeout: float = 6.0,
        max_scripts: int = 12,
        max_script_size_kb: int = 2500,
        verify_ssl: bool = False,
        probe_endpoints: bool = False,
    ):
        self.url = self._normalize_url(url.strip())
        self.timeout = timeout
        self.max_scripts = max_scripts
        self.max_script_size = max_script_size_kb * 1024
        self.verify_ssl = verify_ssl
        self.probe_endpoints = probe_endpoints
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "*/*",
        })

    def _normalize_url(self, raw_url: str) -> str:
        if not raw_url.startswith(("http://", "https://")):
            return f"https://{raw_url}"
        return raw_url.rstrip("/")

    def _fetch_html(self) -> tuple[str, BeautifulSoup]:
        """Fetch base HTML page."""
        try:
            resp = self.session.get(
                self.url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True,
            )
            html = resp.text
            soup = BeautifulSoup(html, "html.parser")
            return html, soup
        except Exception as e:
            logger.debug(f"Failed to fetch base HTML for {self.url}: {e}")
            return "", BeautifulSoup("", "html.parser")

    def _clean_path(self, path: str) -> str:
        """Sanitize and format extracted URL path."""
        p = path.strip(" \"'`")
        if not p.startswith("/"):
            p = f"/{p}"
        # Remove trailing slash duplicates or quotes
        p = re.sub(r"/+", "/", p)
        return p

    def extract_from_text(self, text: str, source_label: str = "") -> dict[str, set[str]]:
        """
        Analyze code text for API routes, general endpoints, cloud URLs, and parameters.
        """
        api_routes: set[str] = set()
        sensitive: set[str] = set()
        cloud_assets: set[str] = set()
        parameters: set[str] = set()
        all_routes: set[str] = set()

        # 1. API Route regex
        for match in REGEX_API_ROUTES.findall(text):
            cleaned = self._clean_path(match)
            if not any(cleaned.lower().endswith(ext) for ext in IGNORE_EXTENSIONS):
                api_routes.add(cleaned)
                all_routes.add(cleaned)

        # 2. General URL Paths
        for match in REGEX_GENERAL_PATHS.findall(text):
            cleaned = self._clean_path(match)
            base_route = cleaned.split("?")[0]
            if not any(base_route.lower().endswith(ext) for ext in IGNORE_EXTENSIONS):
                # Filter out obvious false positives like JS library names or HTML tags
                if not any(fp in base_route.lower() for fp in ("/node_modules/", "/webpack/", "/jquery/")):
                    all_routes.add(base_route)

        # 3. Cloud Storage References
        for match in REGEX_CLOUD_STORAGE.findall(text):
            cloud_assets.add(match)

        # 4. Parameters
        for match in REGEX_PARAMETERS.findall(text):
            if len(match) > 1 and match not in ("id", "v", "t"):
                parameters.add(match)

        # 5. Classify sensitive endpoints
        for r in all_routes:
            r_lower = r.lower()
            for k in SENSITIVE_KEYWORDS:
                if k in ("manage/", "/manage"):
                    if "/manage/" in r_lower or r_lower.endswith("/manage") or "manage-" in r_lower:
                        sensitive.add(r)
                        break
                elif k in r_lower:
                    sensitive.add(r)
                    break

        return {
            "api_routes": api_routes,
            "sensitive": sensitive,
            "cloud_assets": cloud_assets,
            "parameters": parameters,
            "all_routes": all_routes,
        }

    def _fetch_script_content(self, script_url: str) -> str:
        """Download script content with size limit."""
        try:
            resp = self.session.get(
                script_url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                stream=True,
            )
            content_chunks = []
            total_size = 0
            for chunk in resp.iter_content(chunk_size=65536):
                content_chunks.append(chunk)
                total_size += len(chunk)
                if total_size > self.max_script_size:
                    break
            return b"".join(content_chunks).decode("utf-8", errors="ignore")
        except Exception as e:
            logger.debug(f"Failed to fetch script '{script_url}': {e}")
            return ""

    def _probe_route(self, route: str) -> Optional[dict[str, Any]]:
        """Non-intrusively probe a sensitive route for accessibility."""
        full_url = urljoin(self.url, route)
        try:
            resp = self.session.head(
                full_url,
                timeout=3.0,
                verify=self.verify_ssl,
                allow_redirects=False,
            )
            status = resp.status_code
            if status in (200, 301, 302, 401, 403):
                return {
                    "path": route,
                    "url": full_url,
                    "status_code": status,
                    "is_exposed": status == 200,
                }
        except Exception:
            pass
        return None

    def extract(self) -> JSEndpointResult:
        """
        Run end-to-end extraction across HTML inline scripts and external JS bundles.
        """
        logger.info(f"Extracting client-side JS endpoints for [bold magenta]{self.url}[/bold magenta]")

        html, soup = self._fetch_html()
        if not html:
            return JSEndpointResult(url=self.url)

        aggregated_api: set[str] = set()
        aggregated_sensitive: set[str] = set()
        aggregated_cloud: set[str] = set()
        aggregated_params: set[str] = set()
        aggregated_all: set[str] = set()

        scripts_analyzed = 0

        # 1. Analyze inline script elements
        inline_scripts = soup.find_all("script", src=False)
        for s in inline_scripts:
            code = s.string or s.text
            if code and len(code.strip()) > 10:
                res = self.extract_from_text(code, source_label="inline")
                aggregated_api.update(res["api_routes"])
                aggregated_sensitive.update(res["sensitive"])
                aggregated_cloud.update(res["cloud_assets"])
                aggregated_params.update(res["parameters"])
                aggregated_all.update(res["all_routes"])
                scripts_analyzed += 1

        # 2. Collect external script URLs
        script_tags = soup.find_all("script", src=True)
        external_urls: list[str] = []
        for tag in script_tags:
            src = tag.get("src", "").strip()
            if src:
                abs_url = urljoin(self.url, src)
                if abs_url not in external_urls:
                    external_urls.append(abs_url)

        external_urls = external_urls[:self.max_scripts]

        # 3. Download and inspect external script bundles in parallel
        if external_urls:
            with ThreadPoolExecutor(max_workers=min(len(external_urls), 6)) as executor:
                future_to_url = {
                    executor.submit(self._fetch_script_content, u): u
                    for u in external_urls
                }
                for future in as_completed(future_to_url):
                    u = future_to_url[future]
                    try:
                        content = future.result()
                        if content:
                            scripts_analyzed += 1
                            res = self.extract_from_text(content, source_label=u)
                            aggregated_api.update(res["api_routes"])
                            aggregated_sensitive.update(res["sensitive"])
                            aggregated_cloud.update(res["cloud_assets"])
                            aggregated_params.update(res["parameters"])
                            aggregated_all.update(res["all_routes"])
                    except Exception as e:
                        logger.debug(f"Error analyzing script {u}: {e}")

        # 4. Optional: Non-intrusively probe high-risk sensitive paths
        probed_findings = []
        if self.probe_endpoints and aggregated_sensitive:
            probe_targets = list(aggregated_sensitive)[:15]
            with ThreadPoolExecutor(max_workers=5) as executor:
                future_to_p = {
                    executor.submit(self._probe_route, r): r
                    for r in probe_targets
                }
                for future in as_completed(future_to_p):
                    res = future.result()
                    if res:
                        probed_findings.append(res)

        result = JSEndpointResult(
            url=self.url,
            scripts_analyzed=scripts_analyzed,
            api_routes=sorted(list(aggregated_api)),
            sensitive_endpoints=sorted(list(aggregated_sensitive)),
            cloud_assets=sorted(list(aggregated_cloud)),
            parameters=sorted(list(aggregated_params)),
            all_endpoints=sorted(list(aggregated_all)),
            probed_findings=probed_findings,
        )

        logger.info(
            f"JS Endpoint Extraction complete: [bold green]{len(result.api_routes)}[/bold green] API routes, "
            f"[bold yellow]{len(result.sensitive_endpoints)}[/bold yellow] sensitive endpoints, "
            f"[bold cyan]{len(result.cloud_assets)}[/bold cyan] cloud assets."
        )

        return result
