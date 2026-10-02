"""
Phantom Recon — API & Documentation Reconnaissance Engine (v1.6.0).

Specialized in discovering exposed API architectures, OpenAPI / Swagger schemas,
GraphQL endpoints, Postman collections, and Spring Boot Actuators.
Engineered with zero-false-positive baseline validation.

⚠️ DISCLAIMER: For authorized security testing only.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
import json
import re
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from phantom_recon.utils.logger import get_logger, console

logger = get_logger(__name__)

# Common API Schema & Documentation paths
API_CANDIDATE_PATHS: list[dict[str, Any]] = [
    # Swagger & OpenAPI Schemas
    {"path": "/swagger.json", "type": "OpenAPI / Swagger JSON", "category": "schema"},
    {"path": "/swagger/v1/swagger.json", "type": "Swagger v1 JSON", "category": "schema"},
    {"path": "/api/swagger.json", "type": "API Swagger JSON", "category": "schema"},
    {"path": "/openapi.json", "type": "OpenAPI 3.0 JSON", "category": "schema"},
    {"path": "/api/openapi.json", "type": "API OpenAPI JSON", "category": "schema"},
    {"path": "/v2/api-docs", "type": "Springfox Swagger v2", "category": "schema"},
    {"path": "/v3/api-docs", "type": "Springdoc OpenAPI v3", "category": "schema"},
    {"path": "/api-docs", "type": "OpenAPI API Docs", "category": "schema"},

    # Interactive Documentation UIs
    {"path": "/swagger-ui.html", "type": "Swagger UI Dashboard", "category": "docs"},
    {"path": "/swagger-ui/", "type": "Swagger UI Directory", "category": "docs"},
    {"path": "/swagger/", "type": "Swagger UI Portal", "category": "docs"},
    {"path": "/docs", "type": "FastAPI / Redoc Documentation", "category": "docs"},
    {"path": "/redoc", "type": "ReDoc API Documentation", "category": "docs"},
    {"path": "/api/docs", "type": "API Docs Portal", "category": "docs"},

    # GraphQL Endpoints
    {"path": "/graphql", "type": "GraphQL API Endpoint", "category": "graphql"},
    {"path": "/graphiql", "type": "GraphiQL Interactive IDE", "category": "graphql"},
    {"path": "/api/graphql", "type": "API GraphQL Endpoint", "category": "graphql"},

    # Spring Boot / Cloud Actuator Consoles
    {"path": "/actuator", "type": "Spring Boot Actuator Index", "category": "actuator"},
    {"path": "/actuator/health", "type": "Actuator Health Status", "category": "actuator"},
    {"path": "/actuator/info", "type": "Actuator Application Info", "category": "actuator"},
    {"path": "/actuator/env", "type": "Actuator Environment Secrets", "category": "actuator"},
    {"path": "/actuator/beans", "type": "Actuator Dependency Beans", "category": "actuator"},
    {"path": "/actuator/mappings", "type": "Actuator Route Mappings", "category": "actuator"},
]


@dataclass
class APIEndpointFinding:
    """Represents a validated API or documentation discovery."""
    url: str
    path: str
    endpoint_type: str
    category: str
    status_code: int
    content_type: str
    evidence: str
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "path": self.path,
            "type": self.endpoint_type,
            "category": self.category,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


class APIScanner:
    """
    Precision API & Documentation Discovery Scanner.
    
    Identifies exposed API schemas, interactive interfaces, and administrative
    actuators while guarding against wildcard/soft-404 web applications.
    """

    def __init__(self, url: str, timeout: float = 6.0):
        self.url = self._normalize_url(url.strip())
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 PhantomRecon/1.6.0",
            "Accept": "application/json, text/html, */*",
        })
        self.session.verify = False

        self._baseline_status = 404
        self._baseline_length = 0

    def _normalize_url(self, target: str) -> str:
        if not target.startswith("http://") and not target.startswith("https://"):
            return f"https://{target}"
        return target.rstrip("/")

    def _profile_baseline(self) -> None:
        """Establish soft-404 baseline using a random canary path."""
        try:
            canary_url = urljoin(self.url, "/phantom_canary_api_404_test_xyz987")
            resp = self.session.get(canary_url, timeout=self.timeout, allow_redirects=False)
            self._baseline_status = resp.status_code
            self._baseline_length = len(resp.content)
        except requests.RequestException:
            self._baseline_status = 404
            self._baseline_length = 0

    def _is_soft_404(self, resp: requests.Response) -> bool:
        """Check if response matches the server's soft-404 baseline."""
        if resp.status_code == self._baseline_status:
            # If length is within 10% of canary 404 page length
            if abs(len(resp.content) - self._baseline_length) < max(50, self._baseline_length * 0.1):
                return True
        return False

    def _test_candidate(self, candidate: dict[str, Any]) -> Optional[APIEndpointFinding]:
        target_url = urljoin(self.url + "/", candidate["path"].lstrip("/"))
        try:
            resp = self.session.get(target_url, timeout=self.timeout, allow_redirects=True)
            
            # Filter out standard 404/403/500 errors and soft-404s
            if resp.status_code not in (200, 204, 301, 302, 400):
                return None
            if self._is_soft_404(resp):
                return None

            content_type = resp.headers.get("Content-Type", "").lower()
            body_text = resp.text[:15000].lower()
            cat = candidate["category"]

            # 1. OpenAPI / Swagger Schema Validation
            if cat == "schema" and resp.status_code == 200:
                try:
                    data = json.loads(resp.text)
                    if isinstance(data, dict) and any(k in data for k in ["swagger", "openapi", "paths", "components"]):
                        return APIEndpointFinding(
                            url=target_url,
                            path=candidate["path"],
                            endpoint_type=candidate["type"],
                            category=cat,
                            status_code=resp.status_code,
                            content_type=content_type,
                            evidence=f"Valid JSON schema with keys: {[k for k in data.keys() if k in ['swagger', 'openapi', 'paths', 'info']]}",
                            remediation="Restrict public schema access; require API gateway authentication or disable schema exposure in production.",
                        )
                except Exception:
                    pass

            # 2. Interactive Documentation Validation
            elif cat == "docs" and resp.status_code == 200:
                if any(sig in body_text for sig in ["swagger-ui", "swagger ui", "redoc", "api documentation", "openapi"]):
                    return APIEndpointFinding(
                        url=target_url,
                        path=candidate["path"],
                        endpoint_type=candidate["type"],
                        category=cat,
                        status_code=resp.status_code,
                        content_type=content_type,
                        evidence=f"Interactive documentation UI confirmed (Found '{candidate['type']}').",
                        remediation="Ensure interactive API consoles are protected behind internal network firewalls or OAuth2 login.",
                    )

            # 3. GraphQL Endpoint Validation
            elif cat == "graphql":
                # Send non-destructive probe to confirm live GraphQL schema
                is_graphql = False
                evidence_str = ""
                try:
                    gql_resp = self.session.post(
                        target_url,
                        json={"query": "{__typename}"},
                        timeout=self.timeout,
                        headers={"Content-Type": "application/json"},
                    )
                    if gql_resp.status_code in (200, 400):
                        gql_data = gql_resp.json()
                        if "data" in gql_data or "errors" in gql_data:
                            is_graphql = True
                            evidence_str = f"GraphQL query response confirmed: {json.dumps(gql_data)[:100]}"
                except Exception:
                    if "graphiql" in body_text or "graphql" in body_text:
                        is_graphql = True
                        evidence_str = "Interactive GraphiQL interface detected in HTML body."

                if is_graphql:
                    return APIEndpointFinding(
                        url=target_url,
                        path=candidate["path"],
                        endpoint_type=candidate["type"],
                        category=cat,
                        status_code=resp.status_code,
                        content_type=content_type,
                        evidence=evidence_str,
                        remediation="Disable GraphQL introspection in production and apply rate-limiting/query depth restrictions.",
                    )

            # 4. Spring Boot Actuator Validation
            elif cat == "actuator" and resp.status_code == 200:
                try:
                    act_data = json.loads(resp.text)
                    if isinstance(act_data, dict) and any(k in act_data for k in ["_links", "status", "components", "propertySources"]):
                        return APIEndpointFinding(
                            url=target_url,
                            path=candidate["path"],
                            endpoint_type=candidate["type"],
                            category=cat,
                            status_code=resp.status_code,
                            content_type=content_type,
                            evidence=f"Spring Boot Actuator active: Keys: {list(act_data.keys())[:5]}",
                            remediation="Set 'management.endpoints.web.exposure.exclude=*' and isolate actuator ports to localhost.",
                        )
                except Exception:
                    pass

        except requests.RequestException:
            pass
        return None

    def scan_endpoints(self) -> list[dict[str, Any]]:
        """
        Execute API endpoint discovery across known paths with zero false positive checks.
        Uses multi-threaded worker pool for fast execution.
        """
        logger.info(f"Auditing API endpoints & schemas on [bold magenta]{self.url}[/bold magenta]...")
        self._profile_baseline()

        findings: list[APIEndpointFinding] = []
        max_workers = min(len(API_CANDIDATE_PATHS), 10)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_cand = {executor.submit(self._test_candidate, cand): cand for cand in API_CANDIDATE_PATHS}
            for future in as_completed(future_to_cand):
                try:
                    res = future.result()
                    if res:
                        findings.append(res)
                except Exception:
                    pass

        logger.info(f"API reconnaissance completed: [bold cyan]{len(findings)}[/bold cyan] confirmed endpoints.")
        return [f.to_dict() for f in findings]
