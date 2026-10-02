"""
Phantom Recon — Web Reconnaissance Module.

Technology fingerprinting, robots.txt/sitemap parsing, directory enumeration,
form detection, cookie analysis, and link extraction.

⚠️ DISCLAIMER: For authorized security testing only.
"""

import re
from datetime import datetime
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from phantom_recon.utils.logger import get_logger, create_progress, console
from phantom_recon.utils.validators import validate_url

logger = get_logger(__name__)

# Technology signatures for fingerprinting
TECH_SIGNATURES: dict[str, list[dict[str, str]]] = {
    "WordPress": [
        {"type": "header", "name": "X-Powered-By", "pattern": r"WordPress"},
        {"type": "body", "pattern": r"wp-content|wp-includes"},
        {"type": "meta", "name": "generator", "pattern": r"WordPress"},
    ],
    "Drupal": [
        {"type": "header", "name": "X-Generator", "pattern": r"Drupal"},
        {"type": "body", "pattern": r"Drupal\.settings|drupal\.js"},
    ],
    "Joomla": [
        {"type": "meta", "name": "generator", "pattern": r"Joomla"},
        {"type": "body", "pattern": r"/media/jui/|/templates/"},
    ],
    "React": [
        {"type": "body", "pattern": r"react\.production\.min\.js|_react|__NEXT_DATA__"},
    ],
    "Angular": [
        {"type": "body", "pattern": r"ng-version|angular\.min\.js|ng-app"},
    ],
    "Vue.js": [
        {"type": "body", "pattern": r"vue\.min\.js|v-app|__VUE__"},
    ],
    "jQuery": [
        {"type": "body", "pattern": r"jquery[\.-][\d\.]*\.min\.js|jQuery"},
    ],
    "Bootstrap": [
        {"type": "body", "pattern": r"bootstrap[\.-][\d\.]*\.min\.(css|js)"},
    ],
    "nginx": [
        {"type": "header", "name": "Server", "pattern": r"nginx"},
    ],
    "Apache": [
        {"type": "header", "name": "Server", "pattern": r"Apache"},
    ],
    "IIS": [
        {"type": "header", "name": "Server", "pattern": r"Microsoft-IIS"},
    ],
    "PHP": [
        {"type": "header", "name": "X-Powered-By", "pattern": r"PHP"},
    ],
    "ASP.NET": [
        {"type": "header", "name": "X-Powered-By", "pattern": r"ASP\.NET"},
        {"type": "header", "name": "X-AspNet-Version", "pattern": r".+"},
    ],
    "Cloudflare": [
        {"type": "header", "name": "Server", "pattern": r"cloudflare"},
        {"type": "header", "name": "CF-RAY", "pattern": r".+"},
    ],
    "Django": [
        {"type": "header", "name": "X-Frame-Options", "pattern": r"SAMEORIGIN"},
        {"type": "body", "pattern": r"csrfmiddlewaretoken|__django__"},
    ],
    "Laravel": [
        {"type": "body", "pattern": r"laravel_session|XSRF-TOKEN"},
    ],
    "Express.js": [
        {"type": "header", "name": "X-Powered-By", "pattern": r"Express"},
    ],
}

# Common directories to check
DEFAULT_DIRECTORIES = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php",
    "panel", "dashboard", "api", "api/v1", "api/v2", "console",
    "phpmyadmin", "adminer", "cpanel", "webmail", "mail",
    ".git", ".env", ".htaccess", "backup", "backups",
    "config", "configuration", "db", "database", "debug",
    "docs", "documentation", "dump", "error", "errors",
    "files", "img", "images", "includes", "install",
    "js", "css", "static", "assets", "uploads", "media",
    "logs", "log", "old", "new", "test", "tests", "tmp", "temp",
    "server-status", "server-info", "info.php", "phpinfo.php",
    "robots.txt", "sitemap.xml", ".well-known", "humans.txt",
    "crossdomain.xml", "clientaccesspolicy.xml", "security.txt",
    ".well-known/security.txt",
]


class WebRecon:
    """
    Web application reconnaissance tool.

    Performs technology fingerprinting, directory enumeration,
    form detection, cookie analysis, and link extraction.

    Usage:
        recon = WebRecon(url="https://example.com")
        results = recon.run_full_recon()
    """

    def __init__(
        self,
        url: str,
        user_agent: Optional[str] = None,
        timeout: float = 10.0,
        follow_redirects: bool = True,
        verify_ssl: bool = True,
    ):
        """
        Initialize web reconnaissance.

        Args:
            url: Target URL.
            user_agent: Custom User-Agent string.
            timeout: Request timeout in seconds.
            follow_redirects: Whether to follow redirects.
            verify_ssl: Whether to verify SSL certificates.
        """
        if not validate_url(url):
            raise ValueError(f"Invalid URL: {url}")

        self.url = url.rstrip("/")
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": user_agent or (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })
        self.session.verify = verify_ssl
        self._response: Optional[requests.Response] = None
        self._soup: Optional[BeautifulSoup] = None

    def _fetch(self, url: Optional[str] = None) -> requests.Response:
        """Fetch a URL and return the response."""
        target_url = url or self.url
        response = self.session.get(
            target_url,
            timeout=self.timeout,
            allow_redirects=self.follow_redirects,
        )
        if url is None:
            self._response = response
            self._soup = BeautifulSoup(response.text, "html.parser")
        return response

    def fingerprint_technologies(self) -> list[str]:
        """
        Detect technologies used by the web application.

        Returns:
            List of detected technology names.
        """
        if not self._response:
            self._fetch()

        detected: list[str] = []

        for tech_name, signatures in TECH_SIGNATURES.items():
            for sig in signatures:
                try:
                    if sig["type"] == "header":
                        header_val = self._response.headers.get(sig["name"], "")
                        if re.search(sig["pattern"], header_val, re.IGNORECASE):
                            if tech_name not in detected:
                                detected.append(tech_name)
                    elif sig["type"] == "body":
                        if re.search(sig["pattern"], self._response.text, re.IGNORECASE):
                            if tech_name not in detected:
                                detected.append(tech_name)
                    elif sig["type"] == "meta":
                        if self._soup:
                            meta = self._soup.find("meta", attrs={"name": sig["name"]})
                            if meta and re.search(
                                sig["pattern"],
                                meta.get("content", ""),
                                re.IGNORECASE,
                            ):
                                if tech_name not in detected:
                                    detected.append(tech_name)
                except (re.error, TypeError):
                    continue

        return detected

    def parse_robots_txt(self) -> dict[str, Any]:
        """
        Parse robots.txt file.

        Returns:
            Dictionary with allowed/disallowed paths and sitemaps.
        """
        result = {"exists": False, "disallowed": [], "allowed": [], "sitemaps": []}

        try:
            resp = self._fetch(f"{self.url}/robots.txt")
            if resp.status_code == 200 and "html" not in resp.headers.get("Content-Type", "").lower():
                result["exists"] = True
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            result["disallowed"].append(path)
                    elif line.lower().startswith("allow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            result["allowed"].append(path)
                    elif line.lower().startswith("sitemap:"):
                        sitemap = line.split(":", 1)[1].strip()
                        if ":" in sitemap:  # Fix for "Sitemap: http://..."
                            sitemap = line.split(" ", 1)[1].strip()
                        result["sitemaps"].append(sitemap)
        except requests.RequestException:
            pass

        return result

    def parse_sitemap(self) -> list[str]:
        """
        Parse sitemap.xml and extract URLs.

        Returns:
            List of URLs found in sitemap.
        """
        urls = []
        try:
            resp = self._fetch(f"{self.url}/sitemap.xml")
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                for loc in soup.find_all("loc"):
                    urls.append(loc.text.strip())
        except requests.RequestException:
            pass
        return urls

    def enumerate_directories(
        self, wordlist: Optional[list[str]] = None
    ) -> list[dict[str, Any]]:
        """
        Enumerate directories/paths on the target.

        Args:
            wordlist: Custom list of paths to check.

        Returns:
            List of discovered paths with status codes.
        """
        paths_to_check = wordlist or DEFAULT_DIRECTORIES
        found: list[dict[str, Any]] = []

        logger.info(
            f"Enumerating {len(paths_to_check)} paths on "
            f"[bold magenta]{self.url}[/bold magenta]"
        )

        with create_progress() as progress:
            task = progress.add_task("Directory enumeration", total=len(paths_to_check))

            for path in paths_to_check:
                try:
                    url = f"{self.url}/{path}"
                    resp = self.session.get(
                        url,
                        timeout=self.timeout,
                        allow_redirects=False,
                    )
                    progress.advance(task)

                    if resp.status_code not in (404, 403, 500):
                        found.append({
                            "path": f"/{path}",
                            "url": url,
                            "status_code": resp.status_code,
                            "content_length": len(resp.content),
                            "content_type": resp.headers.get("Content-Type", ""),
                        })
                except requests.RequestException:
                    progress.advance(task)
                    continue

        return found

    def detect_forms(self) -> list[dict[str, Any]]:
        """
        Detect HTML forms and extract parameters.

        Returns:
            List of form dictionaries with action, method, and inputs.
        """
        if not self._soup:
            self._fetch()

        forms = []
        for form in self._soup.find_all("form"):
            form_data = {
                "action": form.get("action", ""),
                "method": form.get("method", "GET").upper(),
                "id": form.get("id", ""),
                "class": form.get("class", []),
                "inputs": [],
            }

            for inp in form.find_all(["input", "textarea", "select"]):
                input_data = {
                    "name": inp.get("name", ""),
                    "type": inp.get("type", "text"),
                    "id": inp.get("id", ""),
                    "value": inp.get("value", ""),
                    "required": inp.has_attr("required"),
                    "placeholder": inp.get("placeholder", ""),
                }
                form_data["inputs"].append(input_data)

            forms.append(form_data)

        return forms

    def analyze_cookies(self) -> list[dict[str, Any]]:
        """
        Analyze cookie security settings.

        Returns:
            List of cookie analysis dictionaries.
        """
        if not self._response:
            self._fetch()

        cookies = []
        for cookie in self.session.cookies:
            cookie_info = {
                "name": cookie.name,
                "value": cookie.value[:20] + "..." if len(cookie.value) > 20 else cookie.value,
                "domain": cookie.domain,
                "path": cookie.path,
                "secure": cookie.secure,
                "httponly": bool(cookie._rest.get("HttpOnly", False)),
                "samesite": cookie._rest.get("SameSite", "Not Set"),
                "expires": str(cookie.expires) if cookie.expires else "Session",
                "issues": [],
            }

            # Security checks
            if not cookie.secure:
                cookie_info["issues"].append("Missing Secure flag")
            if not cookie_info["httponly"]:
                cookie_info["issues"].append("Missing HttpOnly flag")
            if cookie_info["samesite"] == "Not Set":
                cookie_info["issues"].append("Missing SameSite attribute")

            cookies.append(cookie_info)

        return cookies

    def extract_links(self) -> dict[str, list[str]]:
        """
        Extract all links from the page.

        Returns:
            Dictionary with 'internal' and 'external' link lists.
        """
        if not self._soup:
            self._fetch()

        parsed_base = urlparse(self.url)
        internal: list[str] = []
        external: list[str] = []

        for tag in self._soup.find_all("a", href=True):
            href = tag["href"]
            full_url = urljoin(self.url, href)
            parsed = urlparse(full_url)

            if parsed.netloc == parsed_base.netloc:
                if full_url not in internal:
                    internal.append(full_url)
            elif parsed.scheme in ("http", "https"):
                if full_url not in external:
                    external.append(full_url)

        return {"internal": internal, "external": external}

    def discover_js_files(self) -> list[str]:
        """
        Discover JavaScript files loaded by the page.

        Returns:
            List of JavaScript file URLs.
        """
        if not self._soup:
            self._fetch()

        js_files = []
        for script in self._soup.find_all("script", src=True):
            js_url = urljoin(self.url, script["src"])
            if js_url not in js_files:
                js_files.append(js_url)

        return js_files

    def analyze_javascript_files(self, max_files: int = 8) -> dict[str, Any]:
        """
        Analyze loaded JavaScript files to extract API endpoints and detect exposed secrets.

        Args:
            max_files: Maximum number of JS files to download and inspect.

        Returns:
            Dictionary with discovered API endpoints and potential secret leaks.
        """
        js_urls = self.discover_js_files()[:max_files]
        analysis = {
            "files_analyzed": len(js_urls),
            "endpoints": [],
            "secrets": [],
        }

        endpoint_regex = re.compile(r"""(?:["'])(/(?:api/v[0-9]+|v[0-9]+/|graphql|rest/)[a-zA-Z0-9_\-\./]+)(?:["'])""")
        secret_patterns = [
            ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
            ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
            ("Slack Webhook", re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[0-9a-zA-Z]{20,}")),
            ("Private RSA Key", re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----")),
            ("Hardcoded API Secret", re.compile(r"""(?i)(?:api[_-]?key|access[_-]?token|auth[_-]?secret)\s*[:=]\s*["']([a-zA-Z0-9_\-]{24,})["']""")),
        ]

        for js_url in js_urls:
            try:
                resp = self.session.get(js_url, timeout=min(self.timeout, 5.0))
                if resp.status_code != 200:
                    continue

                text = resp.text[:500000]  # Cap at 500KB per file for fast performance

                # Extract endpoints
                for match in endpoint_regex.findall(text):
                    if match not in analysis["endpoints"]:
                        analysis["endpoints"].append(match)

                # Extract secrets
                for secret_type, pat in secret_patterns:
                    matches = pat.findall(text)
                    for m in matches:
                        secret_val = m if isinstance(m, str) else m[0]
                        # Redact secret value for safe storage/reporting
                        redacted = secret_val[:6] + "..." + secret_val[-4:] if len(secret_val) > 10 else "***"
                        analysis["secrets"].append({
                            "type": secret_type,
                            "file": js_url,
                            "preview": redacted,
                        })

            except requests.RequestException:
                continue

        return analysis

    def parse_security_txt(self) -> dict[str, Any]:
        """
        Check and parse RFC 9116 security.txt file.

        Returns:
            Dictionary with security.txt presence and extracted directives.
        """
        result = {"exists": False, "url": "", "contact": [], "expires": "", "encryption": "", "policy": ""}
        candidates = [f"{self.url}/.well-known/security.txt", f"{self.url}/security.txt"]

        for cand in candidates:
            try:
                resp = self.session.get(cand, timeout=self.timeout, allow_redirects=True)
                if resp.status_code == 200 and "contact:" in resp.text.lower():
                    result["exists"] = True
                    result["url"] = cand
                    for line in resp.text.splitlines():
                        line = line.strip()
                        if line.lower().startswith("contact:"):
                            val = line.split(":", 1)[1].strip()
                            if val and val not in result["contact"]:
                                result["contact"].append(val)
                        elif line.lower().startswith("expires:"):
                            result["expires"] = line.split(":", 1)[1].strip()
                        elif line.lower().startswith("encryption:"):
                            result["encryption"] = line.split(":", 1)[1].strip()
                        elif line.lower().startswith("policy:"):
                            result["policy"] = line.split(":", 1)[1].strip()
                    break
            except requests.RequestException:
                continue

        return result

    def run_full_recon(self) -> dict[str, Any]:
        """
        Run full web reconnaissance.

        Returns:
            Dictionary with all reconnaissance results.
        """
        logger.info(f"Running full web recon on [bold magenta]{self.url}[/bold magenta]")
        start = datetime.now()

        # Initial fetch
        try:
            self._fetch()
        except requests.RequestException as e:
            return {"error": f"Failed to connect: {e}", "url": self.url}

        results: dict[str, Any] = {
            "url": self.url,
            "status_code": self._response.status_code,
            "title": "",
            "timestamp": datetime.now().isoformat(),
        }

        # Page title
        if self._soup and self._soup.title:
            results["title"] = self._soup.title.string or ""

        # Technologies
        results["technologies"] = self.fingerprint_technologies()

        # Robots.txt
        results["robots_txt"] = self.parse_robots_txt()

        # Sitemap
        results["sitemap_urls"] = self.parse_sitemap()

        # Security.txt
        results["security_txt"] = self.parse_security_txt()

        # Forms
        results["forms"] = self.detect_forms()

        # Cookies
        results["cookies"] = self.analyze_cookies()

        # Links
        results["links"] = self.extract_links()

        # JavaScript files
        results["js_files"] = self.discover_js_files()

        # JavaScript deep analysis
        results["js_analysis"] = self.analyze_javascript_files()

        # Directory enumeration
        results["directories"] = self.enumerate_directories()

        duration = (datetime.now() - start).total_seconds()
        results["duration"] = round(duration, 2)

        return results
