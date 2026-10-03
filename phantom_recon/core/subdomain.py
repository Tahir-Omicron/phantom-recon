"""
Phantom Recon — Subdomain Discovery.

Finds subdomains using brute force, Certificate Transparency logs,
and DNS resolution with wildcard detection.

⚠️ DISCLAIMER: For authorized security testing only.
"""

import random
import socket
import string
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Optional

import requests

from phantom_recon.utils.logger import get_logger, create_progress, console

logger = get_logger(__name__)

# Built-in common subdomain wordlist (top 300)
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "ns4", "dns", "dns1", "dns2", "api", "dev", "staging", "stage",
    "test", "testing", "beta", "alpha", "demo", "sandbox", "qa", "uat",
    "prod", "production", "app", "apps", "mobile", "m", "admin", "administrator",
    "panel", "cpanel", "whm", "webdisk", "autodiscover", "autoconfig",
    "portal", "gateway", "proxy", "vpn", "remote", "access", "connect",
    "secure", "ssl", "tls", "cert", "cdn", "static", "assets", "media",
    "img", "images", "image", "video", "videos", "streaming", "stream",
    "download", "downloads", "upload", "uploads", "files", "file",
    "docs", "doc", "documentation", "help", "support", "kb", "wiki",
    "forum", "forums", "community", "blog", "blogs", "news", "press",
    "shop", "store", "ecommerce", "cart", "checkout", "pay", "payment",
    "billing", "invoice", "account", "accounts", "my", "profile", "user",
    "users", "login", "auth", "oauth", "sso", "signup", "register",
    "dashboard", "console", "manage", "manager", "management", "cms",
    "crm", "erp", "hr", "jira", "confluence", "git", "gitlab", "github",
    "bitbucket", "svn", "repo", "repository", "ci", "cd", "jenkins",
    "travis", "build", "deploy", "release", "monitor", "monitoring",
    "status", "health", "uptime", "nagios", "zabbix", "grafana",
    "prometheus", "elk", "kibana", "elasticsearch", "logstash", "splunk",
    "sentry", "log", "logs", "analytics", "metrics", "stats", "statistics",
    "track", "tracking", "search", "elastic", "solr", "redis", "memcache",
    "cache", "queue", "rabbit", "rabbitmq", "kafka", "mq", "amqp",
    "db", "database", "mysql", "postgres", "postgresql", "mongo", "mongodb",
    "oracle", "mssql", "sql", "phpmyadmin", "adminer", "pgadmin",
    "backup", "backups", "archive", "old", "new", "legacy", "v1", "v2",
    "v3", "api-v1", "api-v2", "api-v3", "internal", "intranet", "private",
    "public", "external", "edge", "node", "cluster", "master", "slave",
    "primary", "secondary", "replica", "mirror", "lb", "loadbalancer",
    "balancer", "web", "web1", "web2", "web3", "server", "server1",
    "server2", "host", "host1", "host2", "cloud", "aws", "azure", "gcp",
    "s3", "storage", "bucket", "container", "docker", "k8s", "kubernetes",
    "swarm", "rancher", "terraform", "ansible", "puppet", "chef",
    "exchange", "outlook", "owa", "calendar", "contacts", "teams",
    "chat", "slack", "discord", "irc", "xmpp", "jabber",
    "map", "maps", "geo", "location", "gis",
    "config", "configuration", "settings", "preferences",
    "report", "reports", "reporting", "data", "bi",
    "service", "services", "svc", "microservice", "micro",
    "graphql", "rest", "soap", "wsdl", "rpc", "grpc",
    "webhook", "hooks", "callback", "notify", "notification",
    "email", "mailer", "newsletter", "campaign", "marketing",
    "ad", "ads", "advertising", "affiliate", "partner", "partners",
    "vendor", "suppliers", "client", "clients", "customer", "customers",
    "en", "es", "fr", "de", "it", "pt", "ru", "cn", "jp", "kr",
    "dev1", "dev2", "test1", "test2", "staging1", "staging2",
    "preview", "pre", "preprod", "pre-prod", "stg",
    "origin", "www1", "www2", "www3",
    "mx", "mx1", "mx2", "relay", "smtp1", "smtp2",
    "imap", "pop3", "mail2", "mail3", "webmail2",
    "time", "ntp", "ldap", "ad", "dc", "dc1", "dc2",
    "radius", "tacacs", "syslog", "snmp", "tftp",
    "ns5", "ns6", "dns3", "dns4", "resolver",
]

# Signatures indicating unclaimed third-party services (Subdomain Takeover)
TAKEOVER_FINGERPRINTS: dict[str, str] = {
    "GitHub Pages": "There isn't a GitHub Pages site here",
    "Amazon S3": "The specified bucket does not exist",
    "Heroku": "No such app",
    "Microsoft Azure": "404 Web Site not found",
    "Shopify": "Sorry, this shop is currently unavailable",
    "Zendesk": "Help Center Closed",
}


class SubdomainFinder:
    """
    Subdomain discovery tool.

    Uses brute force enumeration, Certificate Transparency log
    searches, and DNS resolution to discover subdomains.

    Usage:
        finder = SubdomainFinder(domain="example.com")
        results = finder.find_all()
    """

    def __init__(
        self,
        domain: str,
        wordlist: Optional[list[str]] = None,
        threads: int = 30,
        timeout: float = 3.0,
    ):
        """
        Initialize the subdomain finder.

        Args:
            domain: Target domain name.
            wordlist: Custom subdomain wordlist.
            threads: Number of concurrent threads.
            timeout: DNS resolution timeout.
        """
        self.domain = domain
        self.wordlist = wordlist or COMMON_SUBDOMAINS
        self.threads = min(threads, 100)
        self.timeout = timeout
        self._found: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._wildcard_ip: Optional[str] = None

    def _detect_wildcard(self) -> Optional[str]:
        """Detect wildcard DNS and return the wildcard IP if found."""
        random_sub = "".join(random.choices(string.ascii_lowercase, k=20))
        try:
            ip = socket.gethostbyname(f"{random_sub}.{self.domain}")
            logger.warning(
                f"[yellow]⚠ Wildcard DNS detected: *.{self.domain} → {ip}[/yellow]"
            )
            return ip
        except socket.gaierror:
            return None

    def _resolve_subdomain(self, subdomain: str) -> Optional[dict[str, Any]]:
        """
        Resolve a single subdomain.

        Args:
            subdomain: Subdomain prefix to check.

        Returns:
            Subdomain info dict if resolved, None otherwise.
        """
        fqdn = f"{subdomain}.{self.domain}"
        try:
            socket.setdefaulttimeout(self.timeout)
            ip = socket.gethostbyname(fqdn)

            # Skip if it matches wildcard
            if self._wildcard_ip and ip == self._wildcard_ip:
                return None

            result = {
                "subdomain": fqdn,
                "ip": ip,
                "source": "bruteforce",
            }

            # Try to get HTTP status
            try:
                resp = requests.get(
                    f"http://{fqdn}",
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False,
                )
                result["status_code"] = resp.status_code
                result["title"] = ""
                if "<title>" in resp.text.lower():
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(resp.text, "html.parser")
                    if soup.title:
                        result["title"] = soup.title.string or ""

                # Check for dangling CNAME takeover fingerprint
                result["takeover_risk"] = False
                for service, fp in TAKEOVER_FINGERPRINTS.items():
                    if fp.lower() in resp.text.lower():
                        result["takeover_risk"] = True
                        result["takeover_service"] = service
                        result["takeover_evidence"] = fp
                        logger.warning(
                            f"[bold red]🚨 SUBDOMAIN TAKEOVER RISK: {fqdn} matches dangling {service} pattern![/bold red]"
                        )
                        break

            except requests.RequestException:
                result["status_code"] = None
                result["title"] = ""
                result["takeover_risk"] = False

            return result

        except (socket.gaierror, socket.timeout, OSError):
            return None

    def brute_force(self) -> list[dict[str, Any]]:
        """
        Discover subdomains via brute force enumeration.

        Returns:
            List of discovered subdomain dictionaries.
        """
        logger.info(
            f"Brute forcing subdomains for [bold magenta]{self.domain}[/bold magenta] "
            f"({len(self.wordlist)} words, {self.threads} threads)"
        )

        # Detect wildcard first
        self._wildcard_ip = self._detect_wildcard()

        found: list[dict[str, Any]] = []

        with create_progress() as progress:
            task = progress.add_task("Brute forcing subdomains", total=len(self.wordlist))

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {
                    executor.submit(self._resolve_subdomain, sub): sub
                    for sub in self.wordlist
                }

                for future in as_completed(futures):
                    result = future.result()
                    progress.advance(task)

                    if result:
                        found.append(result)
                        with self._lock:
                            self._found.append(result)

        found.sort(key=lambda x: x["subdomain"])
        logger.info(f"Found [bold green]{len(found)}[/bold green] subdomains via brute force")
        return found

    def _search_crtsh(self) -> list[dict[str, Any]]:
        """Search Certificate Transparency logs via crt.sh with timeout guard."""
        results: list[dict[str, Any]] = []
        seen: set[str] = set()
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%.{self.domain}&output=json",
                timeout=7.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for subdomain in name.split("\n"):
                        subdomain = subdomain.strip().lower()
                        if (
                            subdomain.endswith(f".{self.domain}")
                            and subdomain not in seen
                            and "*" not in subdomain
                        ):
                            seen.add(subdomain)
                            results.append({
                                "subdomain": subdomain,
                                "source": "ct_logs",
                                "issuer": entry.get("issuer_name", ""),
                                "not_before": entry.get("not_before", ""),
                                "not_after": entry.get("not_after", ""),
                            })
        except Exception as e:
            logger.debug(f"crt.sh CT search failed or timed out: {e}")
        return results

    def _search_hackertarget(self) -> list[dict[str, Any]]:
        """Search subdomains via HackerTarget HostSearch passive DNS feed."""
        results: list[dict[str, Any]] = []
        seen: set[str] = set()
        try:
            resp = requests.get(
                f"https://api.hackertarget.com/hostsearch/?q={self.domain}",
                timeout=6.0,
            )
            if resp.status_code == 200 and "API count" not in resp.text and "error" not in resp.text.lower():
                for line in resp.text.splitlines():
                    line = line.strip()
                    if not line or "," not in line:
                        continue
                    parts = line.split(",", 1)
                    sub = parts[0].strip().lower()
                    ip = parts[1].strip() if len(parts) > 1 else ""
                    if (
                        (sub == self.domain or sub.endswith(f".{self.domain}"))
                        and sub not in seen
                        and "*" not in sub
                    ):
                        seen.add(sub)
                        entry: dict[str, Any] = {
                            "subdomain": sub,
                            "source": "passive_intel",
                        }
                        if ip and ip != "N/A":
                            entry["ip"] = ip
                        results.append(entry)
        except Exception as e:
            logger.debug(f"HackerTarget passive search failed or timed out: {e}")
        return results

    def ct_search(self) -> list[dict[str, Any]]:
        """
        Search Certificate Transparency logs and passive OSINT feeds.

        Returns:
            List of unique subdomains found via passive intelligence.
        """
        logger.info(f"Searching passive feeds & CT logs for [bold magenta]{self.domain}[/bold magenta]")

        found: list[dict[str, Any]] = []
        seen_domains: set[str] = set()

        # 1. Primary: crt.sh
        crt_results = self._search_crtsh()
        for r in crt_results:
            sub = r["subdomain"]
            if sub not in seen_domains:
                seen_domains.add(sub)
                found.append(r)

        # 2. Secondary / Fallback: HackerTarget HostSearch
        ht_results = self._search_hackertarget()
        for r in ht_results:
            sub = r["subdomain"]
            if sub not in seen_domains:
                seen_domains.add(sub)
                found.append(r)
            else:
                # If already found in crt.sh but without an IP, enrich with HackerTarget IP
                for f in found:
                    if f["subdomain"] == sub and not f.get("ip") and r.get("ip"):
                        f["ip"] = r["ip"]

        # 3. Fast concurrent DNS IP resolution for subdomains that do not yet have an IP
        unresolved = [f for f in found if not f.get("ip") or f.get("ip") == "N/A"]
        if unresolved:
            def _resolve_ip(entry: dict[str, Any]) -> None:
                sub = entry["subdomain"]
                try:
                    socket.setdefaulttimeout(1.5)
                    entry["ip"] = socket.gethostbyname(sub)
                except Exception:
                    entry["ip"] = "N/A"

            with ThreadPoolExecutor(max_workers=min(len(unresolved), 25)) as executor:
                list(executor.map(_resolve_ip, unresolved))

        logger.info(f"Found [bold green]{len(found)}[/bold green] subdomains via passive intelligence")
        return found

    def find_all(self) -> list[dict[str, Any]]:
        """
        Run all subdomain discovery techniques (brute force + CT / passive OSINT).

        Returns:
            Combined list of unique discovered subdomains with enriched IPs.
        """
        start = datetime.now()

        # Run both methods
        brute_results = self.brute_force()
        ct_results = self.ct_search()

        # Merge and deduplicate
        seen: dict[str, dict[str, Any]] = {}

        for result in brute_results + ct_results:
            sub = result["subdomain"]
            if sub not in seen:
                seen[sub] = dict(result)
            else:
                # If existing lacks IP and new has IP, update
                if (not seen[sub].get("ip") or seen[sub].get("ip") == "N/A") and result.get("ip") and result.get("ip") != "N/A":
                    seen[sub]["ip"] = result["ip"]
                if result.get("status_code") and not seen[sub].get("status_code"):
                    seen[sub]["status_code"] = result["status_code"]

        combined = list(seen.values())
        combined.sort(key=lambda x: x["subdomain"])

        duration = (datetime.now() - start).total_seconds()
        logger.info(
            f"Total unique subdomains: [bold green]{len(combined)}[/bold green] "
            f"(in {duration:.1f}s)"
        )

        return combined
