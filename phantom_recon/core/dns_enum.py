"""
Phantom Recon — DNS Enumerator.

Full DNS record enumeration including A, AAAA, MX, NS, TXT, SOA, CNAME,
SRV records, reverse lookups, zone transfer attempts, and wildcard detection.

⚠️ DISCLAIMER: For authorized security testing only.
"""

import re
import socket
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from phantom_recon.utils.logger import get_logger, console

logger = get_logger(__name__)

# DNS record types supported
RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "PTR", "CAA", "DNSKEY", "DS"]


class DNSEnumerator:
    """
    DNS record enumerator.

    Performs comprehensive DNS enumeration including all record types,
    reverse lookups, zone transfer attempts, and wildcard detection.

    Usage:
        dns = DNSEnumerator(domain="example.com")
        records = dns.enumerate_all()
    """

    def __init__(self, domain: str, nameserver: Optional[str] = None, timeout: float = 5.0):
        """
        Initialize the DNS enumerator.

        Args:
            domain: Target domain name.
            nameserver: Custom DNS nameserver to query.
            timeout: Query timeout in seconds.
        """
        self.domain = domain
        self.nameserver = nameserver
        self.timeout = timeout
        self._results: dict[str, Any] = {}

    def _create_resolver(self, nameservers: Optional[list[str]] = None) -> Any:
        """Create a configured dns.resolver.Resolver instance."""
        import dns.resolver
        resolver = dns.resolver.Resolver()
        if nameservers:
            resolver.nameservers = nameservers
        elif self.nameserver:
            resolver.nameservers = [self.nameserver]
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        return resolver

    def _resolve_query(self, domain: str, record_type: str) -> Any:
        """
        Execute a DNS query with automatic failover to high-reliability public resolvers
        (1.1.1.1, 8.8.8.8, 9.9.9.9) on timeouts, gateway drops, or local server failure.
        """
        import dns.resolver
        import dns.exception

        resolver = self._create_resolver()
        try:
            return resolver.resolve(domain, record_type)
        except (dns.resolver.Timeout, dns.resolver.NoNameservers, dns.exception.Timeout):
            if not self.nameserver:
                # Resilient public DNS resolvers fallback
                fallback_resolver = self._create_resolver(nameservers=["1.1.1.1", "8.8.8.8", "9.9.9.9"])
                return fallback_resolver.resolve(domain, record_type)
            raise

    def _query_record(self, record_type: str) -> list[dict[str, str]]:
        """
        Query a specific DNS record type.

        Args:
            record_type: DNS record type (A, AAAA, MX, etc.).

        Returns:
            List of record dictionaries.
        """
        records = []
        try:
            answers = self._resolve_query(self.domain, record_type)

            for answer in answers:
                record = {"type": record_type, "value": str(answer)}

                if record_type == "MX":
                    record["priority"] = answer.preference
                    record["exchange"] = str(answer.exchange)
                elif record_type == "SOA":
                    record["mname"] = str(answer.mname)
                    record["rname"] = str(answer.rname)
                    record["serial"] = answer.serial
                    record["refresh"] = answer.refresh
                    record["retry"] = answer.retry
                    record["expire"] = answer.expire
                    record["minimum"] = answer.minimum
                elif record_type == "SRV":
                    record["priority"] = answer.priority
                    record["weight"] = answer.weight
                    record["port"] = answer.port
                    record["target"] = str(answer.target)

                records.append(record)

        except ImportError:
            # Fallback without dnspython — basic A record via socket
            if record_type == "A":
                try:
                    ips = socket.getaddrinfo(self.domain, None, socket.AF_INET)
                    seen = set()
                    for info in ips:
                        ip = info[4][0]
                        if ip not in seen:
                            seen.add(ip)
                            records.append({"type": "A", "value": ip})
                except socket.gaierror:
                    pass
            elif record_type == "AAAA":
                try:
                    ips = socket.getaddrinfo(self.domain, None, socket.AF_INET6)
                    seen = set()
                    for info in ips:
                        ip = info[4][0]
                        if ip not in seen:
                            seen.add(ip)
                            records.append({"type": "AAAA", "value": ip})
                except socket.gaierror:
                    pass
        except Exception as e:
            logger.debug(f"No {record_type} records found for {self.domain}: {e}")

        return records

    def enumerate_all(self) -> dict[str, Any]:
        """
        Enumerate all DNS record types.

        Returns:
            Dictionary with all DNS records organized by type.
        """
        logger.info(f"Enumerating DNS records for [bold magenta]{self.domain}[/bold magenta]")
        start = datetime.now()

        results: dict[str, list] = {}
        for record_type in RECORD_TYPES:
            records = self._query_record(record_type)
            if records:
                results[record_type] = records
                logger.info(
                    f"  [green]✓[/green] {record_type}: {len(records)} record(s)"
                )
            else:
                logger.debug(f"  [dim]✗ {record_type}: no records[/dim]")

        duration = (datetime.now() - start).total_seconds()

        email_sec = self.audit_email_security()
        dnssec_sec = self.audit_dnssec()

        self._results = {
            "domain": self.domain,
            "nameserver": self.nameserver or "system default",
            "timestamp": datetime.now().isoformat(),
            "duration": round(duration, 2),
            "records": results,
            "total_records": sum(len(v) for v in results.values()),
            "security": {
                "dmarc": {
                    "has_dmarc": email_sec["dmarc"]["present"],
                    "policy": email_sec["dmarc"].get("policy", "missing"),
                    "raw": email_sec["dmarc"].get("raw", ""),
                },
                "spf": {
                    "has_spf": email_sec["spf"]["present"],
                    "policy": email_sec["spf"].get("policy", "missing"),
                    "raw": email_sec["spf"].get("raw", ""),
                },
                "email": email_sec,
                "dnssec": dnssec_sec,
            },
        }

        return self._results

    def enumerate_type(self, record_type: str) -> list[dict[str, str]]:
        """
        Enumerate a specific record type.

        Args:
            record_type: DNS record type string.

        Returns:
            List of record dictionaries.
        """
        record_type = record_type.upper()
        if record_type not in RECORD_TYPES:
            logger.warning(f"Unsupported record type: {record_type}")
            return []
        return self._query_record(record_type)

    def reverse_lookup(self, ip: str) -> dict[str, str]:
        """
        Perform reverse DNS lookup.

        Args:
            ip: IP address to reverse lookup.

        Returns:
            Dictionary with PTR record info.
        """
        try:
            hostname, aliases, _ = socket.gethostbyaddr(ip)
            return {
                "ip": ip,
                "hostname": hostname,
                "aliases": aliases,
            }
        except (socket.herror, socket.gaierror) as e:
            logger.debug(f"Reverse lookup failed for {ip}: {e}")
            return {"ip": ip, "hostname": "", "aliases": []}

    def check_zone_transfer(self) -> list[dict[str, str]]:
        """
        Attempt DNS zone transfer (AXFR).

        Returns:
            List of records obtained from zone transfer, or empty list.
        """
        logger.info(f"Attempting zone transfer for [bold]{self.domain}[/bold]")
        records = []

        try:
            import dns.resolver
            import dns.zone
            import dns.query

            # Get nameservers
            ns_records = self._query_record("NS")
            if not ns_records:
                logger.warning("No NS records found — cannot attempt zone transfer.")
                return []

            for ns in ns_records:
                ns_addr = ns["value"].rstrip(".")
                try:
                    ns_ip = socket.gethostbyname(ns_addr)
                    zone = dns.zone.from_xfr(
                        dns.query.xfr(ns_ip, self.domain, timeout=self.timeout)
                    )
                    for name, node in zone.nodes.items():
                        for rdataset in node.rdatasets:
                            for rdata in rdataset:
                                records.append({
                                    "name": str(name),
                                    "type": dns.rdatatype.to_text(rdataset.rdtype),
                                    "value": str(rdata),
                                    "ttl": rdataset.ttl,
                                })
                    if records:
                        logger.info(
                            f"[bold red]⚠ Zone transfer successful![/bold red] "
                            f"Retrieved {len(records)} records from {ns_addr}"
                        )
                        return records
                except Exception as e:
                    logger.debug(f"Zone transfer failed for {ns_addr}: {e}")

        except ImportError:
            logger.warning("dnspython required for zone transfer attempts.")

        if not records:
            logger.info("[green]Zone transfer denied (good security)[/green]")

        return records

    def detect_wildcard(self) -> bool:
        """
        Detect wildcard DNS configuration.

        Returns:
            True if wildcard DNS is detected.
        """
        import random
        import string

        random_sub = "".join(random.choices(string.ascii_lowercase, k=16))
        test_domain = f"{random_sub}.{self.domain}"

        try:
            socket.gethostbyname(test_domain)
            logger.warning(
                f"[yellow]⚠ Wildcard DNS detected for {self.domain}[/yellow]"
            )
            return True
        except socket.gaierror:
            return False

    def audit_email_security(self) -> dict[str, Any]:
        """
        Comprehensive DNS email security audit (SPF, DMARC, DKIM).
        Evaluates email spoofing exposure and anti-phishing posture.

        Returns:
            Dictionary containing SPF and DMARC status, policies, and identified issues.
        """
        results: dict[str, Any] = {
            "domain": self.domain,
            "spf": {"present": False, "raw": "", "policy": "missing", "issues": []},
            "dmarc": {"present": False, "raw": "", "policy": "missing", "rua": "", "issues": []},
            "dkim_selectors_checked": [],
            "dkim_found": [],
            "issues": [],
        }

        # 1. Query SPF (TXT records on base domain)
        txt_records = self._query_record("TXT")
        for rec in txt_records:
            val = rec.get("value", "").strip("\"'")
            if val.startswith("v=spf1"):
                results["spf"]["present"] = True
                results["spf"]["raw"] = val
                parts = val.split()
                all_mech = next((p for p in parts if p.endswith("all")), "")
                if all_mech in ("+all", "all"):
                    results["spf"]["policy"] = "+all"
                    issue = "Critical: SPF has '+all' (permissive) — anyone can spoof emails as this domain!"
                    results["spf"]["issues"].append(issue)
                    results["issues"].append({"severity": "critical", "issue": issue})
                elif all_mech == "?all":
                    results["spf"]["policy"] = "?all"
                    issue = "Warning: SPF has '?all' (neutral) — spoofed emails may not be marked as spam."
                    results["spf"]["issues"].append(issue)
                    results["issues"].append({"severity": "medium", "issue": issue})
                elif all_mech == "~all":
                    results["spf"]["policy"] = "~all (softfail)"
                elif all_mech == "-all":
                    results["spf"]["policy"] = "-all (hardfail/strict)"
                break

        if not results["spf"]["present"]:
            issue = "Missing SPF record — domain lacks basic email sender authentication."
            results["spf"]["issues"].append(issue)
            results["issues"].append({"severity": "medium", "issue": issue})

        # 2. Query DMARC (_dmarc.<domain>)
        try:
            dmarc_domain = f"_dmarc.{self.domain}"
            answers = self._resolve_query(dmarc_domain, "TXT")
            for ans in answers:
                val = str(ans).strip("\"'")
                if "v=DMARC1" in val:
                    results["dmarc"]["present"] = True
                    results["dmarc"]["raw"] = val
                    p_match = re.search(r"p\s*=\s*([a-zA-Z]+)", val)
                    policy = p_match.group(1).lower() if p_match else "none"
                    results["dmarc"]["policy"] = policy

                    rua_match = re.search(r"rua\s*=\s*([^;]+)", val)
                    if rua_match:
                        results["dmarc"]["rua"] = rua_match.group(1).strip()

                    if policy == "none":
                        issue = "Weak DMARC policy (p=none) — policy is in monitoring mode only; spoofed emails are NOT rejected."
                        results["dmarc"]["issues"].append(issue)
                        results["issues"].append({"severity": "medium", "issue": issue})
                    break
        except Exception:
            pass

        # Subdomain DMARC inheritance fallback (RFC 7489)
        # If subdomain lacks direct DMARC record, check parent organizational domain
        if not results["dmarc"]["present"]:
            parts = self.domain.split(".")
            if len(parts) > 2:
                org_domain = ".".join(parts[-2:])
                try:
                    org_dmarc = f"_dmarc.{org_domain}"
                    answers = self._resolve_query(org_dmarc, "TXT")
                    for ans in answers:
                        val = str(ans).strip("\"'")
                        if "v=DMARC1" in val:
                            sp_match = re.search(r"sp\s*=\s*([a-zA-Z]+)", val)
                            p_match = re.search(r"p\s*=\s*([a-zA-Z]+)", val)
                            # Subdomain policy sp takes precedence; otherwise falls back to p
                            policy = sp_match.group(1).lower() if sp_match else (p_match.group(1).lower() if p_match else "none")
                            results["dmarc"]["present"] = True
                            results["dmarc"]["raw"] = f"{val} (inherited from {org_domain})"
                            results["dmarc"]["policy"] = policy

                            if policy == "none":
                                issue = f"Inherited DMARC policy from {org_domain} is 'p/sp=none' (monitoring only)."
                                results["dmarc"]["issues"].append(issue)
                                results["issues"].append({"severity": "medium", "issue": issue})
                            break
                except Exception:
                    pass

        if not results["dmarc"]["present"]:
            issue = "Missing DMARC record — domain lacks DMARC protection against email spoofing."
            results["dmarc"]["issues"].append(issue)
            results["issues"].append({"severity": "high", "issue": issue})

        # 3. Check common DKIM selectors
        common_selectors = ["default", "google", "k1", "mail", "s1"]
        results["dkim_selectors_checked"] = common_selectors
        try:
            for sel in common_selectors:
                dkim_domain = f"{sel}._domainkey.{self.domain}"
                try:
                    ans = self._resolve_query(dkim_domain, "TXT")
                    for a in ans:
                        if "v=DKIM1" in str(a) or "p=" in str(a):
                            results["dkim_found"].append(sel)
                            break
                except Exception:
                    continue
        except Exception:
            pass

        return results

    def audit_dnssec(self) -> dict[str, Any]:
        """
        Comprehensive DNSSEC (Domain Name System Security Extensions) posture audit.
        Validates presence of DNSKEY and DS records to prevent DNS cache poisoning
        and rogue resolver redirection.

        Returns:
            Dictionary containing DNSSEC status, records found, and identified issues.
        """
        results: dict[str, Any] = {
            "domain": self.domain,
            "enabled": False,
            "has_dnskey": False,
            "has_ds": False,
            "dnskey_records": [],
            "ds_records": [],
            "status": "Disabled",
            "issues": [],
        }

        try:
            dnskey = self._query_record("DNSKEY")
            if dnskey:
                results["has_dnskey"] = True
                results["dnskey_records"] = [r.get("value", "") for r in dnskey]

            ds = self._query_record("DS")
            if ds:
                results["has_ds"] = True
                results["ds_records"] = [r.get("value", "") for r in ds]

            if results["has_dnskey"] or results["has_ds"]:
                results["enabled"] = True
                results["status"] = "Enabled"
            else:
                results["status"] = "Disabled"
                issue = (
                    f"DNSSEC is not enabled for '{self.domain}'. "
                    "Responses lack cryptographic verification against cache poisoning and BGP hijacking."
                )
                results["issues"].append(issue)
        except Exception as e:
            logger.debug(f"DNSSEC audit error for {self.domain}: {e}")
            results["status"] = "Error"

        return results
