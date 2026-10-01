"""
Phantom Recon — WHOIS Lookup.

Domain and IP WHOIS information retrieval including registrar,
creation/expiry dates, nameservers, and contact information.

⚠️ DISCLAIMER: For authorized security testing only.
"""

from datetime import datetime
from typing import Any, Optional

from phantom_recon.utils.logger import get_logger, console
from phantom_recon.utils.validators import validate_ip, validate_domain

logger = get_logger(__name__)


class WhoisLookup:
    """
    WHOIS information lookup tool.

    Retrieves domain/IP registration details including registrar info,
    creation/expiry dates, and nameservers.

    Usage:
        whois = WhoisLookup(target="example.com")
        info = whois.lookup()
    """

    def __init__(self, target: str):
        """
        Initialize WHOIS lookup.

        Args:
            target: Domain name or IP address.
        """
        self.target = target
        self._result: dict[str, Any] = {}

    def lookup(self) -> dict[str, Any]:
        """
        Perform WHOIS lookup.

        Returns:
            Dictionary with WHOIS information.
        """
        logger.info(f"WHOIS lookup for [bold magenta]{self.target}[/bold magenta]")

        try:
            import whois

            w = whois.whois(self.target)

            self._result = {
                "target": self.target,
                "domain_name": self._normalize(w.domain_name),
                "registrar": w.registrar or "N/A",
                "whois_server": w.whois_server or "N/A",
                "creation_date": self._format_date(w.creation_date),
                "expiration_date": self._format_date(w.expiration_date),
                "updated_date": self._format_date(w.updated_date),
                "name_servers": self._normalize_list(w.name_servers),
                "status": self._normalize_list(w.status),
                "emails": self._normalize_list(w.emails),
                "dnssec": w.dnssec or "N/A",
                "name": w.name or "N/A",
                "org": w.org or "N/A",
                "address": w.address or "N/A",
                "city": w.city or "N/A",
                "state": w.state or "N/A",
                "zipcode": w.zipcode or "N/A",
                "country": w.country or "N/A",
                "registrant_postal_code": getattr(w, "registrant_postal_code", "N/A"),
                "timestamp": datetime.now().isoformat(),
            }

            # Calculate days until expiry
            if w.expiration_date:
                exp = w.expiration_date
                if isinstance(exp, list):
                    exp = exp[0]
                if isinstance(exp, datetime):
                    days = (exp - datetime.now()).days
                    self._result["days_until_expiry"] = days
                    if days < 30:
                        logger.warning(
                            f"[yellow]⚠ Domain expires in {days} days![/yellow]"
                        )

        except ImportError:
            logger.warning("python-whois required: pip install python-whois")
            self._result = {
                "target": self.target,
                "error": "python-whois library not installed",
            }
        except Exception as e:
            logger.error(f"WHOIS lookup failed: {e}")
            self._result = {
                "target": self.target,
                "error": str(e),
            }

        return self._result

    def _normalize(self, value: Any) -> str:
        """Normalize a WHOIS value to string."""
        if isinstance(value, list):
            return value[0] if value else "N/A"
        return str(value) if value else "N/A"

    def _normalize_list(self, value: Any) -> list[str]:
        """Normalize a WHOIS value to a list of strings."""
        if isinstance(value, list):
            return [str(v) for v in value]
        elif value:
            return [str(value)]
        return []

    def _format_date(self, date_val: Any) -> str:
        """Format a WHOIS date value."""
        if isinstance(date_val, list):
            date_val = date_val[0] if date_val else None
        if isinstance(date_val, datetime):
            return date_val.strftime("%Y-%m-%d %H:%M:%S")
        return str(date_val) if date_val else "N/A"

    def bulk_lookup(self, targets: list[str]) -> list[dict[str, Any]]:
        """
        Perform WHOIS lookup on multiple targets.

        Args:
            targets: List of domains/IPs.

        Returns:
            List of WHOIS result dictionaries.
        """
        results = []
        for target in targets:
            self.target = target
            results.append(self.lookup())
        return results
