"""
Phantom Recon — Input validation utilities.

Validates IP addresses, domains, URLs, ports, CIDR ranges, and other inputs
used by the scanning and reconnaissance modules.

⚠️ DISCLAIMER: For authorized security testing only.
"""

import ipaddress
import re
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse


def validate_ip(ip: str) -> bool:
    """
    Validate an IPv4 or IPv6 address.

    Args:
        ip: IP address string to validate.

    Returns:
        True if valid, False otherwise.
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_ipv4(ip: str) -> bool:
    """Validate an IPv4 address."""
    try:
        addr = ipaddress.ip_address(ip)
        return isinstance(addr, ipaddress.IPv4Address)
    except ValueError:
        return False


def validate_ipv6(ip: str) -> bool:
    """Validate an IPv6 address."""
    try:
        addr = ipaddress.ip_address(ip)
        return isinstance(addr, ipaddress.IPv6Address)
    except ValueError:
        return False


def validate_cidr(cidr: str) -> bool:
    """
    Validate a CIDR notation network range.

    Args:
        cidr: CIDR string (e.g., '192.168.1.0/24').

    Returns:
        True if valid, False otherwise.
    """
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def validate_domain(domain: str) -> bool:
    """
    Validate a domain name.

    Args:
        domain: Domain name string to validate.

    Returns:
        True if valid, False otherwise.
    """
    pattern = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
    )
    return bool(pattern.match(domain))


def validate_url(url: str) -> bool:
    """
    Validate a URL.

    Args:
        url: URL string to validate.

    Returns:
        True if valid, False otherwise.
    """
    try:
        result = urlparse(url)
        return all([result.scheme in ("http", "https"), result.netloc])
    except Exception:
        return False


def validate_email(email: str) -> bool:
    """
    Validate an email address.

    Args:
        email: Email string to validate.

    Returns:
        True if valid, False otherwise.
    """
    pattern = re.compile(
        r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    )
    return bool(pattern.match(email))


def validate_port(port: int) -> bool:
    """
    Validate a single port number.

    Args:
        port: Port number (0-65535).

    Returns:
        True if valid, False otherwise.
    """
    return isinstance(port, int) and 0 <= port <= 65535


def parse_ports(port_string: str) -> list[int]:
    """
    Parse a port specification string into a list of port numbers.

    Supports:
        - Single port: '80'
        - Comma-separated: '80,443,8080'
        - Range: '1-1000'
        - Mixed: '22,80,443,8000-9000'

    Args:
        port_string: Port specification string.

    Returns:
        Sorted list of unique port numbers.

    Raises:
        ValueError: If port string is invalid.
    """
    ports: set[int] = set()
    parts = port_string.replace(" ", "").split(",")

    for part in parts:
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                start_port = int(start)
                end_port = int(end)
                if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535):
                    raise ValueError(f"Port out of range: {part}")
                if start_port > end_port:
                    raise ValueError(f"Invalid port range: {part}")
                ports.update(range(start_port, end_port + 1))
            except (ValueError, TypeError) as e:
                raise ValueError(f"Invalid port range '{part}': {e}")
        else:
            try:
                port = int(part)
                if not validate_port(port):
                    raise ValueError(f"Port out of range: {port}")
                ports.add(port)
            except ValueError:
                raise ValueError(f"Invalid port: '{part}'")

    return sorted(ports)


def validate_file_path(path: str, must_exist: bool = True) -> bool:
    """
    Validate a file path.

    Args:
        path: File path string.
        must_exist: Whether the file must already exist.

    Returns:
        True if valid, False otherwise.
    """
    try:
        p = Path(path)
        if must_exist:
            return p.is_file()
        return bool(p.parent.exists())
    except (OSError, TypeError):
        return False


def validate_target(target: str) -> str:
    """
    Determine the type of a target string.

    Args:
        target: Target string (IP, domain, CIDR, or URL).

    Returns:
        Target type: 'ipv4', 'ipv6', 'cidr', 'domain', 'url', or 'unknown'.
    """
    if validate_url(target):
        return "url"
    if validate_cidr(target) and "/" in target:
        return "cidr"
    if validate_ip(target):
        return "ipv4" if validate_ipv4(target) else "ipv6"
    if validate_domain(target):
        return "domain"
    return "unknown"


# ─── Common Port Lists ──────────────────────────────────────────
TOP_20_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
]

TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
    113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
    513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
    1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000,
    2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009,
    5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001,
    6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000,
    32768, 49152, 49153, 49154, 49155, 49156, 49157,
]
