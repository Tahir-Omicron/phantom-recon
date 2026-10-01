"""
Phantom Recon — Network Mapper.

Host discovery, ICMP ping sweep, traceroute, and network interface
enumeration for network reconnaissance.

⚠️ DISCLAIMER: For authorized security testing only.
"""

import ipaddress
import platform
import socket
import struct
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from phantom_recon.utils.logger import get_logger, create_progress, console
from phantom_recon.utils.validators import validate_ip, validate_cidr

logger = get_logger(__name__)


@dataclass
class HostInfo:
    """Information about a discovered host."""
    ip: str
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    is_alive: bool = False
    response_time: float = 0.0
    open_ports: list = None

    def __post_init__(self):
        if self.open_ports is None:
            self.open_ports = []

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "mac": self.mac,
            "vendor": self.vendor,
            "is_alive": self.is_alive,
            "response_time": self.response_time,
            "open_ports": self.open_ports,
        }


@dataclass
class TracerouteHop:
    """A single traceroute hop."""
    ttl: int
    ip: str
    hostname: str = ""
    rtt: float = 0.0
    timed_out: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "ttl": self.ttl,
            "ip": self.ip,
            "hostname": self.hostname,
            "rtt": round(self.rtt, 2),
            "timed_out": self.timed_out,
        }


class NetworkMapper:
    """
    Network mapping and host discovery tool.

    Provides host discovery via ICMP ping sweeps, TCP probes,
    traceroute functionality, and network interface enumeration.

    Usage:
        mapper = NetworkMapper(target="192.168.1.0/24")
        hosts = mapper.discover_hosts()
    """

    def __init__(
        self,
        target: str = "",
        threads: int = 50,
        timeout: float = 2.0,
    ):
        """
        Initialize the network mapper.

        Args:
            target: Target IP, hostname, or CIDR range.
            threads: Number of concurrent threads.
            timeout: Timeout for each probe in seconds.
        """
        self.target = target
        self.threads = min(threads, 256)
        self.timeout = timeout
        self._hosts: list[HostInfo] = []
        self._lock = threading.Lock()

    def _expand_cidr(self, cidr: str) -> list[str]:
        """Expand a CIDR range to a list of IP addresses."""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            return [cidr]

    def _ping_host(self, ip: str) -> HostInfo:
        """
        Ping a single host to check if it's alive.

        Args:
            ip: Target IP address.

        Returns:
            HostInfo with discovery results.
        """
        param = "-n" if platform.system().lower() == "windows" else "-c"
        timeout_param = "-w" if platform.system().lower() == "windows" else "-W"
        timeout_val = str(int(self.timeout * 1000)) if platform.system().lower() == "windows" else str(int(self.timeout))

        start = time.time()
        try:
            result = subprocess.run(
                ["ping", param, "1", timeout_param, timeout_val, ip],
                capture_output=True,
                text=True,
                timeout=self.timeout + 2,
            )
            rtt = round((time.time() - start) * 1000, 2)

            if result.returncode == 0:
                hostname = self._reverse_lookup(ip)
                return HostInfo(
                    ip=ip,
                    hostname=hostname,
                    is_alive=True,
                    response_time=rtt,
                )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        return HostInfo(ip=ip, is_alive=False)

    def _tcp_probe(self, ip: str, port: int = 80) -> bool:
        """
        TCP connect probe to check host availability.

        Args:
            ip: Target IP address.
            port: Port to probe.

        Returns:
            True if host responds.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except (socket.timeout, OSError):
            return False

    def _reverse_lookup(self, ip: str) -> str:
        """Perform reverse DNS lookup."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            return ""

    def discover_hosts(self) -> list[dict[str, Any]]:
        """
        Discover live hosts in the target range.

        Returns:
            List of discovered host dictionaries.
        """
        if not self.target:
            raise ValueError("No target specified.")

        # Expand CIDR or use single target
        if "/" in self.target and validate_cidr(self.target):
            targets = self._expand_cidr(self.target)
        else:
            targets = [self.target]

        logger.info(
            f"Discovering hosts in [bold magenta]{self.target}[/bold magenta] "
            f"({len(targets)} addresses)"
        )

        alive_hosts: list[HostInfo] = []

        with create_progress() as progress:
            task = progress.add_task("Pinging hosts", total=len(targets))

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {
                    executor.submit(self._ping_host, ip): ip
                    for ip in targets
                }

                for future in as_completed(futures):
                    host = future.result()
                    progress.advance(task)

                    if host.is_alive:
                        alive_hosts.append(host)
                        with self._lock:
                            self._hosts.append(host)

        alive_hosts.sort(key=lambda h: ipaddress.ip_address(h.ip))

        logger.info(
            f"Discovered [bold green]{len(alive_hosts)}[/bold green] "
            f"live hosts out of {len(targets)}"
        )

        return [h.to_dict() for h in alive_hosts]

    def traceroute(self, target: Optional[str] = None, max_hops: int = 30) -> list[dict[str, Any]]:
        """
        Perform a traceroute to the target.

        Args:
            target: Target IP or hostname (uses self.target if None).
            max_hops: Maximum number of hops.

        Returns:
            List of TracerouteHop dictionaries.
        """
        target = target or self.target
        if not target:
            raise ValueError("No target specified.")

        logger.info(f"Traceroute to [bold magenta]{target}[/bold magenta] (max {max_hops} hops)")

        hops: list[TracerouteHop] = []

        # Use system traceroute
        cmd = (
            ["tracert", "-d", "-h", str(max_hops), "-w", str(int(self.timeout * 1000)), target]
            if platform.system().lower() == "windows"
            else ["traceroute", "-n", "-m", str(max_hops), "-w", str(int(self.timeout)), target]
        )

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=max_hops * (self.timeout + 1),
            )

            for line in result.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("Tracing") or line.startswith("traceroute"):
                    continue

                parts = line.split()
                if not parts:
                    continue

                try:
                    ttl = int(parts[0])
                except ValueError:
                    continue

                if "*" in line and all(p in ("*", "ms") for p in parts[1:]):
                    hops.append(TracerouteHop(ttl=ttl, ip="*", timed_out=True))
                else:
                    # Extract IP and RTT
                    ip_addr = ""
                    rtt_val = 0.0
                    for part in parts[1:]:
                        if validate_ip(part):
                            ip_addr = part
                        elif part.replace(".", "").isdigit():
                            try:
                                rtt_val = float(part)
                            except ValueError:
                                pass

                    if ip_addr:
                        hostname = self._reverse_lookup(ip_addr)
                        hops.append(TracerouteHop(
                            ttl=ttl, ip=ip_addr, hostname=hostname, rtt=rtt_val
                        ))

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.warning(f"Traceroute failed: {e}")

        return [h.to_dict() for h in hops]

    def get_network_interfaces(self) -> list[dict[str, str]]:
        """
        Enumerate local network interfaces.

        Returns:
            List of interface info dictionaries.
        """
        interfaces = []
        try:
            hostname = socket.gethostname()
            addrs = socket.getaddrinfo(hostname, None)

            seen = set()
            for addr in addrs:
                ip = addr[4][0]
                if ip not in seen:
                    seen.add(ip)
                    interfaces.append({
                        "hostname": hostname,
                        "ip": ip,
                        "family": "IPv4" if addr[0] == socket.AF_INET else "IPv6",
                    })
        except (socket.gaierror, OSError) as e:
            logger.warning(f"Failed to enumerate interfaces: {e}")

        return interfaces
