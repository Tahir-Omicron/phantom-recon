"""
Phantom Recon — Advanced Port Scanner.

Multi-threaded TCP/UDP port scanner with service detection, banner grabbing,
and OS fingerprinting support.

⚠️ DISCLAIMER: For authorized security testing only. Always obtain proper
written authorization before scanning any systems you do not own.
"""

import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional

from phantom_recon.utils.logger import get_logger, create_progress, console
from phantom_recon.utils.validators import parse_ports, validate_ip, validate_domain, TOP_100_PORTS

logger = get_logger(__name__)

# ─── Well-known service mapping ─────────────────────────────────
COMMON_SERVICES: dict[int, str] = {
    7: "echo", 9: "discard", 13: "daytime", 21: "ftp", 22: "ssh",
    23: "telnet", 25: "smtp", 37: "time", 53: "dns", 67: "dhcp",
    68: "dhcp", 69: "tftp", 79: "finger", 80: "http", 81: "http-alt",
    88: "kerberos", 110: "pop3", 111: "rpcbind", 113: "ident",
    119: "nntp", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    162: "snmptrap", 179: "bgp", 389: "ldap", 427: "svrloc",
    443: "https", 445: "microsoft-ds", 465: "smtps", 500: "isakmp",
    513: "rlogin", 514: "syslog", 515: "printer", 520: "rip",
    523: "ibm-db2", 543: "klogin", 544: "kshell", 548: "afp",
    554: "rtsp", 587: "submission", 631: "ipp", 636: "ldaps",
    646: "ldp", 873: "rsync", 990: "ftps", 993: "imaps", 995: "pop3s",
    1025: "nfs", 1080: "socks", 1099: "rmiregistry", 1433: "mssql",
    1434: "mssql-m", 1521: "oracle", 1723: "pptp", 1883: "mqtt",
    2049: "nfs", 2082: "cpanel", 2083: "cpanels", 2181: "zookeeper",
    2375: "docker", 2376: "docker-s", 3000: "grafana", 3128: "squid",
    3306: "mysql", 3389: "rdp", 3690: "svn", 4443: "https-alt",
    5000: "upnp", 5432: "postgresql", 5060: "sip", 5222: "xmpp",
    5432: "postgresql", 5631: "pcanywhere", 5672: "amqp", 5900: "vnc",
    5984: "couchdb", 6000: "x11", 6379: "redis", 6443: "kubernetes",
    6667: "irc", 7001: "weblogic", 8000: "http-alt", 8008: "http-alt",
    8009: "ajp13", 8080: "http-proxy", 8081: "http-alt", 8443: "https-alt",
    8888: "http-alt", 9000: "cslistener", 9090: "prometheus",
    9092: "kafka", 9100: "jetdirect", 9200: "elasticsearch",
    9300: "elasticsearch", 9418: "git", 9999: "abyss", 10000: "webmin",
    11211: "memcached", 27017: "mongodb", 27018: "mongodb",
    28017: "mongodb-web", 50000: "db2", 50070: "hadoop",
}


@dataclass
class ScanResult:
    """Represents a single port scan result."""
    port: int
    state: str  # open, closed, filtered
    protocol: str = "tcp"
    service: str = ""
    banner: str = ""
    version: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "state": self.state,
            "protocol": self.protocol,
            "service": self.service,
            "banner": self.banner,
            "version": self.version,
        }


class PortScanner:
    """
    Advanced multi-threaded port scanner.

    Supports TCP Connect scanning, banner grabbing, service detection,
    and configurable thread counts for high-performance scanning.

    Usage:
        scanner = PortScanner(target="192.168.1.1", ports="1-1000")
        results = scanner.scan()
    """

    def __init__(
        self,
        target: str,
        ports: str = "1-1000",
        threads: int = 50,
        timeout: float = 2.0,
        scan_type: str = "connect",
        callback: Optional[Callable] = None,
    ):
        """
        Initialize the port scanner.

        Args:
            target: Target IP address or hostname.
            ports: Port specification string (e.g., '80', '1-1000', '22,80,443').
            threads: Number of concurrent scanning threads.
            timeout: Socket timeout in seconds.
            scan_type: Scan type ('connect' or 'udp').
            callback: Optional callback for progress updates.
        """
        self.target = target
        self.port_spec = ports
        self.threads = min(threads, 500)  # Safety cap
        self.timeout = timeout
        self.scan_type = scan_type
        self.callback = callback
        self._results: list[ScanResult] = []
        self._lock = threading.Lock()
        self._resolved_ip: Optional[str] = None
        self._start_time: Optional[datetime] = None
        self._end_time: Optional[datetime] = None

    def _resolve_target(self) -> str:
        """Resolve hostname to IP address."""
        if validate_ip(self.target):
            return self.target
        try:
            ip = socket.gethostbyname(self.target)
            logger.info(f"Resolved [bold]{self.target}[/bold] → [cyan]{ip}[/cyan]")
            return ip
        except socket.gaierror:
            raise ValueError(f"Cannot resolve hostname: {self.target}")

    def _tcp_connect_scan(self, port: int) -> ScanResult:
        """
        Perform a TCP connect scan on a single port.

        Args:
            port: Port number to scan.

        Returns:
            ScanResult with port state and optional banner.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result_code = sock.connect_ex((self._resolved_ip, port))

            if result_code == 0:
                # Port is open — try banner grab
                banner = self._grab_banner(sock, port)
                service = COMMON_SERVICES.get(port, "unknown")
                sock.close()
                return ScanResult(
                    port=port,
                    state="open",
                    protocol="tcp",
                    service=service,
                    banner=banner,
                )
            else:
                sock.close()
                return ScanResult(port=port, state="closed", protocol="tcp")
        except socket.timeout:
            return ScanResult(port=port, state="filtered", protocol="tcp")
        except ConnectionRefusedError:
            return ScanResult(port=port, state="closed", protocol="tcp")
        except OSError:
            return ScanResult(port=port, state="filtered", protocol="tcp")

    def _udp_scan(self, port: int) -> ScanResult:
        """
        Perform a UDP scan on a single port.

        Args:
            port: Port number to scan.

        Returns:
            ScanResult with port state.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(b"\x00", (self._resolved_ip, port))
            try:
                data, _ = sock.recvfrom(1024)
                sock.close()
                service = COMMON_SERVICES.get(port, "unknown")
                return ScanResult(
                    port=port,
                    state="open",
                    protocol="udp",
                    service=service,
                    banner=data.decode("utf-8", errors="replace").strip()[:100],
                )
            except socket.timeout:
                sock.close()
                return ScanResult(
                    port=port,
                    state="open|filtered",
                    protocol="udp",
                    service=COMMON_SERVICES.get(port, "unknown"),
                )
        except OSError:
            return ScanResult(port=port, state="closed", protocol="udp")

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        """
        Attempt to grab a service banner from an open port.

        Args:
            sock: Connected socket.
            port: Port number (used for protocol-specific probes).

        Returns:
            Banner string, or empty string if failed.
        """
        try:
            # Send protocol-specific probes
            if port in (80, 8080, 8000, 8008, 8081, 8443, 443):
                sock.sendall(
                    f"HEAD / HTTP/1.1\r\nHost: {self.target}\r\nConnection: close\r\n\r\n".encode()
                )
            elif port == 21:
                pass  # FTP sends banner on connect
            elif port == 22:
                pass  # SSH sends banner on connect
            elif port == 25:
                pass  # SMTP sends banner on connect
            else:
                sock.sendall(b"\r\n")

            sock.settimeout(2.0)
            banner_data = sock.recv(1024)
            return banner_data.decode("utf-8", errors="replace").strip()[:200]
        except (socket.timeout, OSError, UnicodeDecodeError):
            return ""

    def _scan_port(self, port: int) -> ScanResult:
        """Scan a single port using the configured scan type."""
        if self.scan_type == "udp":
            return self._udp_scan(port)
        else:
            return self._tcp_connect_scan(port)

    def scan(self) -> dict[str, Any]:
        """
        Execute the port scan.

        Returns:
            Dictionary containing scan results, metadata, and statistics.
        """
        self._start_time = datetime.now()
        self._resolved_ip = self._resolve_target()

        # Check if resolved IP belongs to a known cloud WAF/CDN proxy network
        from phantom_recon.core.waf_detector import WAFDetector
        is_waf, waf_provider = WAFDetector.is_ip_in_waf_cidr(self._resolved_ip)
        waf_warning = None
        if is_waf:
            waf_warning = (
                f"Target IP {self._resolved_ip} belongs to {waf_provider} CDN/WAF proxy network. "
                f"Port scan probes {waf_provider} Anycast edge nodes, not the internal backend origin."
            )
            logger.warning(
                f"[bold yellow]⚠️ NOTICE:[/bold yellow] Target IP [cyan]{self._resolved_ip}[/cyan] belongs to "
                f"[bold red]{waf_provider}[/bold red] CDN/WAF proxy network!\n"
                f"  [yellow]→ Port scanning will probe {waf_provider} Anycast edge nodes, NOT the internal backend origin.[/yellow]\n"
                f"  [yellow]→ Use 'phantom waf -t {self.target}' to audit for unproxied origin IP leakage.[/yellow]"
            )

        # Parse ports
        if self.port_spec.lower() == "top100":
            ports = TOP_100_PORTS
        elif self.port_spec.lower() == "all":
            ports = list(range(1, 65536))
        else:
            ports = parse_ports(self.port_spec)

        logger.info(
            f"Scanning [bold magenta]{self.target}[/bold magenta] "
            f"({self._resolved_ip}) — {len(ports)} ports — "
            f"{self.scan_type.upper()} scan"
        )

        open_ports: list[ScanResult] = []
        filtered_ports: list[ScanResult] = []

        with create_progress() as progress:
            task = progress.add_task(
                f"Scanning {self.target}", total=len(ports)
            )

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {
                    executor.submit(self._scan_port, port): port
                    for port in ports
                }

                for future in as_completed(futures):
                    result = future.result()
                    progress.advance(task)

                    if result.state == "open":
                        open_ports.append(result)
                        if self.callback:
                            self.callback(result)
                    elif result.state in ("filtered", "open|filtered"):
                        filtered_ports.append(result)

                    with self._lock:
                        self._results.append(result)

        self._end_time = datetime.now()
        duration = (self._end_time - self._start_time).total_seconds()

        # Sort results
        open_ports.sort(key=lambda r: r.port)
        filtered_ports.sort(key=lambda r: r.port)

        return {
            "target": self.target,
            "ip": self._resolved_ip,
            "is_waf_proxy": is_waf,
            "waf_provider": waf_provider if is_waf else None,
            "waf_warning": waf_warning,
            "scan_type": self.scan_type,
            "start_time": self._start_time.isoformat(),
            "end_time": self._end_time.isoformat(),
            "duration": round(duration, 2),
            "total_ports_scanned": len(ports),
            "open_ports_count": len(open_ports),
            "filtered_ports_count": len(filtered_ports),
            "ports": {
                r.port: r.to_dict() for r in open_ports
            },
            "filtered": {
                r.port: r.to_dict() for r in filtered_ports
            },
        }

    def get_open_ports(self) -> list[ScanResult]:
        """Return list of open ports from last scan."""
        return [r for r in self._results if r.state == "open"]

    def quick_scan(self) -> dict[str, Any]:
        """Run a quick scan on top 20 common ports."""
        self.port_spec = ",".join(str(p) for p in [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
            443, 445, 993, 995, 3306, 3389, 5900, 8080, 8443, 9090
        ])
        return self.scan()
