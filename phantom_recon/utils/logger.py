"""
Phantom Recon — Rich logging and console output utilities.

Provides colorized console output, progress bars, tables, and ASCII art
banners for the Phantom Recon penetration testing toolkit.

⚠️ DISCLAIMER: For authorized security testing only.
"""

import logging
import sys
from datetime import datetime
from typing import Any, Optional

from rich import box
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

# Reconfigure Windows standard streams to UTF-8 to prevent charmap encoding errors
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ─── Custom Theme ───────────────────────────────────────────────
PHANTOM_THEME = Theme(
    {
        "info": "cyan",
        "warning": "yellow",
        "error": "bold red",
        "success": "bold green",
        "critical": "bold white on red",
        "target": "bold magenta",
        "port.open": "bold green",
        "port.closed": "dim red",
        "port.filtered": "yellow",
        "severity.critical": "bold white on red",
        "severity.high": "bold red",
        "severity.medium": "bold yellow",
        "severity.low": "bold blue",
        "severity.info": "dim cyan",
    }
)

console = Console(theme=PHANTOM_THEME, legacy_windows=False if sys.platform == "win32" else None)

BANNER = r"""
[bold red]
    ____  __  _____    _   ___________  __  ___
   / __ \/ / / /   |  / | / /_  __/   |/  |/  /
  / /_/ / /_/ / /| | /  |/ / / / / /|_/ / /|_/ / 
 / ____/ __  / ___ |/ /|  / / / / /  / / /  / /  
/_/   /_/ /_/_/  |_/_/ |_/ /_/ /_/  /_/_/  /_/   
[/bold red]
[bold green]
    ____  ________________  _   __
   / __ \/ ____/ ____/ __ \/ | / /
  / /_/ / __/ / /   / / / /  |/ / 
 / _, _/ /___/ /___/ /_/ / /|  /  
/_/ |_/_____/\____/\____/_/ |_/   
[/bold green]
"""


def print_banner() -> None:
    """Print the Phantom Recon ASCII art banner."""
    console.print(BANNER)
    console.print(
        Panel(
            "[bold white]🔥 Advanced Penetration Testing & Reconnaissance Toolkit[/bold white]\n"
            "[dim]📌 Version 1.7.0 | Author: Tahir | License: MIT[/dim]\n"
            "[dim yellow]⚠️  For authorized security testing only[/dim yellow]",
            border_style="red",
            padding=(1, 2),
        )
    )
    console.print()


def print_command_palette() -> None:
    """
    Render an ultra-clean, categorized interactive command palette and cheat sheet.
    Tailored for cybersecurity students, analysts, and operators for immediate clarity.
    """
    console.print(
        Panel(
            "[bold cyan]⚡ PHANTOM RECON — COMMAND CENTER & OPERATIONAL PALETTE[/bold cyan]\n"
            "[dim]A unified ethical hacking framework for surface reconnaissance, vulnerability auditing & edge defense.[/dim]",
            border_style="cyan",
            padding=(0, 2),
        )
    )

    table = Table(
        title="Available Commands & Syntax Matrix",
        title_style="bold white",
        border_style="bright_blue",
        show_lines=True,
        header_style="bold cyan",
    )
    table.add_column("Category", style="bold yellow", width=18)
    table.add_column("Command", style="bold green", width=14)
    table.add_column("Syntax Example", style="cyan", width=38)
    table.add_column("Operational Purpose", style="white")

    # Category: Surface Reconnaissance
    table.add_row(
        "🌐 Surface Recon",
        "scan",
        "phantom scan -t 192.168.1.1 -p 80,443",
        "Multi-threaded TCP/UDP port scanner with banner grabbing & WAF notice."
    )
    table.add_row(
        "🌐 Surface Recon",
        "recon",
        "phantom recon -u https://site.com --full",
        "Web tech stack fingerprinting, form extraction & directory crawler."
    )
    table.add_row(
        "🌐 Surface Recon",
        "subdomain",
        "phantom subdomain -d site.com --ct-logs",
        "Discover subdomains via Certificate Transparency & DNS brute force."
    )
    table.add_row(
        "🌐 Surface Recon",
        "dns",
        "phantom dns -d site.com --type all",
        "DNS records (A, MX, TXT, NS, SOA), zone transfers & SPF/DMARC spoof check."
    )
    table.add_row(
        "🌐 Surface Recon",
        "whois",
        "phantom whois -t site.com",
        "Domain registration, expiration dates, registrar, and nameservers."
    )

    # Category: Vulnerability & Defense
    table.add_row(
        "🛡️ Vuln & Defense",
        "vuln",
        "phantom vuln -u https://site.com",
        "Ultra-precision vulnerability scanner (Zero False Positive) + PoC cURLs."
    )
    table.add_row(
        "🛡️ Vuln & Defense",
        "waf",
        "phantom waf -t site.com",
        "Cloud WAF/CDN detector (10 vendors) & unproxied origin IP leakage audit."
    )
    table.add_row(
        "🛡️ Vuln & Defense",
        "cloud",
        "phantom cloud -t site.com",
        "Multi-cloud storage auditor: AWS S3, GCP, Azure Blob bucket leaks."
    )
    table.add_row(
        "🛡️ Vuln & Defense",
        "api",
        "phantom api -u https://site.com",
        "API discovery: Swagger/OpenAPI schemas, GraphQL & Spring Actuators."
    )
    table.add_row(
        "🛡️ Vuln & Defense",
        "ssl",
        "phantom ssl -h site.com",
        "SSL/TLS protocol inspector, cipher evaluation & DER binary cert parser."
    )

    # Category: Network & Access
    table.add_row(
        "⚙️ Network & Auth",
        "network",
        "phantom network -t 192.168.1.0/24",
        "Local CIDR subnet live host discovery (ping sweep) & route traceroute."
    )
    table.add_row(
        "⚙️ Network & Auth",
        "brute",
        "phantom brute -t host -s ssh -u usr.txt",
        "Rate-limited credential verification for SSH, FTP, and HTTP Basic."
    )

    # Category: Master Automation & Reports
    table.add_row(
        "📊 Master & Report",
        "full",
        "phantom full -t site.com -o report.html",
        "Master 11-step full reconnaissance pipeline + interactive report."
    )
    table.add_row(
        "📊 Master & Report",
        "report",
        "phantom report -i scan.json -f html",
        "Convert scan JSON into Dark Glassmorphism HTML, CSV, or Markdown."
    )
    table.add_row(
        "📊 Master & Report",
        "help",
        "phantom help",
        "Display this structured interactive command palette and cheat sheet."
    )

    console.print(table)

    # Quick Start Cheat Sheet Panel
    console.print(
        Panel(
            "[bold white]🚀 Quick-Start Command Cheat Sheet:[/bold white]\n"
            "  [dim]•[/dim] [cyan]phantom vuln -u https://example.com -o report.html[/cyan]  → [dim]Full web vulnerability assessment + HTML dashboard[/dim]\n"
            "  [dim]•[/dim] [cyan]phantom cloud -t example.com[/cyan]                        → [dim]Audit AWS S3, GCP & Azure for publicly exposed buckets[/dim]\n"
            "  [dim]•[/dim] [cyan]phantom waf -t example.com[/cyan]                         → [dim]Detect WAF front & audit for leaked origin server IPs[/dim]\n"
            "  [dim]•[/dim] [cyan]phantom api -u https://example.com[/cyan]                         → [dim]Discover OpenAPI/Swagger schemas & GraphQL routes[/dim]\n"
            "  [dim]•[/dim] [cyan]phantom full -t example.com[/cyan]                        → [dim]End-to-end 11-stage autonomous penetration test recon[/dim]\n"
            "  [dim]•[/dim] [cyan]phantom scan -t 192.168.1.1 -p top100[/cyan]              → [dim]Scan top 100 ports with banner grabbing[/dim]",
            title="[bold yellow]💡 Pro Tips[/bold yellow]",
            border_style="yellow",
            padding=(0, 2),
        )
    )
    console.print()


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """
    Create a rich-powered logger instance.

    Args:
        name: Logger name (usually __name__).
        level: Logging level.

    Returns:
        Configured logging.Logger instance.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = RichHandler(
            console=console,
            show_time=True,
            show_path=False,
            markup=True,
            rich_tracebacks=True,
        )
        handler.setLevel(level)
        formatter = logging.Formatter("%(message)s", datefmt="[%X]")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(level)
    return logger


def create_progress() -> Progress:
    """Create a rich progress bar for scanning operations."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=40),
        MofNCompleteColumn(),
        TextColumn("•"),
        TimeElapsedColumn(),
        TextColumn("•"),
        TimeRemainingColumn(),
        console=console,
    )


def print_results_table(
    title: str,
    columns: list[tuple[str, str]],
    rows: list[list[str]],
    border_style: str = "cyan",
) -> None:
    """
    Print a formatted results table.

    Args:
        title: Table title.
        columns: List of (name, style) tuples.
        rows: List of row data lists.
        border_style: Border color.
    """
    table = Table(title=title, border_style=border_style, show_lines=True)
    for col_name, col_style in columns:
        table.add_column(col_name, style=col_style)
    for row in rows:
        table.add_row(*row)
    console.print(table)
    console.print()


def print_vulnerabilities_matrix(
    vulns: list[dict],
    title: str = "Vulnerability Assessment & Explanations Matrix",
) -> None:
    """
    Render an executive and technical vulnerability matrix table.
    Presents severity, title, location, technical explanation of what the vulnerability is,
    and actionable remediation guidance in a structured, readable table.
    """
    if not vulns:
        return

    table = Table(
        title=f"🛡️  {title}",
        title_style="bold red",
        border_style="bright_blue",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold cyan",
    )
    table.add_column("#", justify="center", style="bold dim", width=4)
    table.add_column("Severity", justify="center", width=12)
    table.add_column("Vulnerability Name", style="bold white", width=26)
    table.add_column("Affected Location", style="cyan", width=22)
    table.add_column("Description & Impact (Nədir & Təsiri)", style="white", min_width=32)
    table.add_column("Remediation / Fix Guidance", style="green", min_width=26)

    for idx, v in enumerate(vulns, 1):
        if not isinstance(v, dict):
            continue
        sev = v.get("severity", "info")
        badge = severity_badge(sev)
        title_text = v.get("title", "Finding")
        if v.get("cve"):
            title_text += f"\n[dim yellow]({v['cve']})[/dim yellow]"
        if v.get("cvss_score"):
            badge += f"\n[dim]CVSS {v['cvss_score']}[/dim]"
        loc = v.get("location", "Global Target")
        desc = v.get("description", "No description provided.")
        remedy = v.get("remediation", "Review application security policy.")

        table.add_row(
            str(idx),
            badge,
            title_text,
            loc,
            desc,
            remedy,
        )

    console.print(table)
    console.print()


def success(msg: str) -> None:
    """Print a success message."""
    console.print(f"  [success]✓[/success] {msg}")


def error(msg: str) -> None:
    """Print an error message."""
    console.print(f"  [error]✗[/error] {msg}")


def warning(msg: str) -> None:
    """Print a warning message."""
    console.print(f"  [warning]⚠[/warning] {msg}")


def info(msg: str) -> None:
    """Print an info message."""
    console.print(f"  [info]ℹ[/info] {msg}")


def section_header(title: str) -> None:
    """Print a section header."""
    console.print()
    console.print(Panel(f"[bold white]{title}[/bold white]", border_style="cyan"))


def severity_badge(severity: str) -> str:
    """Return a rich-formatted severity badge."""
    badges = {
        "critical": "[severity.critical] CRITICAL [/severity.critical]",
        "high": "[severity.high] HIGH [/severity.high]",
        "medium": "[severity.medium] MEDIUM [/severity.medium]",
        "low": "[severity.low] LOW [/severity.low]",
        "info": "[severity.info] INFO [/severity.info]",
    }
    return badges.get(severity.lower(), f"[dim]{severity}[/dim]")


def print_scan_summary(
    target: str, start_time: datetime, end_time: datetime, results_count: int
) -> None:
    """Print a scan summary panel."""
    duration = (end_time - start_time).total_seconds()
    console.print(
        Panel(
            f"[bold]Target:[/bold] [target]{target}[/target]\n"
            f"[bold]Started:[/bold] {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"[bold]Duration:[/bold] {duration:.2f}s\n"
            f"[bold]Results:[/bold] {results_count} items found",
            title="[bold green]📊 Scan Summary[/bold green]",
            border_style="green",
        )
    )
