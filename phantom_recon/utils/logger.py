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
 ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
 ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
 ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
 ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
 ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
 ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
[/bold red]
[bold cyan]
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
[/bold cyan]
"""


def print_banner() -> None:
    """Print the Phantom Recon ASCII art banner."""
    console.print(BANNER)
    console.print(
        Panel(
            "[bold white]🔥 Advanced Penetration Testing & Reconnaissance Toolkit[/bold white]\n"
            "[dim]📌 Version 1.5.1 | Author: Tahir | License: MIT[/dim]\n"
            "[dim yellow]⚠️  For authorized security testing only[/dim yellow]",
            border_style="red",
            padding=(1, 2),
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
