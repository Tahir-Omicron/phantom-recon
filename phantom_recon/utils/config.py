"""
Phantom Recon — Configuration management.

Handles loading, saving, and merging configuration from files and
environment variables.

⚠️ DISCLAIMER: For authorized security testing only.
"""

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional


@dataclass
class ScannerConfig:
    """Port scanner configuration."""
    default_ports: str = "1-1000"
    scan_type: str = "connect"
    service_detection: bool = True
    timeout: float = 3.0
    threads: int = 50


@dataclass
class WebReconConfig:
    """Web reconnaissance configuration."""
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 PhantomRecon/1.5.0"
    follow_redirects: bool = True
    max_depth: int = 3
    timeout: float = 10.0
    verify_ssl: bool = True


@dataclass
class BruteForceConfig:
    """Brute force module configuration."""
    max_threads: int = 10
    delay: float = 0.5
    lockout_threshold: int = 5
    timeout: float = 10.0


@dataclass
class ReportingConfig:
    """Report generation configuration."""
    format: str = "html"
    include_remediation: bool = True
    severity_threshold: str = "low"
    output_dir: str = "./reports"


@dataclass
class PhantomConfig:
    """
    Main configuration for Phantom Recon.

    Aggregates all module-specific configurations and provides
    load/save functionality.
    """
    # General settings
    timeout: float = 10.0
    threads: int = 50
    verbose: bool = False
    output_format: str = "html"
    no_color: bool = False

    # Module-specific configs
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    web_recon: WebReconConfig = field(default_factory=WebReconConfig)
    brute_force: BruteForceConfig = field(default_factory=BruteForceConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)

    def to_dict(self) -> dict[str, Any]:
        """Convert config to dictionary."""
        return asdict(self)

    def save(self, path: str) -> None:
        """
        Save configuration to a JSON file.

        Args:
            path: File path to save to.
        """
        filepath = Path(path)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, path: str) -> "PhantomConfig":
        """
        Load configuration from a JSON file.

        Args:
            path: File path to load from.

        Returns:
            PhantomConfig instance.
        """
        filepath = Path(path)
        if not filepath.exists():
            return cls()

        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        config = cls()
        config._merge_dict(data)
        return config

    def _merge_dict(self, data: dict[str, Any]) -> None:
        """Merge a dictionary into this config."""
        for key, value in data.items():
            if key == "scanner" and isinstance(value, dict):
                for k, v in value.items():
                    if hasattr(self.scanner, k):
                        setattr(self.scanner, k, v)
            elif key == "web_recon" and isinstance(value, dict):
                for k, v in value.items():
                    if hasattr(self.web_recon, k):
                        setattr(self.web_recon, k, v)
            elif key == "brute_force" and isinstance(value, dict):
                for k, v in value.items():
                    if hasattr(self.brute_force, k):
                        setattr(self.brute_force, k, v)
            elif key == "reporting" and isinstance(value, dict):
                for k, v in value.items():
                    if hasattr(self.reporting, k):
                        setattr(self.reporting, k, v)
            elif hasattr(self, key):
                setattr(self, key, value)

    def apply_env_overrides(self) -> None:
        """Apply environment variable overrides."""
        env_map = {
            "PHANTOM_TIMEOUT": ("timeout", float),
            "PHANTOM_THREADS": ("threads", int),
            "PHANTOM_VERBOSE": ("verbose", lambda x: x.lower() in ("true", "1", "yes")),
            "PHANTOM_OUTPUT_DIR": ("reporting.output_dir", str),
            "PHANTOM_OUTPUT_FORMAT": ("output_format", str),
            "PHANTOM_USER_AGENT": ("web_recon.user_agent", str),
            "PHANTOM_NO_COLOR": ("no_color", lambda x: x.lower() in ("true", "1", "yes")),
        }

        for env_var, (attr_path, converter) in env_map.items():
            value = os.environ.get(env_var)
            if value is not None:
                try:
                    converted = converter(value)
                    if "." in attr_path:
                        parts = attr_path.split(".")
                        obj = getattr(self, parts[0])
                        setattr(obj, parts[1], converted)
                    else:
                        setattr(self, attr_path, converted)
                except (ValueError, TypeError):
                    pass  # Skip invalid environment values


def get_default_config() -> PhantomConfig:
    """
    Get the default configuration, with environment overrides applied.

    Returns:
        PhantomConfig with defaults and env overrides.
    """
    config = PhantomConfig()
    config.apply_env_overrides()
    return config


def load_or_create_config(path: Optional[str] = None) -> PhantomConfig:
    """
    Load config from file or create default.

    Args:
        path: Optional path to config file.

    Returns:
        PhantomConfig instance.
    """
    if path and Path(path).exists():
        config = PhantomConfig.load(path)
    else:
        config = PhantomConfig()

    config.apply_env_overrides()
    return config
