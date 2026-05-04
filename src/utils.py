"""
utils.py — Shared helper utilities for Docker Security Scanner.

Provides:
  - Logging configuration
  - Docker image tag parsing
  - Severity scoring & ordering
  - File I/O helpers
  - Custom exception hierarchy
  - Configuration management via Pydantic + python-dotenv
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator
from rich.console import Console
from rich.logging import RichHandler

# ─── Load .env ───────────────────────────────────────────────────────────────
load_dotenv()

# ─── Rich console (shared) ───────────────────────────────────────────────────
console = Console()

# ─── Severity constants & ordering ───────────────────────────────────────────
SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "UNKNOWN": 1,
    "NONE": 0,
}

SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "UNKNOWN": "dim",
    "NONE": "green",
}


# ─── Custom Exceptions ────────────────────────────────────────────────────────
class ScannerError(Exception):
    """Base exception for all scanner errors."""


class ToolNotFoundError(ScannerError):
    """Raised when a required external tool is not installed or not on PATH."""

    def __init__(self, tool_name: str) -> None:
        super().__init__(
            f"Required tool '{tool_name}' not found. "
            f"Please install it and ensure it is on your PATH."
        )
        self.tool_name = tool_name


class DockerfileNotFoundError(ScannerError):
    """Raised when the specified Dockerfile does not exist."""


class ImageBuildError(ScannerError):
    """Raised when the Docker image build fails."""


class ScanExecutionError(ScannerError):
    """Raised when a scanner subprocess fails unexpectedly."""


class PolicyViolationError(ScannerError):
    """Raised when the scan result violates security policy (e.g. critical CVEs)."""

    def __init__(self, message: str, severity: str = "CRITICAL") -> None:
        super().__init__(message)
        self.severity = severity


# ─── Configuration Model ─────────────────────────────────────────────────────
class ScannerConfig(BaseModel):
    """Pydantic model for scanner configuration loaded from env / config file."""

    # Severity policy
    fail_on_severity: list[str] = Field(
        default_factory=lambda: ["CRITICAL", "HIGH"],
        description="Severity levels that trigger a pipeline failure.",
    )
    critical_threshold: int = Field(
        default=0, ge=0, description="Max CRITICAL CVEs before hard-fail (0 = any)."
    )
    high_threshold: int = Field(
        default=10, ge=0, description="Max HIGH CVEs before hard-fail (0 = disabled)."
    )

    # Tool paths
    trivy_path: str = Field(default="trivy")
    hadolint_path: str = Field(default="hadolint")
    gitleaks_path: str = Field(default="gitleaks")

    # Trivy options
    trivy_cache_dir: str = Field(default=".trivy-cache")
    trivy_skip_update: bool = Field(default=False)

    # Hadolint options
    hadolint_config: Optional[str] = Field(default=None)
    hadolint_ignore: list[str] = Field(default_factory=list)

    # Gitleaks options
    gitleaks_config: Optional[str] = Field(default=None)

    # Reporting
    report_output_dir: str = Field(default="reports")
    report_formats: list[str] = Field(default_factory=lambda: ["html", "json", "markdown"])
    sbom_formats: list[str] = Field(default_factory=lambda: ["cyclonedx", "spdx"])

    # Notifications
    github_token: Optional[str] = Field(default=None)
    slack_webhook_url: Optional[str] = Field(default=None)

    # Logging
    log_level: str = Field(default="INFO")
    log_file: Optional[str] = Field(default=None)

    @field_validator("fail_on_severity", mode="before")
    @classmethod
    def _parse_severity_list(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            return [s.strip().upper() for s in v.split(",") if s.strip()]
        return [s.upper() for s in v]

    @field_validator("report_formats", "sbom_formats", "hadolint_ignore", mode="before")
    @classmethod
    def _parse_comma_list(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            return [s.strip().lower() for s in v.split(",") if s.strip()]
        return list(v)

    @classmethod
    def from_env(cls) -> "ScannerConfig":
        """Create a ScannerConfig instance from environment variables."""
        return cls(
            fail_on_severity=os.getenv("FAIL_ON_SEVERITY", "CRITICAL,HIGH"),
            critical_threshold=int(os.getenv("CRITICAL_THRESHOLD", "0")),
            high_threshold=int(os.getenv("HIGH_THRESHOLD", "10")),
            trivy_path=os.getenv("TRIVY_PATH", "trivy"),
            hadolint_path=os.getenv("HADOLINT_PATH", "hadolint"),
            gitleaks_path=os.getenv("GITLEAKS_PATH", "gitleaks"),
            trivy_cache_dir=os.getenv("TRIVY_CACHE_DIR", ".trivy-cache"),
            trivy_skip_update=os.getenv("TRIVY_SKIP_UPDATE", "false").lower() == "true",
            hadolint_config=os.getenv("HADOLINT_CONFIG") or None,
            hadolint_ignore=os.getenv("HADOLINT_IGNORE", ""),
            gitleaks_config=os.getenv("GITLEAKS_CONFIG") or None,
            report_output_dir=os.getenv("REPORT_OUTPUT_DIR", "reports"),
            report_formats=os.getenv("REPORT_FORMATS", "html,json,markdown"),
            sbom_formats=os.getenv("SBOM_FORMATS", "cyclonedx,spdx"),
            github_token=os.getenv("GITHUB_TOKEN") or None,
            slack_webhook_url=os.getenv("SLACK_WEBHOOK_URL") or None,
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            log_file=os.getenv("LOG_FILE") or None,
        )


# ─── Logging setup ───────────────────────────────────────────────────────────
def setup_logging(level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """Configure rich-based logging for the scanner.

    Args:
        level: Logging level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_file: Optional file path to also write logs to.

    Returns:
        Configured root logger.
    """
    log_level = getattr(logging, level.upper(), logging.INFO)
    handlers: list[logging.Handler] = [
        RichHandler(console=console, rich_tracebacks=True, markup=True)
    ]

    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))

    logging.basicConfig(
        level=log_level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=handlers,
        force=True,
    )

    return logging.getLogger("docker_security_scanner")


# ─── Docker image parsing ─────────────────────────────────────────────────────
@dataclass
class ImageRef:
    """Parsed Docker image reference.

    Attributes:
        registry: Registry hostname (e.g. docker.io, ghcr.io).
        repository: Image repository path.
        tag: Image tag (default: latest).
        digest: Optional SHA256 digest.
        raw: Original unparsed string.
    """

    registry: str
    repository: str
    tag: str
    digest: Optional[str]
    raw: str

    @property
    def full_name(self) -> str:
        """Fully-qualified image name without digest."""
        return f"{self.registry}/{self.repository}:{self.tag}"

    @property
    def is_latest(self) -> bool:
        """Return True if the image uses the :latest tag."""
        return self.tag == "latest"

    @property
    def is_pinned(self) -> bool:
        """Return True if the image is pinned to a specific digest."""
        return self.digest is not None


_IMAGE_RE = re.compile(
    r"^(?:(?P<registry>[a-zA-Z0-9][a-zA-Z0-9._-]*(?:\:[0-9]+)?)/)??"
    r"(?P<repository>[a-zA-Z0-9][a-zA-Z0-9._\-/]*)?"
    r"(?::(?P<tag>[a-zA-Z0-9._\-]+))?"
    r"(?:@(?P<digest>sha256:[a-fA-F0-9]{64}))?$"
)


def parse_image_ref(image: str) -> ImageRef:
    """Parse a Docker image reference string into an :class:`ImageRef`.

    Args:
        image: Docker image reference (e.g. ``nginx:1.25``, ``ghcr.io/org/img:v1``).

    Returns:
        Parsed :class:`ImageRef`.

    Raises:
        ValueError: If the image reference cannot be parsed.

    Example:
        >>> ref = parse_image_ref("python:3.11-slim")
        >>> ref.repository
        'python'
        >>> ref.tag
        '3.11-slim'
    """
    image = image.strip()
    m = _IMAGE_RE.match(image)
    if not m:
        raise ValueError(f"Cannot parse image reference: {image!r}")

    registry = m.group("registry") or "docker.io"
    repository = m.group("repository") or "library/unknown"
    tag = m.group("tag") or "latest"
    digest = m.group("digest")

    # Normalise official Docker Hub images (e.g. "nginx" → "library/nginx")
    if registry == "docker.io" and "/" not in repository:
        repository = f"library/{repository}"

    return ImageRef(
        registry=registry,
        repository=repository,
        tag=tag,
        digest=digest,
        raw=image,
    )


# ─── Severity helpers ─────────────────────────────────────────────────────────
def severity_rank(severity: str) -> int:
    """Return a numeric rank for a severity string (higher = worse).

    Args:
        severity: Severity string (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN, NONE).

    Returns:
        Integer rank 0–5.
    """
    return SEVERITY_ORDER.get(severity.upper(), 0)


def max_severity(severities: list[str]) -> str:
    """Return the highest severity from a list.

    Args:
        severities: List of severity strings.

    Returns:
        Highest severity string, or 'NONE' if list is empty.
    """
    if not severities:
        return "NONE"
    return max(severities, key=severity_rank)


# ─── File I/O helpers ─────────────────────────────────────────────────────────
def ensure_dir(path: str | Path) -> Path:
    """Ensure a directory exists, creating it if necessary.

    Args:
        path: Directory path.

    Returns:
        Resolved :class:`Path`.
    """
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def write_json(data: Any, path: str | Path, indent: int = 2) -> None:
    """Write data as pretty-printed JSON.

    Args:
        data: JSON-serialisable object.
        path: Destination file path.
        indent: JSON indentation level.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=indent, default=str)


def read_json(path: str | Path) -> Any:
    """Read and parse a JSON file.

    Args:
        path: Source file path.

    Returns:
        Parsed JSON data.

    Raises:
        FileNotFoundError: If the file does not exist.
        json.JSONDecodeError: If the file is not valid JSON.
    """
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def truncate_string(s: str, max_len: int = 120) -> str:
    """Truncate a string with ellipsis if it exceeds max_len.

    Args:
        s: Source string.
        max_len: Maximum length before truncation.

    Returns:
        Truncated string.
    """
    return s if len(s) <= max_len else s[: max_len - 3] + "..."
