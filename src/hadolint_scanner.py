"""
hadolint_scanner.py — Hadolint Dockerfile linting integration.

Wraps the Hadolint CLI to identify Dockerfile anti-patterns, security
misconfigurations, and best-practice violations.
"""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .utils import ScannerConfig, ScanExecutionError, ToolNotFoundError, severity_rank

logger = logging.getLogger("docker_security_scanner.hadolint")

HIGH_RISK_RULES = {"DL3002", "DL3007", "DL4006", "SC2035"}
RULE_CATEGORIES: dict[str, str] = {
    "DL1": "Base Image", "DL2": "Commands", "DL3": "Package Management",
    "DL4": "File System", "DL5": "Networking", "DL6": "Permissions",
    "DL7": "Arguments", "SC": "Shell Script",
}


@dataclass
class LintIssue:
    """A single Hadolint lint finding."""

    code: str
    level: str
    message: str
    line: int
    column: int
    file: str
    url: str = ""

    @property
    def severity(self) -> str:
        return {"error": "HIGH", "warning": "MEDIUM", "info": "LOW", "style": "LOW"}.get(
            self.level.lower(), "UNKNOWN"
        )

    @property
    def category(self) -> str:
        return RULE_CATEGORIES.get(self.code[:3], "General")

    @property
    def is_security_critical(self) -> bool:
        return self.code in HIGH_RISK_RULES or self.level == "error"

    def to_dict(self) -> dict:
        return {
            "code": self.code, "level": self.level, "severity": self.severity,
            "message": self.message, "line": self.line, "column": self.column,
            "file": self.file, "url": self.url, "category": self.category,
            "is_security_critical": self.is_security_critical,
        }


@dataclass
class HadolintResult:
    """Aggregated result from a Hadolint scan."""

    dockerfile_path: str
    scan_timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    issues: list[LintIssue] = field(default_factory=list)
    error: str = ""

    @property
    def errors(self) -> list[LintIssue]:
        return [i for i in self.issues if i.level == "error"]

    @property
    def warnings(self) -> list[LintIssue]:
        return [i for i in self.issues if i.level == "warning"]

    @property
    def infos(self) -> list[LintIssue]:
        return [i for i in self.issues if i.level in ("info", "style")]

    @property
    def passed(self) -> bool:
        return not self.errors and not self.error

    @property
    def total_count(self) -> int:
        return len(self.issues)

    @property
    def security_critical_count(self) -> int:
        return sum(1 for i in self.issues if i.is_security_critical)

    def summary(self) -> str:
        return (
            f"Hadolint — Errors: {len(self.errors)}, "
            f"Warnings: {len(self.warnings)}, Info: {len(self.infos)}"
        )

    def to_dict(self) -> dict:
        return {
            "dockerfile_path": self.dockerfile_path,
            "scan_timestamp": self.scan_timestamp,
            "summary": {
                "total": self.total_count, "errors": len(self.errors),
                "warnings": len(self.warnings), "info": len(self.infos),
                "security_critical": self.security_critical_count,
            },
            "passed": self.passed,
            "error": self.error,
            "issues": [i.to_dict() for i in self.issues],
        }


class HadolintScanner:
    """Wrapper around the Hadolint CLI for Dockerfile linting.

    Args:
        config: ScannerConfig instance.

    Example::

        scanner = HadolintScanner(config)
        result = scanner.scan("./Dockerfile")
        print(result.summary())
    """

    RULE_BASE_URL = "https://github.com/hadolint/hadolint/wiki/"

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config
        self._check_tool_available()

    def _check_tool_available(self) -> None:
        try:
            subprocess.run(
                [self.config.hadolint_path, "--version"],
                capture_output=True, check=True,
            )
        except (FileNotFoundError, subprocess.CalledProcessError) as exc:
            raise ToolNotFoundError("hadolint") from exc

    def _build_command(self, dockerfile_path: str) -> list[str]:
        cmd = [self.config.hadolint_path, "--format", "json", "--no-fail"]
        if self.config.hadolint_config:
            cmd.extend(["--config", self.config.hadolint_config])
        for rule_id in self.config.hadolint_ignore:
            cmd.extend(["--ignore", rule_id])
        cmd.append(dockerfile_path)
        return cmd

    def scan(self, dockerfile_path: str) -> HadolintResult:
        """Lint a Dockerfile and return structured findings.

        Args:
            dockerfile_path: Path to the Dockerfile.

        Returns:
            HadolintResult with all findings.

        Raises:
            FileNotFoundError: If the Dockerfile does not exist.
            ScanExecutionError: If Hadolint fails unexpectedly.
        """
        path = Path(dockerfile_path)
        if not path.exists():
            raise FileNotFoundError(f"Dockerfile not found: {dockerfile_path}")

        logger.info("Starting Hadolint scan: %s", dockerfile_path)
        cmd = self._build_command(str(path))

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired as exc:
            raise ScanExecutionError(f"Hadolint timed out for {dockerfile_path}") from exc
        except FileNotFoundError as exc:
            raise ToolNotFoundError("hadolint") from exc

        return self._parse_output(str(path), proc.stdout, proc.stderr)

    def _parse_output(self, dockerfile_path: str, stdout: str, stderr: str) -> HadolintResult:
        result = HadolintResult(dockerfile_path=dockerfile_path)

        if not stdout.strip():
            result.error = stderr.strip() if stderr.strip() else ""
            return result

        try:
            raw = json.loads(stdout)
        except json.JSONDecodeError as exc:
            result.error = f"Failed to parse Hadolint JSON: {exc}"
            return result

        issues: list[LintIssue] = []
        for item in raw:
            code = item.get("code", "")
            issues.append(LintIssue(
                code=code,
                level=item.get("level", "info"),
                message=item.get("message", ""),
                line=item.get("line", 0),
                column=item.get("column", 0),
                file=item.get("file", dockerfile_path),
                url=f"{self.RULE_BASE_URL}{code}" if code.startswith("DL") else "",
            ))

        issues.sort(key=lambda i: (-severity_rank(i.severity), i.line))
        result.issues = issues
        logger.info("Hadolint: %d issues (%d errors, %d warnings)",
                    result.total_count, len(result.errors), len(result.warnings))
        return result
