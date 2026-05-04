"""
gitleaks_scanner.py — Gitleaks secret detection integration.

Detects hardcoded secrets, API keys, credentials, and other sensitive data
in source files, Dockerfiles, and environment files before they reach production.
"""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .utils import ScannerConfig, ScanExecutionError, ToolNotFoundError

logger = logging.getLogger("docker_security_scanner.gitleaks")

# Risk tier by rule type
HIGH_RISK_RULE_PATTERNS = {
    "aws", "gcp", "azure", "private-key", "rsa", "ssh",
    "github-pat", "slack", "stripe", "twilio", "sendgrid",
}


@dataclass
class SecretFinding:
    """A single secret detected by Gitleaks.

    Attributes:
        rule_id: Gitleaks rule that triggered the detection.
        description: Human-readable rule description.
        file: File path where the secret was found.
        line_number: Line number of the finding.
        commit: Git commit SHA (empty for filesystem scans).
        secret_snippet: Redacted snippet of the matched secret.
        entropy: Shannon entropy of the matched value.
        tags: List of tags from the rule.
    """

    rule_id: str
    description: str
    file: str
    line_number: int
    commit: str
    secret_snippet: str
    entropy: float
    tags: list[str] = field(default_factory=list)

    @property
    def severity(self) -> str:
        """Estimate severity based on rule ID and entropy."""
        rule_lower = self.rule_id.lower()
        if any(pattern in rule_lower for pattern in HIGH_RISK_RULE_PATTERNS):
            return "CRITICAL"
        if self.entropy > 4.5:
            return "HIGH"
        return "MEDIUM"

    @property
    def redacted_snippet(self) -> str:
        """Return a safely redacted version of the secret snippet."""
        if not self.secret_snippet:
            return "[REDACTED]"
        visible = self.secret_snippet[:4]
        return f"{visible}{'*' * min(len(self.secret_snippet) - 4, 20)}[REDACTED]"

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "file": self.file,
            "line_number": self.line_number,
            "commit": self.commit,
            "secret_snippet": self.redacted_snippet,
            "entropy": self.entropy,
            "severity": self.severity,
            "tags": self.tags,
        }


@dataclass
class GitleaksResult:
    """Aggregated result from a Gitleaks scan.

    Attributes:
        scan_path: Directory or file path that was scanned.
        scan_timestamp: ISO-8601 timestamp.
        findings: All secret findings.
        error: Non-empty if scan encountered an error.
    """

    scan_path: str
    scan_timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    findings: list[SecretFinding] = field(default_factory=list)
    error: str = ""

    @property
    def passed(self) -> bool:
        return len(self.findings) == 0 and not self.error

    @property
    def total_count(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH")

    def by_file(self) -> dict[str, list[SecretFinding]]:
        """Group findings by file path."""
        result: dict[str, list[SecretFinding]] = {}
        for finding in self.findings:
            result.setdefault(finding.file, []).append(finding)
        return result

    def summary(self) -> str:
        return (
            f"Gitleaks scan for {self.scan_path} — "
            f"Secrets found: {self.total_count} "
            f"(CRITICAL: {self.critical_count}, HIGH: {self.high_count})"
        )

    def to_dict(self) -> dict:
        return {
            "scan_path": self.scan_path,
            "scan_timestamp": self.scan_timestamp,
            "summary": {
                "total": self.total_count,
                "critical": self.critical_count,
                "high": self.high_count,
            },
            "passed": self.passed,
            "error": self.error,
            "findings": [f.to_dict() for f in self.findings],
        }


class GitleaksScanner:
    """Wrapper around the Gitleaks CLI for secret detection.

    Args:
        config: ScannerConfig instance.

    Example::

        scanner = GitleaksScanner(config)
        result = scanner.scan("./examples/vulnerable-app")
        if not result.passed:
            print(f"Secrets found: {result.total_count}")
    """

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config
        self._check_tool_available()

    def _check_tool_available(self) -> None:
        try:
            subprocess.run(
                [self.config.gitleaks_path, "version"],
                capture_output=True, check=True,
            )
        except (FileNotFoundError, subprocess.CalledProcessError) as exc:
            raise ToolNotFoundError("gitleaks") from exc

    def _build_command(self, scan_path: str) -> list[str]:
        cmd = [
            self.config.gitleaks_path,
            "detect",
            "--source", scan_path,
            "--report-format", "json",
            "--report-path", "/dev/stdout",
            "--no-git",          # filesystem scan (no git history required)
            "--exit-code", "0",  # we handle policy
        ]
        if self.config.gitleaks_config:
            cmd.extend(["--config", self.config.gitleaks_config])
        return cmd

    def scan(self, scan_path: str) -> GitleaksResult:
        """Scan a directory or file for secrets with Gitleaks.

        Args:
            scan_path: Directory or file path to scan.

        Returns:
            GitleaksResult with all findings.

        Raises:
            FileNotFoundError: If scan_path does not exist.
            ScanExecutionError: If Gitleaks fails unexpectedly.
        """
        path = Path(scan_path)
        if not path.exists():
            raise FileNotFoundError(f"Scan path not found: {scan_path}")

        logger.info("Starting Gitleaks scan: %s", scan_path)
        cmd = self._build_command(str(path))

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired as exc:
            raise ScanExecutionError(f"Gitleaks timed out for {scan_path}") from exc
        except FileNotFoundError as exc:
            raise ToolNotFoundError("gitleaks") from exc

        return self._parse_output(str(path), proc.stdout, proc.stderr)

    def _parse_output(self, scan_path: str, stdout: str, stderr: str) -> GitleaksResult:
        result = GitleaksResult(scan_path=scan_path)

        if not stdout.strip():
            if "leaks found" not in stderr.lower() and stderr.strip():
                result.error = stderr.strip()
            logger.info("Gitleaks: no secrets found in %s", scan_path)
            return result

        try:
            raw = json.loads(stdout)
        except json.JSONDecodeError:
            # Gitleaks may output non-JSON on no-findings
            logger.info("Gitleaks: no structured output — treating as clean.")
            return result

        findings: list[SecretFinding] = []
        for item in raw if isinstance(raw, list) else []:
            findings.append(SecretFinding(
                rule_id=item.get("RuleID", item.get("ruleID", "unknown")),
                description=item.get("Description", item.get("description", "")),
                file=item.get("File", item.get("file", "")),
                line_number=item.get("StartLine", item.get("startLine", 0)),
                commit=item.get("Commit", item.get("commit", "")),
                secret_snippet=item.get("Secret", item.get("secret", "")),
                entropy=float(item.get("Entropy", item.get("entropy", 0.0))),
                tags=item.get("Tags", item.get("tags", [])),
            ))

        # Sort by severity then file
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
        findings.sort(key=lambda f: (severity_order.get(f.severity, 3), f.file))
        result.findings = findings

        logger.warning(
            "Gitleaks: %d secrets found (%d CRITICAL) in %s",
            result.total_count, result.critical_count, scan_path,
        )
        return result
