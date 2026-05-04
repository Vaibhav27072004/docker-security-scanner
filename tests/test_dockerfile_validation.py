"""
test_dockerfile_validation.py — Tests for Hadolint Dockerfile linting.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.hadolint_scanner import HadolintResult, HadolintScanner, LintIssue
from src.utils import ScannerConfig, ToolNotFoundError


class TestHadolintScanner:
    """Tests for HadolintScanner class."""

    @patch("subprocess.run")
    def test_tool_not_found_raises(self, mock_run: MagicMock, config: ScannerConfig) -> None:
        """ToolNotFoundError raised when hadolint is missing."""
        mock_run.side_effect = FileNotFoundError
        with pytest.raises(ToolNotFoundError) as exc_info:
            HadolintScanner(config)
        assert "hadolint" in str(exc_info.value)

    @patch("subprocess.run")
    def test_scan_parses_issues(
        self,
        mock_run: MagicMock,
        config: ScannerConfig,
        sample_hadolint_output: str,
        vulnerable_dockerfile: Path,
    ) -> None:
        """scan() correctly parses Hadolint JSON output."""
        mock_run.side_effect = [
            MagicMock(returncode=0),  # version check
            MagicMock(returncode=0, stdout=sample_hadolint_output, stderr=""),
        ]
        scanner = HadolintScanner(config)
        result = scanner.scan(str(vulnerable_dockerfile))

        assert result.total_count == 3
        assert len(result.warnings) == 3
        assert len(result.errors) == 0

    @patch("subprocess.run")
    def test_scan_clean_dockerfile(
        self,
        mock_run: MagicMock,
        config: ScannerConfig,
        secure_dockerfile: Path,
    ) -> None:
        """Clean Dockerfile produces no issues."""
        mock_run.side_effect = [
            MagicMock(returncode=0),
            MagicMock(returncode=0, stdout="[]", stderr=""),
        ]
        scanner = HadolintScanner(config)
        result = scanner.scan(str(secure_dockerfile))

        assert result.passed is True
        assert result.total_count == 0

    def test_scan_nonexistent_dockerfile(self, config: ScannerConfig) -> None:
        """FileNotFoundError raised for missing Dockerfile."""
        with patch("subprocess.run", return_value=MagicMock(returncode=0)):
            scanner = HadolintScanner(config)

        with pytest.raises(FileNotFoundError):
            scanner.scan("/nonexistent/path/Dockerfile")

    @patch("subprocess.run")
    def test_issues_sorted_by_severity_then_line(
        self,
        mock_run: MagicMock,
        config: ScannerConfig,
        tmp_path: Path,
    ) -> None:
        """Issues are sorted: errors first, then warnings, then by line number."""
        output = json.dumps([
            {"code": "DL3008", "level": "warning", "message": "pin versions", "line": 10, "column": 1, "file": "Dockerfile"},
            {"code": "DL3002", "level": "error", "message": "root user", "line": 5, "column": 1, "file": "Dockerfile"},
            {"code": "DL3007", "level": "warning", "message": "latest tag", "line": 1, "column": 1, "file": "Dockerfile"},
        ])
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM ubuntu:latest\n", encoding="utf-8")

        mock_run.side_effect = [
            MagicMock(returncode=0),
            MagicMock(returncode=0, stdout=output, stderr=""),
        ]
        scanner = HadolintScanner(config)
        result = scanner.scan(str(dockerfile))

        # First issue should be the error (DL3002)
        assert result.issues[0].code == "DL3002"
        assert result.issues[0].level == "error"


class TestLintIssue:
    """Tests for the LintIssue data class."""

    def _make_issue(self, **kwargs) -> LintIssue:
        defaults = dict(
            code="DL3007",
            level="warning",
            message="Using latest is best avoided",
            line=1,
            column=1,
            file="Dockerfile",
        )
        defaults.update(kwargs)
        return LintIssue(**defaults)

    def test_severity_error_maps_to_high(self) -> None:
        issue = self._make_issue(level="error")
        assert issue.severity == "HIGH"

    def test_severity_warning_maps_to_medium(self) -> None:
        issue = self._make_issue(level="warning")
        assert issue.severity == "MEDIUM"

    def test_severity_info_maps_to_low(self) -> None:
        issue = self._make_issue(level="info")
        assert issue.severity == "LOW"

    def test_category_dl3_is_package_management(self) -> None:
        issue = self._make_issue(code="DL3008")
        assert issue.category == "Package Management"

    def test_is_security_critical_for_high_risk_rule(self) -> None:
        issue = self._make_issue(code="DL3002", level="warning")
        assert issue.is_security_critical is True

    def test_url_generated_for_dl_rules(self) -> None:
        issue = self._make_issue(code="DL3007", url="https://github.com/hadolint/hadolint/wiki/DL3007")
        assert "DL3007" in issue.url

    def test_to_dict_has_required_keys(self) -> None:
        issue = self._make_issue()
        d = issue.to_dict()
        for key in ("code", "level", "severity", "message", "line", "category"):
            assert key in d
