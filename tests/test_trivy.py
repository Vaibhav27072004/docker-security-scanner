"""
test_trivy.py — Unit tests for the Trivy CVE scanner integration.
"""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from src.trivy_scanner import CVE, TrivyScanResult, TrivyScanner
from src.utils import ScannerConfig, ScanExecutionError, ToolNotFoundError


class TestTrivyScanner:
    """Tests for TrivyScanner class."""

    @patch("subprocess.run")
    def test_check_tool_available_success(self, mock_run: MagicMock, config: ScannerConfig) -> None:
        """TrivyScanner initialises when trivy is on PATH."""
        mock_run.return_value = MagicMock(returncode=0)
        scanner = TrivyScanner(config)
        assert scanner is not None

    @patch("subprocess.run")
    def test_check_tool_not_found(self, mock_run: MagicMock, config: ScannerConfig) -> None:
        """ToolNotFoundError raised when trivy is not installed."""
        mock_run.side_effect = FileNotFoundError
        with pytest.raises(ToolNotFoundError) as exc_info:
            TrivyScanner(config)
        assert "trivy" in str(exc_info.value)

    @patch("subprocess.run")
    def test_scan_parses_vulnerabilities(
        self, mock_run: MagicMock, config: ScannerConfig, sample_trivy_output: str
    ) -> None:
        """scan() correctly parses Trivy JSON output."""
        # First call is version check, second is the actual scan
        mock_run.side_effect = [
            MagicMock(returncode=0),           # version check
            MagicMock(returncode=0, stdout=sample_trivy_output, stderr=""),  # scan
        ]
        scanner = TrivyScanner(config)
        result = scanner.scan("python:3.9")

        assert result.image == "python:3.9"
        assert result.total_count == 3
        assert result.critical_count == 1
        assert result.high_count == 1
        assert result.medium_count == 1
        assert result.low_count == 0

    @patch("subprocess.run")
    def test_scan_sorts_by_severity_then_cvss(
        self, mock_run: MagicMock, config: ScannerConfig, sample_trivy_output: str
    ) -> None:
        """Vulnerabilities are sorted: CRITICAL first, then by CVSS score."""
        mock_run.side_effect = [
            MagicMock(returncode=0),
            MagicMock(returncode=0, stdout=sample_trivy_output, stderr=""),
        ]
        scanner = TrivyScanner(config)
        result = scanner.scan("python:3.9")

        assert result.vulnerabilities[0].severity == "CRITICAL"
        assert result.vulnerabilities[0].cvss_score == 9.8

    @patch("subprocess.run")
    def test_scan_empty_output(self, mock_run: MagicMock, config: ScannerConfig) -> None:
        """scan() handles empty Trivy output gracefully."""
        mock_run.side_effect = [
            MagicMock(returncode=0),
            MagicMock(returncode=0, stdout="", stderr="No image found"),
        ]
        scanner = TrivyScanner(config)
        result = scanner.scan("nonexistent:image")

        assert result.error != ""
        assert result.total_count == 0

    @patch("subprocess.run")
    def test_scan_timeout_raises(self, mock_run: MagicMock, config: ScannerConfig) -> None:
        """ScanExecutionError raised on subprocess timeout."""
        mock_run.side_effect = [
            MagicMock(returncode=0),
            subprocess.TimeoutExpired(cmd="trivy", timeout=300),
        ]
        scanner = TrivyScanner(config)
        with pytest.raises(ScanExecutionError, match="timed out"):
            scanner.scan("slow:image")

    @patch("subprocess.run")
    def test_scan_no_vulnerabilities(self, mock_run: MagicMock, config: ScannerConfig) -> None:
        """scan() returns passed=True when no vulnerabilities are found."""
        clean_output = json.dumps({
            "SchemaVersion": 2,
            "ArtifactName": "distroless:latest",
            "Results": [],
        })
        mock_run.side_effect = [
            MagicMock(returncode=0),
            MagicMock(returncode=0, stdout=clean_output, stderr=""),
        ]
        scanner = TrivyScanner(config)
        result = scanner.scan("distroless:latest")

        assert result.passed is True
        assert result.total_count == 0


class TestCVE:
    """Tests for the CVE data class."""

    def _make_cve(self, **kwargs) -> CVE:
        defaults = dict(
            id="CVE-2023-0001",
            severity="HIGH",
            package_name="openssl",
            installed_version="1.1.1",
            fixed_version="1.1.2",
            title="Test CVE",
            description="A test vulnerability",
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-0001"],
            published_date="2023-01-01T00:00:00Z",
            target="debian:11",
        )
        defaults.update(kwargs)
        return CVE(**defaults)

    def test_nvd_url(self) -> None:
        cve = self._make_cve()
        assert cve.nvd_url == "https://nvd.nist.gov/vuln/detail/CVE-2023-0001"

    def test_is_fixable_true(self) -> None:
        cve = self._make_cve(fixed_version="1.1.2")
        assert cve.is_fixable is True

    def test_is_fixable_false_na(self) -> None:
        cve = self._make_cve(fixed_version="N/A")
        assert cve.is_fixable is False

    def test_is_fixable_false_empty(self) -> None:
        cve = self._make_cve(fixed_version="")
        assert cve.is_fixable is False

    def test_to_dict_contains_expected_keys(self) -> None:
        cve = self._make_cve()
        d = cve.to_dict()
        for key in ("id", "severity", "package_name", "cvss_score", "nvd_url", "is_fixable"):
            assert key in d


class TestTrivyScanResult:
    """Tests for TrivyScanResult helper methods."""

    def _make_result_with_mixed_cves(self) -> TrivyScanResult:
        cves = [
            CVE("CVE-A", "CRITICAL", "pkg1", "1.0", "1.1", "", "", 9.8, "", [], "", "layer1"),
            CVE("CVE-B", "HIGH", "pkg2", "2.0", "N/A", "", "", 7.5, "", [], "", "layer1"),
            CVE("CVE-C", "MEDIUM", "pkg3", "3.0", "3.1", "", "", 5.0, "", [], "", "layer1"),
            CVE("CVE-D", "LOW", "pkg4", "4.0", "4.1", "", "", 2.0, "", [], "", "layer1"),
        ]
        result = TrivyScanResult(image="test:latest")
        result.vulnerabilities = cves
        return result

    def test_severity_counts(self) -> None:
        r = self._make_result_with_mixed_cves()
        assert r.critical_count == 1
        assert r.high_count == 1
        assert r.medium_count == 1
        assert r.low_count == 1
        assert r.total_count == 4

    def test_fixable_count(self) -> None:
        r = self._make_result_with_mixed_cves()
        assert r.fixable_count == 3  # CVE-B has N/A fixed

    def test_by_severity_filters_correctly(self) -> None:
        r = self._make_result_with_mixed_cves()
        criticals = r.by_severity("CRITICAL")
        assert len(criticals) == 1
        assert criticals[0].id == "CVE-A"

    def test_top_cvss(self) -> None:
        r = self._make_result_with_mixed_cves()
        top = r.top_cvss(2)
        assert top[0].cvss_score == 9.8
        assert top[1].cvss_score == 7.5

    def test_passed_when_no_vulns(self) -> None:
        r = TrivyScanResult(image="clean:image")
        assert r.passed is True

    def test_not_passed_when_vulns_exist(self) -> None:
        r = self._make_result_with_mixed_cves()
        assert r.passed is False
