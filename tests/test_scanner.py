"""
test_scanner.py — Integration tests for the main scanner orchestrator.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.scanner import AggregatedResult, SecurityScanner
from src.trivy_scanner import TrivyScanResult
from src.hadolint_scanner import HadolintResult
from src.gitleaks_scanner import GitleaksResult
from src.utils import PolicyViolationError, ScannerConfig


class TestAggregatedResult:
    """Tests for the AggregatedResult data class."""

    def _make_clean_result(self) -> AggregatedResult:
        result = AggregatedResult(image="clean:image")
        result.trivy = TrivyScanResult(image="clean:image")
        result.hadolint = HadolintResult(dockerfile_path="Dockerfile")
        result.gitleaks = GitleaksResult(scan_path=".")
        return result

    def test_passed_when_all_scanners_clean(self) -> None:
        result = self._make_clean_result()
        assert result.passed is True

    def test_not_passed_when_trivy_has_vulns(self) -> None:
        from src.trivy_scanner import CVE
        result = self._make_clean_result()
        result.trivy.vulnerabilities = [
            CVE("CVE-2023-0001", "CRITICAL", "pkg", "1.0", "1.1", "", "", 9.8, "", [], "", "layer")
        ]
        assert result.passed is False

    def test_not_passed_when_secrets_found(self) -> None:
        from src.gitleaks_scanner import SecretFinding
        result = self._make_clean_result()
        result.gitleaks.findings = [
            SecretFinding("aws-access-token", "AWS Key", ".env", 4, "", "AKIA...", 3.67)
        ]
        assert result.passed is False

    def test_overall_severity_none_when_clean(self) -> None:
        result = self._make_clean_result()
        assert result.overall_severity == "NONE"

    def test_to_dict_contains_all_sections(self) -> None:
        result = self._make_clean_result()
        d = result.to_dict()
        for key in ("image", "passed", "overall_severity", "trivy", "hadolint", "gitleaks"):
            assert key in d


class TestSecurityScannerPolicyEnforcement:
    """Tests for the policy enforcement logic in SecurityScanner."""

    def _make_scanner_with_mocked_tools(self, config: ScannerConfig) -> SecurityScanner:
        """Create a SecurityScanner that bypasses tool availability checks."""
        with patch("subprocess.run", return_value=MagicMock(returncode=0)):
            from src.trivy_scanner import TrivyScanner
            from src.hadolint_scanner import HadolintScanner
            from src.gitleaks_scanner import GitleaksScanner

        scanner = SecurityScanner.__new__(SecurityScanner)
        scanner.config = config
        return scanner

    def test_policy_passes_with_no_findings(self, config: ScannerConfig) -> None:
        from src.trivy_scanner import TrivyScanResult
        from src.hadolint_scanner import HadolintResult
        from src.gitleaks_scanner import GitleaksResult

        scanner = SecurityScanner.__new__(SecurityScanner)
        scanner.config = config

        result = AggregatedResult(image="clean:image")
        result.trivy = TrivyScanResult(image="clean:image")
        result.hadolint = HadolintResult(dockerfile_path="Dockerfile")
        result.gitleaks = GitleaksResult(scan_path=".")

        # Should not raise
        scanner._enforce_policy(result)

    def test_policy_fails_on_critical_cve(self, config: ScannerConfig) -> None:
        from src.trivy_scanner import CVE, TrivyScanResult
        from src.hadolint_scanner import HadolintResult
        from src.gitleaks_scanner import GitleaksResult

        scanner = SecurityScanner.__new__(SecurityScanner)
        scanner.config = config

        result = AggregatedResult(image="vuln:image")
        result.trivy = TrivyScanResult(image="vuln:image")
        result.trivy.vulnerabilities = [
            CVE("CVE-2023-0001", "CRITICAL", "pkg", "1.0", "1.1", "", "", 9.8, "", [], "", "layer")
        ]
        result.hadolint = HadolintResult(dockerfile_path="Dockerfile")
        result.gitleaks = GitleaksResult(scan_path=".")

        with pytest.raises(PolicyViolationError) as exc_info:
            scanner._enforce_policy(result)
        assert "CRITICAL" in str(exc_info.value)

    def test_policy_fails_on_secrets(self, config: ScannerConfig) -> None:
        from src.trivy_scanner import TrivyScanResult
        from src.hadolint_scanner import HadolintResult
        from src.gitleaks_scanner import GitleaksResult, SecretFinding

        scanner = SecurityScanner.__new__(SecurityScanner)
        scanner.config = config

        result = AggregatedResult(image="secret:image")
        result.trivy = TrivyScanResult(image="secret:image")
        result.hadolint = HadolintResult(dockerfile_path="Dockerfile")
        result.gitleaks = GitleaksResult(scan_path=".")
        result.gitleaks.findings = [
            SecretFinding("aws-access-token", "AWS Key", ".env", 4, "", "AKIA...", 3.67)
        ]

        with pytest.raises(PolicyViolationError) as exc_info:
            scanner._enforce_policy(result)
        assert "secrets" in str(exc_info.value).lower()

    def test_policy_respects_high_threshold(self, config: ScannerConfig) -> None:
        """Policy should pass if HIGH count is within threshold."""
        from src.trivy_scanner import CVE, TrivyScanResult
        from src.hadolint_scanner import HadolintResult
        from src.gitleaks_scanner import GitleaksResult

        config.high_threshold = 5  # Allow up to 5 HIGH CVEs
        scanner = SecurityScanner.__new__(SecurityScanner)
        scanner.config = config

        result = AggregatedResult(image="moderate:image")
        result.trivy = TrivyScanResult(image="moderate:image")
        # Add 3 HIGH CVEs (under threshold of 5)
        result.trivy.vulnerabilities = [
            CVE(f"CVE-2023-000{i}", "HIGH", "pkg", "1.0", "1.1", "", "", 7.0, "", [], "", "layer")
            for i in range(3)
        ]
        result.hadolint = HadolintResult(dockerfile_path="Dockerfile")
        result.gitleaks = GitleaksResult(scan_path=".")

        # Should not raise — 3 HIGH < threshold of 5
        scanner._enforce_policy(result)


class TestUtilsIntegration:
    """Tests for utility functions used across the scanner."""

    def test_parse_image_ref_official_image(self) -> None:
        from src.utils import parse_image_ref
        ref = parse_image_ref("nginx:1.25")
        assert ref.tag == "1.25"
        assert ref.repository == "library/nginx"
        assert ref.is_latest is False

    def test_parse_image_ref_latest_tag(self) -> None:
        from src.utils import parse_image_ref
        ref = parse_image_ref("ubuntu:latest")
        assert ref.is_latest is True

    def test_parse_image_ref_with_registry(self) -> None:
        from src.utils import parse_image_ref
        ref = parse_image_ref("ghcr.io/org/myapp:v1.2.3")
        assert ref.registry == "ghcr.io"
        assert ref.tag == "v1.2.3"

    def test_max_severity_returns_highest(self) -> None:
        from src.utils import max_severity
        assert max_severity(["LOW", "CRITICAL", "MEDIUM"]) == "CRITICAL"

    def test_max_severity_empty_list(self) -> None:
        from src.utils import max_severity
        assert max_severity([]) == "NONE"

    def test_severity_rank_ordering(self) -> None:
        from src.utils import severity_rank
        assert severity_rank("CRITICAL") > severity_rank("HIGH")
        assert severity_rank("HIGH") > severity_rank("MEDIUM")
        assert severity_rank("MEDIUM") > severity_rank("LOW")
