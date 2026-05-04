"""
scanner.py — Main orchestrator for Docker Image Security Scanner.

This module ties together all scanning components (Trivy, Hadolint, Gitleaks,
SBOM) into a single pipeline. It is the primary CLI entry point and can also
be used programmatically.

Usage (CLI)::

    docker-scan image nginx:1.25
    docker-scan dockerfile ./Dockerfile
    docker-scan dir ./my-app --dockerfile ./my-app/Dockerfile

Usage (programmatic)::

    from src.scanner import SecurityScanner
    from src.utils import ScannerConfig

    config = ScannerConfig.from_env()
    scanner = SecurityScanner(config)
    result = scanner.scan_image("nginx:1.25", dockerfile_path="./Dockerfile")
    print(result.summary())
"""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich import box

from .gitleaks_scanner import GitleaksResult, GitleaksScanner
from .hadolint_scanner import HadolintResult, HadolintScanner
from .report_generator import ReportGenerator
from .sbom_generator import SBOMResult, SBOMGenerator
from .trivy_scanner import TrivyScanResult, TrivyScanner
from .utils import (
    PolicyViolationError,
    ScannerConfig,
    ScannerError,
    SEVERITY_COLORS,
    console,
    max_severity,
    setup_logging,
)

logger = logging.getLogger("docker_security_scanner")


# ─── Aggregated result ────────────────────────────────────────────────────────
@dataclass
class AggregatedResult:
    """Combined result from all scanning tools.

    Attributes:
        image: Scanned image reference.
        scan_timestamp: ISO-8601 scan start timestamp.
        trivy: Trivy CVE scan result.
        hadolint: Hadolint Dockerfile lint result.
        gitleaks: Gitleaks secret detection result.
        sbom_results: List of SBOM generation results.
        report_paths: Map of format → report file path.
    """

    image: str
    scan_timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    trivy: TrivyScanResult = field(default_factory=lambda: TrivyScanResult(image=""))
    hadolint: HadolintResult = field(
        default_factory=lambda: HadolintResult(dockerfile_path="N/A")
    )
    gitleaks: GitleaksResult = field(
        default_factory=lambda: GitleaksResult(scan_path="N/A")
    )
    sbom_results: list[SBOMResult] = field(default_factory=list)
    report_paths: dict[str, str] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        """True only if ALL scanners report no policy-violating findings."""
        return (
            self.trivy.passed
            and self.hadolint.passed
            and self.gitleaks.passed
            and not any(r.error for r in self.sbom_results)
        )

    @property
    def overall_severity(self) -> str:
        """Highest severity across all tools."""
        severities: list[str] = []
        severities.extend(v.severity for v in self.trivy.vulnerabilities)
        severities.extend(i.severity for i in self.hadolint.issues)
        severities.extend(f.severity for f in self.gitleaks.findings)
        return max_severity(severities) if severities else "NONE"

    def summary(self) -> str:
        return (
            f"Security scan for {self.image} — "
            f"Status: {'PASSED' if self.passed else 'FAILED'} | "
            f"Overall severity: {self.overall_severity}"
        )

    def to_dict(self) -> dict:
        return {
            "image": self.image,
            "scan_timestamp": self.scan_timestamp,
            "passed": self.passed,
            "overall_severity": self.overall_severity,
            "trivy": self.trivy.to_dict(),
            "hadolint": self.hadolint.to_dict(),
            "gitleaks": self.gitleaks.to_dict(),
            "sbom_results": [s.to_dict() for s in self.sbom_results],
            "report_paths": self.report_paths,
        }


# ─── Main scanner orchestrator ────────────────────────────────────────────────
class SecurityScanner:
    """Orchestrates all security scanning tools in a unified pipeline.

    Args:
        config: ScannerConfig instance. If None, loaded from environment.

    Example::

        scanner = SecurityScanner()
        result = scanner.scan_image("python:3.9", dockerfile_path="./Dockerfile")
        if not result.passed:
            print("Security gate failed!")
    """

    def __init__(self, config: Optional[ScannerConfig] = None) -> None:
        self.config = config or ScannerConfig.from_env()
        setup_logging(self.config.log_level, self.config.log_file)

    def scan_image(
        self,
        image: str,
        dockerfile_path: Optional[str] = None,
        scan_path: Optional[str] = None,
        output_dir: Optional[str] = None,
        generate_sbom: bool = True,
    ) -> AggregatedResult:
        """Run all security scanners against a Docker image.

        Args:
            image: Docker image reference (e.g. 'nginx:1.25').
            dockerfile_path: Optional path to the Dockerfile for linting.
            scan_path: Optional directory to scan for secrets.
            output_dir: Directory to write reports and SBOMs.
            generate_sbom: Whether to generate SBOM files.

        Returns:
            AggregatedResult with all findings.

        Raises:
            PolicyViolationError: If critical findings violate the configured policy.

        Example::

            result = scanner.scan_image(
                "myapp:latest",
                dockerfile_path="./Dockerfile",
                scan_path="./src",
                output_dir="./security-reports",
            )
        """
        out_dir = output_dir or self.config.report_output_dir
        result = AggregatedResult(image=image)

        console.rule(f"[bold cyan]🔒 Docker Security Scanner[/bold cyan]")
        console.print(f"[bold]Scanning image:[/bold] {image}")

        # ── Step 1: CVE Scan ─────────────────────────────────────────────────
        console.print("\n[bold cyan]Step 1/4:[/bold cyan] Running Trivy CVE scan...")
        try:
            trivy = TrivyScanner(self.config)
            result.trivy = trivy.scan(image)
            self._print_trivy_summary(result.trivy)
        except ScannerError as exc:
            logger.error("Trivy scan failed: %s", exc)
            result.trivy.error = str(exc)

        # ── Step 2: Dockerfile Lint ──────────────────────────────────────────
        if dockerfile_path:
            console.print("\n[bold cyan]Step 2/4:[/bold cyan] Running Hadolint Dockerfile lint...")
            try:
                hadolint = HadolintScanner(self.config)
                result.hadolint = hadolint.scan(dockerfile_path)
                self._print_hadolint_summary(result.hadolint)
            except ScannerError as exc:
                logger.error("Hadolint scan failed: %s", exc)
                result.hadolint.error = str(exc)
        else:
            console.print("\n[dim]Step 2/4: Skipping Hadolint (no Dockerfile specified).[/dim]")

        # ── Step 3: Secret Scan ──────────────────────────────────────────────
        effective_scan_path = scan_path or dockerfile_path or "."
        console.print(f"\n[bold cyan]Step 3/4:[/bold cyan] Running Gitleaks secret scan on {effective_scan_path}...")
        try:
            gitleaks = GitleaksScanner(self.config)
            result.gitleaks = gitleaks.scan(effective_scan_path)
            self._print_gitleaks_summary(result.gitleaks)
        except ScannerError as exc:
            logger.error("Gitleaks scan failed: %s", exc)
            result.gitleaks.error = str(exc)

        # ── Step 4: SBOM Generation ──────────────────────────────────────────
        if generate_sbom:
            console.print("\n[bold cyan]Step 4/4:[/bold cyan] Generating SBOM...")
            try:
                sbom_gen = SBOMGenerator(self.config)
                result.sbom_results = sbom_gen.generate_all(image, out_dir)
                for sbom_r in result.sbom_results:
                    console.print(f"  [green]✓[/green] {sbom_r.format.upper()} SBOM: {sbom_r.output_path}")
            except ScannerError as exc:
                logger.warning("SBOM generation failed: %s", exc)

        # ── Reports ──────────────────────────────────────────────────────────
        console.print("\n[bold]Generating reports...[/bold]")
        report_gen = ReportGenerator(self.config)
        result.report_paths = report_gen.generate_all(result, out_dir)
        for fmt, path in result.report_paths.items():
            console.print(f"  [green]✓[/green] {fmt.upper()} report: {path}")

        # ── Policy Check ─────────────────────────────────────────────────────
        self._enforce_policy(result)

        return result

    def _enforce_policy(self, result: AggregatedResult) -> None:
        """Enforce security policy and raise if violated.

        Args:
            result: Aggregated scan result.

        Raises:
            PolicyViolationError: If findings exceed configured thresholds.
        """
        violations: list[str] = []

        for sev in self.config.fail_on_severity:
            if sev == "CRITICAL" and result.trivy.critical_count > self.config.critical_threshold:
                violations.append(
                    f"{result.trivy.critical_count} CRITICAL CVEs "
                    f"(threshold: {self.config.critical_threshold})"
                )
            elif sev == "HIGH" and self.config.high_threshold > 0:
                if result.trivy.high_count > self.config.high_threshold:
                    violations.append(
                        f"{result.trivy.high_count} HIGH CVEs "
                        f"(threshold: {self.config.high_threshold})"
                    )

        if result.gitleaks.total_count > 0 and "CRITICAL" in self.config.fail_on_severity:
            violations.append(f"{result.gitleaks.total_count} hardcoded secrets detected")

        if violations:
            msg = "Security policy violated: " + "; ".join(violations)
            console.print(f"\n[bold red]❌ {msg}[/bold red]")
            raise PolicyViolationError(msg)
        else:
            console.print(f"\n[bold green]✅ Security policy: PASSED[/bold green]")

    # ── Pretty-print helpers ─────────────────────────────────────────────────
    @staticmethod
    def _print_trivy_summary(result: TrivyScanResult) -> None:
        table = Table(title="CVE Summary", box=box.ROUNDED, show_header=True)
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        for sev, count in [
            ("CRITICAL", result.critical_count),
            ("HIGH", result.high_count),
            ("MEDIUM", result.medium_count),
            ("LOW", result.low_count),
        ]:
            color = SEVERITY_COLORS.get(sev, "white")
            table.add_row(f"[{color}]{sev}[/{color}]", str(count))
        console.print(table)

    @staticmethod
    def _print_hadolint_summary(result: HadolintResult) -> None:
        status = "[green]✓ PASSED[/green]" if result.passed else "[red]✗ FAILED[/red]"
        console.print(
            f"  Hadolint: {status} — "
            f"Errors: {len(result.errors)}, Warnings: {len(result.warnings)}"
        )

    @staticmethod
    def _print_gitleaks_summary(result: GitleaksResult) -> None:
        status = "[green]✓ PASSED[/green]" if result.passed else "[red]✗ FAILED[/red]"
        console.print(f"  Gitleaks: {status} — Secrets: {result.total_count}")


# ─── CLI ──────────────────────────────────────────────────────────────────────
@click.group()
@click.option("--log-level", default="INFO", show_default=True, help="Logging verbosity.")
@click.pass_context
def cli(ctx: click.Context, log_level: str) -> None:
    """Docker Image Security Scanner — zero-trust container security gate."""
    ctx.ensure_object(dict)
    config = ScannerConfig.from_env()
    config.log_level = log_level
    ctx.obj["config"] = config
    ctx.obj["scanner"] = SecurityScanner(config)


@cli.command("image")
@click.argument("image_ref")
@click.option("--dockerfile", "-d", default=None, help="Path to Dockerfile for linting.")
@click.option("--scan-path", "-s", default=None, help="Directory to scan for secrets.")
@click.option("--output-dir", "-o", default="reports", show_default=True)
@click.option("--no-sbom", is_flag=True, default=False, help="Skip SBOM generation.")
@click.option("--fail-on-severity", default=None, help="Override FAIL_ON_SEVERITY env var.")
@click.pass_context
def scan_image_cmd(
    ctx: click.Context,
    image_ref: str,
    dockerfile: Optional[str],
    scan_path: Optional[str],
    output_dir: str,
    no_sbom: bool,
    fail_on_severity: Optional[str],
) -> None:
    """Scan a Docker image for vulnerabilities, misconfigurations, and secrets.

    IMAGE_REF: Docker image reference (e.g. nginx:1.25, python:3.11-slim)

    Examples:\n
        docker-scan image nginx:1.25\n
        docker-scan image myapp:latest --dockerfile ./Dockerfile --output-dir ./reports
    """
    scanner: SecurityScanner = ctx.obj["scanner"]

    if fail_on_severity:
        scanner.config.fail_on_severity = [s.strip().upper() for s in fail_on_severity.split(",")]

    try:
        result = scanner.scan_image(
            image=image_ref,
            dockerfile_path=dockerfile,
            scan_path=scan_path,
            output_dir=output_dir,
            generate_sbom=not no_sbom,
        )
        sys.exit(0 if result.passed else 1)
    except PolicyViolationError:
        sys.exit(1)
    except ScannerError as exc:
        console.print(f"[bold red]Scanner error:[/bold red] {exc}")
        sys.exit(2)


@cli.command("dockerfile")
@click.argument("dockerfile_path")
@click.pass_context
def scan_dockerfile_cmd(ctx: click.Context, dockerfile_path: str) -> None:
    """Lint a Dockerfile with Hadolint.

    DOCKERFILE_PATH: Path to the Dockerfile.
    """
    config: ScannerConfig = ctx.obj["config"]
    try:
        from .hadolint_scanner import HadolintScanner
        scanner = HadolintScanner(config)
        result = scanner.scan(dockerfile_path)
        console.print(result.summary())
        for issue in result.issues:
            color = SEVERITY_COLORS.get(issue.severity, "white")
            console.print(
                f"  [{color}]{issue.level.upper()}[/{color}] "
                f"Line {issue.line}: [{issue.code}] {issue.message}"
            )
        sys.exit(0 if result.passed else 1)
    except ScannerError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        sys.exit(2)


if __name__ == "__main__":
    cli()
