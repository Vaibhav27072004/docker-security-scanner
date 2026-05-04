"""
report_generator.py — Multi-format security report generation.

Generates HTML dashboards, JSON structured reports, and Markdown summaries
from aggregated scanner results. Designed to integrate with GitHub Actions
PR comments and artifact uploads.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .utils import ScannerConfig, ensure_dir, write_json

if TYPE_CHECKING:
    from .scanner import AggregatedResult

logger = logging.getLogger("docker_security_scanner.report")

# ─── Inline HTML template (no external file needed) ───────────────────────────
_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Docker Security Scan Report — {{ result.image }}</title>
  <style>
    :root {
      --bg: #0d1117; --surface: #161b22; --border: #30363d;
      --text: #e6edf3; --muted: #8b949e;
      --critical: #ff4444; --high: #ff8c00; --medium: #ffd700;
      --low: #4fc3f7; --pass: #3fb950;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; padding: 2rem; }
    h1 { font-size: 1.8rem; margin-bottom: 0.4rem; }
    h2 { font-size: 1.2rem; margin: 1.5rem 0 0.6rem; color: var(--muted); border-bottom: 1px solid var(--border); padding-bottom: 0.3rem; }
    .meta { color: var(--muted); font-size: 0.85rem; margin-bottom: 2rem; }
    .badge { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 999px; font-size: 0.8rem; font-weight: 700; }
    .badge-CRITICAL { background: var(--critical); }
    .badge-HIGH { background: var(--high); }
    .badge-MEDIUM { background: var(--medium); color: #000; }
    .badge-LOW { background: var(--low); color: #000; }
    .badge-PASS { background: var(--pass); }
    .badge-FAIL { background: var(--critical); }
    .cards { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.2rem 1.8rem; min-width: 140px; }
    .card .num { font-size: 2.4rem; font-weight: 700; }
    .card .label { color: var(--muted); font-size: 0.8rem; margin-top: 0.2rem; }
    .card.critical .num { color: var(--critical); }
    .card.high .num { color: var(--high); }
    .card.medium .num { color: var(--medium); }
    .card.low .num { color: var(--low); }
    .card.pass .num { color: var(--pass); }
    table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    th { background: var(--surface); padding: 0.6rem 0.8rem; text-align: left; color: var(--muted); font-weight: 600; }
    td { padding: 0.5rem 0.8rem; border-top: 1px solid var(--border); vertical-align: top; }
    tr:hover td { background: #1c2128; }
    a { color: #58a6ff; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .section { margin-bottom: 2.5rem; }
    .status-bar { display: flex; align-items: center; gap: 1rem; padding: 1rem 1.5rem;
                  border-radius: 8px; margin-bottom: 2rem; font-weight: 600; }
    .status-bar.pass { background: #1a3a1f; border: 1px solid var(--pass); }
    .status-bar.fail { background: #3a1a1a; border: 1px solid var(--critical); }
  </style>
</head>
<body>
  <h1>🔒 Docker Security Scan Report</h1>
  <div class="meta">Image: <strong>{{ result.image }}</strong> &nbsp;|&nbsp; Generated: {{ result.scan_timestamp }}</div>

  <div class="status-bar {{ 'pass' if result.passed else 'fail' }}">
    <span class="badge {{ 'badge-PASS' if result.passed else 'badge-FAIL' }}">
      {{ '✓ PASSED' if result.passed else '✗ FAILED' }}
    </span>
    <span>Overall Security Status</span>
  </div>

  <div class="cards">
    <div class="card critical"><div class="num">{{ result.trivy.critical_count }}</div><div class="label">Critical CVEs</div></div>
    <div class="card high"><div class="num">{{ result.trivy.high_count }}</div><div class="label">High CVEs</div></div>
    <div class="card medium"><div class="num">{{ result.trivy.medium_count }}</div><div class="label">Medium CVEs</div></div>
    <div class="card low"><div class="num">{{ result.trivy.low_count }}</div><div class="label">Low CVEs</div></div>
    <div class="card"><div class="num">{{ result.hadolint.total_count }}</div><div class="label">Lint Issues</div></div>
    <div class="card high"><div class="num">{{ result.gitleaks.total_count }}</div><div class="label">Secrets Found</div></div>
  </div>

  <div class="section">
    <h2>🛡️ Vulnerability Findings (Top 20)</h2>
    {% if result.trivy.vulnerabilities %}
    <table>
      <thead><tr><th>CVE ID</th><th>Severity</th><th>Package</th><th>Installed</th><th>Fixed</th><th>CVSS</th></tr></thead>
      <tbody>
        {% for v in result.trivy.vulnerabilities[:20] %}
        <tr>
          <td><a href="{{ v.nvd_url }}" target="_blank">{{ v.id }}</a></td>
          <td><span class="badge badge-{{ v.severity }}">{{ v.severity }}</span></td>
          <td>{{ v.package_name }}</td>
          <td>{{ v.installed_version }}</td>
          <td>{{ v.fixed_version }}</td>
          <td>{{ v.cvss_score }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    {% else %}
    <p style="color: var(--pass)">✓ No vulnerabilities detected.</p>
    {% endif %}
  </div>

  <div class="section">
    <h2>📋 Dockerfile Lint Issues</h2>
    {% if result.hadolint.issues %}
    <table>
      <thead><tr><th>Code</th><th>Level</th><th>Line</th><th>Message</th></tr></thead>
      <tbody>
        {% for i in result.hadolint.issues %}
        <tr>
          <td><a href="{{ i.url }}" target="_blank">{{ i.code }}</a></td>
          <td><span class="badge badge-{{ i.severity }}">{{ i.level }}</span></td>
          <td>{{ i.line }}</td>
          <td>{{ i.message }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    {% else %}
    <p style="color: var(--pass)">✓ No Dockerfile issues detected.</p>
    {% endif %}
  </div>

  <div class="section">
    <h2>🔑 Secret Findings</h2>
    {% if result.gitleaks.findings %}
    <table>
      <thead><tr><th>Rule</th><th>Severity</th><th>File</th><th>Line</th><th>Description</th></tr></thead>
      <tbody>
        {% for f in result.gitleaks.findings %}
        <tr>
          <td>{{ f.rule_id }}</td>
          <td><span class="badge badge-{{ f.severity }}">{{ f.severity }}</span></td>
          <td>{{ f.file }}</td>
          <td>{{ f.line_number }}</td>
          <td>{{ f.description }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    {% else %}
    <p style="color: var(--pass)">✓ No secrets detected.</p>
    {% endif %}
  </div>

  <div class="meta" style="margin-top: 2rem; border-top: 1px solid var(--border); padding-top: 1rem;">
    Generated by Docker Security Scanner &nbsp;|&nbsp;
    <a href="https://github.com/yourusername/docker-security-scanner">GitHub</a>
  </div>
</body>
</html>
"""


class ReportGenerator:
    """Generate security scan reports in multiple formats.

    Args:
        config: ScannerConfig instance.

    Example::

        generator = ReportGenerator(config)
        paths = generator.generate_all(result, output_dir="reports")
        print(paths)
    """

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config

    def generate_all(
        self, result: "AggregatedResult", output_dir: str = "reports"
    ) -> dict[str, str]:
        """Generate all configured report formats.

        Args:
            result: Aggregated scan result.
            output_dir: Directory to write reports.

        Returns:
            Dictionary mapping format → file path.
        """
        out = ensure_dir(output_dir)
        paths: dict[str, str] = {}

        for fmt in self.config.report_formats:
            if fmt == "html":
                paths["html"] = self._generate_html(result, out)
            elif fmt == "json":
                paths["json"] = self._generate_json(result, out)
            elif fmt == "markdown":
                paths["markdown"] = self._generate_markdown(result, out)

        logger.info("Reports written to %s: %s", out, list(paths.keys()))
        return paths

    def _generate_html(self, result: "AggregatedResult", out: Path) -> str:
        """Render the HTML dashboard report."""
        from jinja2 import Environment
        env = Environment(autoescape=select_autoescape(["html"]))
        template = env.from_string(_HTML_TEMPLATE)
        html_content = template.render(result=result)
        output_path = out / "security_report.html"
        output_path.write_text(html_content, encoding="utf-8")
        logger.info("HTML report: %s", output_path)
        return str(output_path)

    def _generate_json(self, result: "AggregatedResult", out: Path) -> str:
        """Write the JSON structured report."""
        output_path = out / "security_report.json"
        write_json(result.to_dict(), output_path)
        logger.info("JSON report: %s", output_path)
        return str(output_path)

    def _generate_markdown(self, result: "AggregatedResult", out: Path) -> str:
        """Write a Markdown summary for GitHub PR comments."""
        status = "✅ PASSED" if result.passed else "❌ FAILED"
        lines = [
            f"## 🔒 Docker Security Scan — {status}",
            f"",
            f"**Image:** `{result.image}`  ",
            f"**Scanned:** {result.scan_timestamp}",
            f"",
            f"### 📊 Summary",
            f"",
            f"| Check | Status | Findings |",
            f"|-------|--------|----------|",
            f"| CVE Scan (Trivy) | {'✅' if result.trivy.passed else '❌'} | "
            f"CRITICAL: {result.trivy.critical_count}, HIGH: {result.trivy.high_count}, "
            f"MEDIUM: {result.trivy.medium_count}, LOW: {result.trivy.low_count} |",
            f"| Dockerfile Lint (Hadolint) | {'✅' if result.hadolint.passed else '⚠️'} | "
            f"{result.hadolint.total_count} issues |",
            f"| Secret Detection (Gitleaks) | {'✅' if result.gitleaks.passed else '❌'} | "
            f"{result.gitleaks.total_count} secrets found |",
        ]

        if result.trivy.critical_count > 0:
            lines += ["", "### 🚨 Critical Vulnerabilities (Top 5)", ""]
            lines.append("| CVE ID | Package | Installed | Fixed | CVSS |")
            lines.append("|--------|---------|-----------|-------|------|")
            for v in result.trivy.by_severity("CRITICAL")[:5]:
                lines.append(
                    f"| [{v.id}]({v.nvd_url}) | {v.package_name} | "
                    f"{v.installed_version} | {v.fixed_version} | {v.cvss_score} |"
                )

        if result.gitleaks.findings:
            lines += ["", "### 🔑 Secrets Detected", ""]
            lines.append("| Rule | File | Line | Severity |")
            lines.append("|------|------|------|----------|")
            for f in result.gitleaks.findings[:5]:
                lines.append(f"| {f.rule_id} | `{f.file}` | {f.line_number} | {f.severity} |")

        output_path = out / "security_report.md"
        output_path.write_text("\n".join(lines), encoding="utf-8")
        logger.info("Markdown report: %s", output_path)
        return str(output_path)
