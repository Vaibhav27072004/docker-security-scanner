# Getting Started with Docker Security Scanner

Welcome! This guide walks you through your **first security scan** in under 5 minutes.

---

## Prerequisites

| Requirement | Version | Check |
|-------------|---------|-------|
| Python | ≥ 3.9 | `python --version` |
| Docker | ≥ 24.0 | `docker --version` |
| [Trivy](https://aquasecurity.github.io/trivy/latest/getting-started/installation/) | ≥ 0.50 | `trivy --version` |
| [Hadolint](https://github.com/hadolint/hadolint#install) | ≥ 2.12 | `hadolint --version` |
| [Gitleaks](https://github.com/gitleaks/gitleaks#installing) | ≥ 8.18 | `gitleaks version` |

---

## Step 1 — Clone & Install

```bash
git clone https://github.com/yourusername/docker-security-scanner.git
cd docker-security-scanner

# Create virtual environment
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt
pip install -e .
```

---

## Step 2 — Configure Environment

```bash
cp .env.example .env
# Edit .env if you need to override defaults (paths, thresholds, etc.)
```

---

## Step 3 — Run Your First Scan

Scan the deliberately vulnerable example image:

```bash
# Build the example image
docker build -t demo-vulnerable:latest examples/vulnerable-app/

# Run the full security scan
docker-scan image demo-vulnerable:latest \
  --dockerfile examples/vulnerable-app/Dockerfile \
  --scan-path examples/vulnerable-app/ \
  --output-dir reports/
```

**Expected output:**
```
────────────────────────────────────────────────────────────
 🔒 Docker Security Scanner
────────────────────────────────────────────────────────────
Scanning image: demo-vulnerable:latest

Step 1/4: Running Trivy CVE scan...
┌──────────────────────┐
│     CVE Summary      │
├──────────────┬───────┤
│ CRITICAL     │    12 │
│ HIGH         │    47 │
│ MEDIUM       │    38 │
│ LOW          │    19 │
└──────────────┴───────┘

Step 2/4: Running Hadolint Dockerfile lint...
  Hadolint: ✗ FAILED — Errors: 2, Warnings: 6

Step 3/4: Running Gitleaks secret scan...
  Gitleaks: ✗ FAILED — Secrets: 3

Step 4/4: Generating SBOM...
  ✓ CYCLONEDX SBOM: reports/sbom_demo-vulnerable_latest_cyclonedx.json
  ✓ SPDX SBOM: reports/sbom_demo-vulnerable_latest_spdx.spdx.json

Generating reports...
  ✓ HTML report: reports/security_report.html
  ✓ JSON report: reports/security_report.json
  ✓ MARKDOWN report: reports/security_report.md

❌ Security policy violated: 12 CRITICAL CVEs (threshold: 0); 3 hardcoded secrets detected
```

---

## Step 4 — View Reports

Open the HTML dashboard:

```bash
# Linux/macOS
open reports/security_report.html

# Windows
start reports/security_report.html
```

The dashboard shows:
- **CVE table** with severity badges, CVSS scores, and NVD links
- **Dockerfile lint issues** with rule references
- **Secret findings** with file locations (redacted values)

---

## Step 5 — Scan the Secure App

Compare with the corrected secure version:

```bash
docker build -t demo-secure:latest examples/secure-app/
docker-scan image demo-secure:latest \
  --dockerfile examples/secure-app/Dockerfile \
  --scan-path examples/secure-app/ \
  --output-dir reports-secure/
```

You'll see dramatically fewer findings, demonstrating the value of the security controls applied.

---

## Next Steps

- 📖 [Configuration Guide](configuration.md) — tune thresholds, formats, and tool settings
- 🔧 [GitHub Actions Setup](.github/workflows/security-scan.yml) — automate in CI/CD
- 🏗️ [Architecture](../ARCHITECTURE.md) — understand how the scanner works internally
- 🔍 [Troubleshooting](troubleshooting.md) — common issues and fixes
