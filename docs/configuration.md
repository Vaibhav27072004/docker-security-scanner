# Configuration Guide

Complete reference for all scanner configuration options.

---

## Configuration Sources (Priority Order)

1. **CLI flags** — highest priority
2. **Environment variables** (`.env` file via python-dotenv)
3. **Built-in defaults** — lowest priority

---

## Environment Variables Reference

### Severity Policy

| Variable | Default | Description |
|----------|---------|-------------|
| `FAIL_ON_SEVERITY` | `CRITICAL,HIGH` | Comma-separated severities that trigger pipeline failure |
| `CRITICAL_THRESHOLD` | `0` | Max CRITICAL CVEs allowed (0 = any triggers failure) |
| `HIGH_THRESHOLD` | `10` | Max HIGH CVEs allowed (0 = disabled) |

**Example — strict policy (zero tolerance):**
```bash
FAIL_ON_SEVERITY=CRITICAL,HIGH,MEDIUM
CRITICAL_THRESHOLD=0
HIGH_THRESHOLD=0
```

**Example — relaxed policy (only block on critical):**
```bash
FAIL_ON_SEVERITY=CRITICAL
CRITICAL_THRESHOLD=0
HIGH_THRESHOLD=0
```

---

### Tool Paths

| Variable | Default | Description |
|----------|---------|-------------|
| `TRIVY_PATH` | `trivy` | Path to Trivy binary |
| `HADOLINT_PATH` | `hadolint` | Path to Hadolint binary |
| `GITLEAKS_PATH` | `gitleaks` | Path to Gitleaks binary |

Useful for non-standard install locations:
```bash
TRIVY_PATH=/opt/security-tools/trivy
```

---

### Trivy Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `TRIVY_CACHE_DIR` | `.trivy-cache` | Trivy vulnerability DB cache directory |
| `TRIVY_SKIP_UPDATE` | `false` | Skip DB update (air-gapped environments) |

**Air-gapped environment setup:**
```bash
# On internet-connected machine:
trivy image --download-db-only --cache-dir /shared/trivy-cache

# On air-gapped machine:
TRIVY_CACHE_DIR=/shared/trivy-cache
TRIVY_SKIP_UPDATE=true
```

---

### Hadolint Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `HADOLINT_CONFIG` | _(none)_ | Path to `.hadolint.yaml` config |
| `HADOLINT_IGNORE` | _(none)_ | Comma-separated rule IDs to ignore |

**Example `.hadolint.yaml`:**
```yaml
ignore:
  - DL3008  # Allow unpinned apt packages in dev environments
  - DL3009
trustedRegistries:
  - docker.io
  - gcr.io
  - ghcr.io
```

---

### Gitleaks Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `GITLEAKS_CONFIG` | _(none)_ | Path to `.gitleaks.toml` config |

**Example `.gitleaks.toml` (allowlist):**
```toml
[allowlist]
  description = "Allowlist for test fixtures"
  paths = [
    "tests/fixtures/.*",
    "examples/vulnerable-app/.*"   # Demo secrets are intentional
  ]
```

---

### Reporting

| Variable | Default | Description |
|----------|---------|-------------|
| `REPORT_OUTPUT_DIR` | `reports` | Output directory for all reports |
| `REPORT_FORMATS` | `html,json,markdown` | Comma-separated list of formats |
| `SBOM_FORMATS` | `cyclonedx,spdx` | Comma-separated SBOM formats |

---

### Notifications

| Variable | Default | Description |
|----------|---------|-------------|
| `GITHUB_TOKEN` | _(none)_ | GitHub token for PR comments and check runs |
| `SLACK_WEBHOOK_URL` | _(none)_ | Slack Incoming Webhook URL |

---

### Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `INFO` | Log verbosity: DEBUG, INFO, WARNING, ERROR |
| `LOG_FILE` | _(none)_ | Write logs to file (in addition to stdout) |

---

## CLI Override Flags

The `docker-scan image` command accepts flags that override env vars:

```
Usage: docker-scan image [OPTIONS] IMAGE_REF

Options:
  -d, --dockerfile PATH       Dockerfile to lint with Hadolint
  -s, --scan-path PATH        Directory to scan for secrets
  -o, --output-dir PATH       Output directory for reports [default: reports]
  --no-sbom                   Skip SBOM generation
  --fail-on-severity TEXT     Override FAIL_ON_SEVERITY
  --log-level TEXT            Override LOG_LEVEL
  --help                      Show this message and exit.
```

**Examples:**

```bash
# Scan with custom severity threshold
docker-scan image myapp:latest --fail-on-severity CRITICAL

# Scan with Dockerfile lint, custom output dir
docker-scan image myapp:latest \
  --dockerfile ./Dockerfile \
  --output-dir /tmp/scan-reports

# Quick scan (no SBOM, no secrets)
docker-scan image myapp:latest --no-sbom
```
