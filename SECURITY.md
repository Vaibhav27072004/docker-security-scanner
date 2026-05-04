# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x (latest) | ✅ |
| < 1.0 | ❌ |

---

## Reporting a Vulnerability

If you discover a security vulnerability in **Docker Security Scanner** itself
(not in images it scans), please follow responsible disclosure:

1. **Do NOT** open a public GitHub issue for security vulnerabilities
2. Email: **security@yourdomain.com** with subject `[SECURITY] Docker Security Scanner`
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will acknowledge within **48 hours** and aim to release a patch within **7 days**
for critical issues.

---

## Security Assumptions & Limitations

### What This Tool Does
- Scans Docker images for **known** CVEs (from NVD/OSV databases)
- Lints Dockerfiles for **known** anti-patterns
- Detects **pattern-matched** secrets (not all possible secrets)
- Generates SBOMs for software supply chain visibility

### Known Limitations

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| Zero-day CVEs not in databases | CRITICAL findings may be missed | Supplement with DAST and runtime security |
| Secret patterns may have false negatives | Novel secrets may not be detected | Use key rotation as defence-in-depth |
| Only scans the final image layer | Build-time secrets in intermediate layers detected only with `--all-targets` | Use multi-stage builds to eliminate secrets |
| Trivy DB freshness | Scans use the DB from last update | Enable daily scheduled scans |

### Out of Scope
- Runtime container security (use Falco, Sysdig)
- Network security policies (use Kubernetes NetworkPolicies)
- Runtime secret injection (use Vault, AWS Secrets Manager)

---

## Best Practices for Users

### Secrets Management
```bash
# ❌ NEVER do this
ENV AWS_SECRET_KEY=real-secret-key

# ✅ DO this instead — inject at runtime
docker run -e AWS_SECRET_KEY="$(aws secretsmanager get-secret-value ...)" myapp:latest
```

### Image Pinning
```dockerfile
# ❌ Unpinned
FROM python:3.11

# ✅ Pinned with digest
FROM python:3.11.9-slim@sha256:abc123...
```

### Non-Root Execution
```dockerfile
# ✅ Always run as non-root
RUN useradd --uid 10001 appuser
USER appuser
```

---

## Compliance Standards Addressed

| Standard | Coverage |
|----------|----------|
| OWASP Top 10 (Docker) | Vulnerability scanning, secret detection |
| NIST SP 800-190 | Container image security |
| CIS Docker Benchmark | Dockerfile hardening checks via Hadolint |
| Executive Order 14028 | SBOM generation (CycloneDX, SPDX) |
| NTIA SBOM Minimum Elements | CycloneDX and SPDX outputs |
