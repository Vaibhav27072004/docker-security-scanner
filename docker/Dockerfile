# ─────────────────────────────────────────────────────────────────────────────
# Docker Security Scanner — Scanner Container Image
# Packages all three tools (Trivy, Hadolint, Gitleaks) with the Python scanner
# into a self-contained, portable container.
# ─────────────────────────────────────────────────────────────────────────────

FROM python:3.11.9-slim AS base

# ── Tool versions ─────────────────────────────────────────────────────────────
ARG TRIVY_VERSION=0.50.1
ARG HADOLINT_VERSION=v2.12.0
ARG GITLEAKS_VERSION=8.18.4

# ── System dependencies ───────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    ca-certificates \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# ── Install Trivy ─────────────────────────────────────────────────────────────
RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | \
        gpg --dearmor > /usr/share/keyrings/trivy.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
        > /etc/apt/sources.list.d/trivy.list \
    && apt-get update -q \
    && apt-get install -y trivy \
    && rm -rf /var/lib/apt/lists/*

# ── Install Hadolint ──────────────────────────────────────────────────────────
RUN curl -sSL \
    "https://github.com/hadolint/hadolint/releases/download/${HADOLINT_VERSION}/hadolint-Linux-x86_64" \
    -o /usr/local/bin/hadolint \
    && chmod +x /usr/local/bin/hadolint

# ── Install Gitleaks ─────────────────────────────────────────────────────────
RUN curl -sSL \
    "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks

# ── Python scanner ───────────────────────────────────────────────────────────
WORKDIR /scanner

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/
COPY setup.py .
COPY README.md .
RUN pip install --no-cache-dir -e .

# ── Non-root user ─────────────────────────────────────────────────────────────
RUN groupadd --gid 10001 scanner \
    && useradd --uid 10001 --gid scanner --no-create-home scanner

# ── Output directory ──────────────────────────────────────────────────────────
RUN mkdir -p /reports && chown scanner:scanner /reports

USER scanner

VOLUME ["/scan-target", "/reports"]

# ── Entrypoint ────────────────────────────────────────────────────────────────
ENTRYPOINT ["docker-scan"]
CMD ["--help"]

# ── Labels ────────────────────────────────────────────────────────────────────
LABEL org.opencontainers.image.title="Docker Security Scanner" \
      org.opencontainers.image.description="Automated Docker image security scanner with Trivy, Hadolint, and Gitleaks" \
      org.opencontainers.image.source="https://github.com/yourusername/docker-security-scanner" \
      org.opencontainers.image.licenses="MIT"
