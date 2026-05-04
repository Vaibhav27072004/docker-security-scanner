# ─────────────────────────────────────────────────────────────────────────────
# Intentionally VULNERABLE Dockerfile — For demonstration purposes ONLY
# This Dockerfile contains deliberate security issues to showcase
# what the Docker Security Scanner detects.
#
# DO NOT deploy this image to production!
# ─────────────────────────────────────────────────────────────────────────────

# Issue 1: Using 'latest' tag — unpinned, non-reproducible, insecure
FROM ubuntu:latest

# Issue 2: No non-root USER specified — runs as root by default
# Issue 3: Not pinning package versions
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    wget \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Issue 4: COPY . . copies everything including .env files, secrets, etc.
COPY . .

# Issue 5: Hardcoded sensitive values in ENV (visible in image layers!)
ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
ENV DATABASE_URL=postgresql://admin:supersecretpassword@db.internal:5432/prod

# Issue 6: Installing dependencies with no hash verification
RUN pip3 install --break-system-packages -r requirements.txt

# Issue 7: Running on a privileged port (requires root)
EXPOSE 80

# Issue 8: No HEALTHCHECK instruction
# Issue 9: CMD using shell form (harder to send signals)
CMD python3 app.py
