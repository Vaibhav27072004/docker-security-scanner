"""
app.py — Secure demo application.

Demonstrates security best practices:
  - No hardcoded secrets (all config loaded from environment variables)
  - Security response headers (X-Content-Type-Options, X-Frame-Options)
  - Proper error handling and structured logging
  - Graceful SIGTERM shutdown
  - Minimal attack surface (no unnecessary imports or dependencies)
"""

from __future__ import annotations

import logging
import os
import signal
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import FrameType

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


# ✅ SECURE: Load credentials from environment variables (never hardcoded)
def get_config() -> dict[str, str]:
    """Load application configuration from environment variables.

    Returns:
        Mapping of variable name to value for all required env vars.

    Raises:
        SystemExit: If any required variable is missing or empty.
    """
    required_vars = ["DATABASE_URL", "SECRET_KEY"]
    config: dict[str, str] = {}

    for var in required_vars:
        value = os.environ.get(var)
        if not value:
            logger.error("Required environment variable %s is not set.", var)
            sys.exit(1)
        config[var] = value

    return config


class SecureHandler(BaseHTTPRequestHandler):
    """Secure HTTP request handler."""

    def do_GET(self) -> None:
        """Handle GET requests securely."""
        if self.path == "/health":
            self._send_response(200, b"OK")
        elif self.path == "/":
            self._send_response(200, b"Secure Demo App - Running")
        else:
            self._send_response(404, b"Not Found")

    def _send_response(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))  # prevents response-splitting
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:  # type: ignore[override]
        """Route access logs through the application logger."""
        logger.info("[HTTP] %s", fmt % args)


def main() -> None:
    """Start the secure application server."""
    logger.info("Secure Demo App starting...")

    # Graceful shutdown handler
    def handle_sigterm(signum: int, frame: FrameType | None) -> None:
        logger.info("Received SIGTERM, shutting down gracefully.")
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_sigterm)

    # ✅ Load and validate required config at startup — fail fast if missing
    get_config()

    port = int(os.environ.get("PORT", "8080"))
    server = HTTPServer(("0.0.0.0", port), SecureHandler)

    uid = os.getuid() if hasattr(os, "getuid") else -1
    logger.info("Listening on port %d (running as UID %d)", port, uid)
    server.serve_forever()


if __name__ == "__main__":
    main()
