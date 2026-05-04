"""
app.py — Deliberately insecure demo application.

This file intentionally contains hardcoded secrets and poor security
practices to demonstrate what the Docker Security Scanner detects.

DO NOT use any of these patterns in real code!
"""

import os
import sqlite3

# ── SECURITY ISSUE: Hardcoded AWS credentials ────────────────────────────────
# These would be detected by Gitleaks as secret findings
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# ── SECURITY ISSUE: Hardcoded GitHub token ───────────────────────────────────
GITHUB_TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"

# ── SECURITY ISSUE: Hardcoded database password ──────────────────────────────
DB_PASSWORD = "supersecretpassword123!"
DB_CONNECTION = f"postgresql://admin:{DB_PASSWORD}@db.internal:5432/production"

# ── SECURITY ISSUE: Hardcoded Slack webhook ──────────────────────────────────
# SECURITY ISSUE: Slack webhook (intentionally fake for demo — triggers Gitleaks)
SLACK_WEBHOOK = "https://hooks.slack.com/services/TXXXXXX/BXXXXXX/DEMO_WEBHOOK_NOT_REAL"


def get_db_connection():
    """SECURITY ISSUE: Using SQLite with no parameterised queries."""
    conn = sqlite3.connect("vulnerable.db")
    return conn


def unsafe_query(user_input: str) -> list:
    """SECURITY ISSUE: SQL injection vulnerability."""
    conn = get_db_connection()
    cursor = conn.cursor()
    # Never do this — SQL injection risk!
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor.execute(query)
    return cursor.fetchall()


def main():
    """Run the demo vulnerable application."""
    print("⚠️  WARNING: This is a deliberately insecure demo application!")
    print("=" * 60)
    print(f"AWS Key: {AWS_ACCESS_KEY[:8]}...")
    print(f"DB: {DB_CONNECTION[:30]}...")
    print("Running insecure HTTP server on port 80...")

    # Simulate a basic server (do not actually use this)
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class VulnerableHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            # SECURITY ISSUE: Exposing internal configuration to any client
            self.send_response(200)
            self.end_headers()
            response = (
                f"App running as user: {os.getenv('USER', 'root')}\n"
                f"DB: {DB_CONNECTION}\n"  # NEVER expose this!
            )
            self.wfile.write(response.encode())

    server = HTTPServer(("0.0.0.0", 80), VulnerableHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
