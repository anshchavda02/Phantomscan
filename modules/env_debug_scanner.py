"""Environment and debug route scanner module with HTML catch-all rejection."""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Optional
from urllib.parse import urlparse

from modules.response_validator import ResponseContentValidator

logger = logging.getLogger(__name__)

MODULE_GROUP = "ai_app_security"


class EnvDebugScanner:
    """Scan for exposed environment files, debug routes, and build artifacts."""

    PATHS_TO_CHECK: list[str] = [
        # Environment files
        "/.env", "/.env.local", "/.env.production",
        "/.env.development", "/.env.example",
        # Common vibe-platform build artifacts
        "/.vercel/output/config.json",
        "/api/debug", "/api/_debug",
        "/api/health/env", "/debug", "/__debug__",
        "/api/config", "/config.json",
        "/api/test", "/api/dev",
        "/preview", "/__preview",
        # Git & source exposure
        "/.git/config", "/.git/HEAD",
        # Dependency & config exposure
        "/package.json", "/vite.config.js.map",
        "/next.config.js", "/vercel.json",
        "/netlify.toml",
    ]

    _SENSITIVE_ENV_KEYS = frozenset({
        "API_KEY", "SECRET", "TOKEN", "PASSWORD",
        "DATABASE_URL", "PRIVATE_KEY", "AUTH",
        "OPENAI", "ANTHROPIC", "SUPABASE_SERVICE",
        "STRIPE_SECRET", "JWT_SECRET",
    })

    def __init__(self, http: Any) -> None:
        self.http = http

    async def scan(self, target: str) -> list[dict[str, Any]]:
        """Probe each path and return findings for exposed resources."""
        findings: list[dict[str, Any]] = []

        parsed = urlparse(target)
        if parsed.scheme and parsed.netloc:
            base = f"{parsed.scheme}://{parsed.netloc}"
        else:
            base = target.rstrip("/")

        for path in self.PATHS_TO_CHECK:
            url = base + path
            try:
                resp = await self.http.get(url, retries=1)
                status = getattr(resp, "status", getattr(resp, "status_code", 0))
                if status != 200:
                    continue

                if hasattr(resp, "text"):
                    if callable(resp.text):
                        body = resp.text()
                    else:
                        body = str(resp.text)
                elif hasattr(resp, "body"):
                    if isinstance(resp.body, bytes):
                        body = resp.body.decode("utf-8", errors="ignore")
                    else:
                        body = str(resp.body)
                else:
                    body = str(resp)

                headers = getattr(resp, "headers", {})
                ct = ""
                if isinstance(headers, dict):
                    ct = headers.get("content-type", headers.get("Content-Type", "")).lower()

                finding = self._classify(path, url, body, ct)
                if finding:
                    findings.append(finding)

            except Exception as exc:
                logger.debug("Env/debug scan error %s: %s", url, exc)

        return findings

    def _classify(
        self, path: str, url: str, body: str, content_type: str = ""
    ) -> dict[str, Any] | None:
        """Classify a 200-OK response for a sensitive path."""
        # First check: reject if response is clearly an HTML page (catch-all or error)
        if ResponseContentValidator.is_html_page(body, content_type):
            return None

        if path.startswith("/.env"):
            found_keys = [
                line.split("=")[0].strip()
                for line in body.splitlines()
                if "=" in line
                and any(sk in line.upper() for sk in self._SENSITIVE_ENV_KEYS)
            ]
            has_env_pattern = bool(re.search(r"^[A-Z0-9_]+=.+", body, re.MULTILINE))
            if found_keys or has_env_pattern:
                return {
                    "id": "AI-ENV-FILE-EXPOSED",
                    "title": f".env File Publicly Accessible: {path}",
                    "severity": "critical",
                    "confidence": "high",
                    "category": MODULE_GROUP,
                    "target": url,
                    "evidence": (
                        f"URL: {url}\n"
                        f"Sensitive-looking keys found: {found_keys}\n"
                        f"File size: {len(body)} bytes"
                    ),
                    "recommendation": (
                        "Ensure .env files are excluded from the deployment "
                        "build output, add to .gitignore, and rotate every "
                        "credential found in this file immediately."
                    ),
                    "references": ["CWE-538"],
                }

        if path in ("/.git/config", "/.git/HEAD"):
            if "ref: refs/" in body or "[core]" in body or "[remote" in body or "repositoryformatversion" in body:
                return {
                    "id": "AI-GIT-EXPOSED",
                    "title": ".git Directory Exposed",
                    "severity": "high",
                    "confidence": "high",
                    "category": MODULE_GROUP,
                    "target": url,
                    "evidence": (
                        f"URL: {url}\n"
                        "The .git directory is publicly accessible, potentially "
                        "exposing full source code history, commit messages, "
                        "and any secrets ever committed."
                    ),
                    "recommendation": (
                        "Block access to .git/ in your web server configuration "
                        "or deployment settings."
                    ),
                    "references": ["CWE-538"],
                }

        if path in ("/api/debug", "/api/_debug", "/debug", "/__debug__", "/api/health/env", "/api/config"):
            return {
                "id": "AI-DEBUG-ENDPOINT",
                "title": f"Debug Endpoint Accessible: {path}",
                "severity": "high",
                "confidence": "medium",
                "category": MODULE_GROUP,
                "target": url,
                "evidence": (
                    f"URL: {url}\n"
                    f"Response preview: {body[:300]}\n"
                    "A debug/development endpoint is accessible in what "
                    "appears to be a production deployment."
                ),
                "recommendation": (
                    "Disable or remove all debug endpoints in production. "
                    "Use environment-based feature flags to prevent debug "
                    "routes from being registered."
                ),
                "references": ["CWE-489"],
            }

        if path == "/package.json":
            if '"dependencies"' in body or '"devDependencies"' in body or '"name"' in body:
                return {
                    "id": "AI-PACKAGE-JSON-EXPOSED",
                    "title": "package.json Publicly Accessible",
                    "severity": "low",
                    "confidence": "high",
                    "category": MODULE_GROUP,
                    "target": url,
                    "evidence": (
                        f"URL: {url}\n"
                        "package.json is readable, exposing exact dependency "
                        "versions (useful for CVE targeting) and potentially "
                        "custom scripts."
                    ),
                    "recommendation": (
                        "Block access to package.json from the public web "
                        "server or exclude it from the deployment build."
                    ),
                    "references": ["CWE-200"],
                }

        return None
