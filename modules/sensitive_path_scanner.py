"""Sensitive path scanner with body verification, catch-all detection, and web-root probing."""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlparse

from phantomscan.models import Finding
from modules.catch_all_detector import CatchAllDetector, CatchAllResult
from modules.response_validator import ResponseContentValidator

logger = logging.getLogger(__name__)


@dataclass
class VerifyResult:
    confirmed: bool
    reason: str


class SensitivePathScanner:
    """Probes for sensitive files and directories at the correct location (web root),
    not appended to existing discovered page URLs, and verifies the response body matches
    expected content before flagging as a finding.
    """

    SENSITIVE_PATHS: list[dict[str, Any]] = [
        # Git exposure — body must contain git ref string
        {
            "path": "/.git/HEAD",
            "severity": "Critical",
            "verify_body": [
                "ref: refs/heads/",
                "ref: refs/tags/",
            ],
            "verify_type": "contains_any",
            "false_positive_note": "Must contain git ref string. HTML or redirect = false positive.",
        },
        {
            "path": "/.git/config",
            "severity": "Critical",
            "verify_body": ["[core]", "[remote"],
            "verify_type": "contains_any",
        },

        # Environment files — body must have KEY=VALUE
        {
            "path": "/.env",
            "severity": "Critical",
            "verify_body": [
                r"[A-Z_]+=.+",  # env var pattern
                "DB_PASSWORD", "API_KEY", "SECRET",
                "DATABASE_URL", "APP_KEY",
            ],
            "verify_type": "contains_any",
            "false_positive_note": "Must contain KEY=VALUE env var format. HTML = false positive.",
        },
        {
            "path": "/.env.local",
            "severity": "Critical",
            "verify_body": [r"[A-Z_]+=.+"],
            "verify_type": "contains_any",
        },
        {
            "path": "/.env.production",
            "severity": "Critical",
            "verify_body": [r"[A-Z_]+=.+"],
            "verify_type": "contains_any",
        },

        # Config files — body must match file format
        {
            "path": "/web.config",
            "severity": "Critical",
            "verify_body": [
                "<?xml", "<configuration>",
                "connectionString", "appSettings",
            ],
            "verify_type": "contains_any",
            "false_positive_note": "Must be XML config format. HTML = ASP.NET catch-all, not exposed.",
        },
        {
            "path": "/config.php",
            "severity": "Critical",
            "verify_body": [
                "<?php", "define(", "$db_",
                "$config", "mysqli_connect",
            ],
            "verify_type": "contains_any",
        },
        {
            "path": "/wp-config.php",
            "severity": "Critical",
            "verify_body": [
                "DB_NAME", "DB_PASSWORD",
                "table_prefix", "AUTH_KEY",
            ],
            "verify_type": "contains_any",
        },

        # PHP info — body must contain phpinfo output
        {
            "path": "/phpinfo.php",
            "severity": "High",
            "verify_body": [
                "PHP Version", "phpinfo()",
                "PHP Extension", "php_uname",
            ],
            "verify_type": "contains_any",
        },

        # Admin/debug pages — body must NOT be login redirect or 403 in disguise as 200
        {
            "path": "/admin/",
            "severity": "Medium",
            "verify_body": [
                "admin", "dashboard", "panel",
                "management",
            ],
            "verify_type": "contains_any",
            "also_check_not_login_page": True,
        },
        {
            "path": "/phpmyadmin/",
            "severity": "High",
            "verify_body": [
                "phpMyAdmin", "pma_", "phpmyadmin",
            ],
            "verify_type": "contains_any",
        },

        # ELMAH (ASP.NET error log)
        {
            "path": "/elmah.axd",
            "severity": "High",
            "verify_body": [
                "Error Log for", "ELMAH",
                "errorLogFilters",
            ],
            "verify_type": "contains_any",
            "false_positive_note": "ASP.NET catch-all returns 200 for any path. Body must contain ELMAH content, not login page HTML.",
        },

        # Trace
        {
            "path": "/trace.axd",
            "severity": "High",
            "verify_body": [
                "Application Trace", "Trace Information",
                "Requests to this Application",
            ],
            "verify_type": "contains_any",
        },

        # Apache server-status & .htaccess
        {
            "path": "/.htaccess",
            "severity": "High",
            "verify_body": [
                "RewriteEngine", "AuthType", "Deny from", "Require all",
            ],
            "verify_type": "contains_any",
        },
        {
            "path": "/server-status",
            "severity": "Medium",
            "verify_body": [
                "Apache Server Status", "Server Version:", "Current Time:",
            ],
            "verify_type": "contains_any",
        },

        # Backup files
        {
            "path": "/backup.zip",
            "severity": "Critical",
            "verify_content_type": [
                "application/zip",
                "application/octet-stream",
                "application/x-zip",
            ],
            "verify_type": "content_type",
            "false_positive_note": "Only flag if content-type is zip/binary. HTML content-type = false positive.",
        },
        {
            "path": "/backup.sql",
            "severity": "Critical",
            "verify_body": [
                "CREATE TABLE", "INSERT INTO",
                "DROP TABLE", "-- MySQL dump",
            ],
            "verify_type": "contains_any",
        },

        # DS_Store
        {
            "path": "/.DS_Store",
            "severity": "Low",
            "verify_content_type": [
                "application/octet-stream",
            ],
            "verify_type": "content_type",
            "also_check_min_size": 4,  # DS_Store > 4 bytes
        },
    ]

    def __init__(self, http_client: Any = None) -> None:
        self.http = http_client

    async def scan(
        self,
        target: str,
        catch_all: Optional[CatchAllResult] = None,
    ) -> list[Finding]:
        """CRITICAL: always probe at web root, NEVER at a discovered page URL.
        The base URL for probing is always scheme + host only.
        """
        findings: list[Finding] = []

        parsed = urlparse(target)
        if parsed.scheme and parsed.netloc:
            web_root = f"{parsed.scheme}://{parsed.netloc}"
        else:
            web_root = target.rstrip("/")

        client = self.http
        should_close = False
        if client is None:
            from phantomscan.http_client import RobustHTTPClient
            client = RobustHTTPClient()
            await client.start()
            should_close = True

        if catch_all is None:
            detector = CatchAllDetector(http_client=client)
            catch_all = await detector.detect(web_root)

        try:
            for path_config in self.SENSITIVE_PATHS:
                probe_url = web_root.rstrip("/") + path_config["path"]

                try:
                    response = await client.get(
                        probe_url,
                        timeout=10,
                        allow_redirects=False,
                    )

                    status = getattr(response, "status", getattr(response, "status_code", 0))

                    # Step 1: Status code pre-filter
                    # Only continue checking if 200 or 206
                    # Redirect (301/302/307/308) = not exposed
                    # 403 = exists but blocked (only report as Info, not as a vulnerability)
                    # 404 = not present (skip)
                    # 500 = server error (skip)
                    if status not in [200, 206]:
                        if status == 403:
                            if path_config["severity"] in ("Critical", "High", "critical", "high"):
                                findings.append(Finding(
                                    id=f"SENSITIVE-PATH-BLOCKED-{path_config['path'].replace('/', '-').strip('-').upper()}",
                                    title=f"Sensitive Path Exists (Access Blocked): {path_config['path']}",
                                    severity="info",
                                    confidence="medium",
                                    category="web",
                                    target=probe_url,
                                    description=(
                                        f"Path {path_config['path']} returned 403 — server blocked access. "
                                        f"The path appears to exist but is not publicly readable. "
                                        f"No action required unless the block can be bypassed."
                                    ),
                                    evidence=f"GET {probe_url}\nResponse: HTTP 403",
                                    recommendation="Ensure access controls remain intact.",
                                    verification_method="baseline_differential",
                                    cwe="CWE-538",
                                ))
                        continue

                    # Extract body, content_type, and body_len
                    if hasattr(response, "body") and isinstance(response.body, bytes):
                        body_bytes = response.body
                        body = body_bytes.decode("utf-8", errors="ignore")
                    elif hasattr(response, "text"):
                        if callable(response.text):
                            body = response.text()
                        else:
                            body = str(response.text)
                        body_bytes = body.encode("utf-8", errors="ignore")
                    else:
                        body = str(response)
                        body_bytes = body.encode("utf-8", errors="ignore")

                    headers = getattr(response, "headers", {})
                    content_type = ""
                    if isinstance(headers, dict):
                        content_type = headers.get("content-type", headers.get("Content-Type", "")).lower()
                    body_len = len(body_bytes)

                    # Check catch-all baseline rejection
                    if catch_all.has_catch_all:
                        if ResponseContentValidator.is_catch_all_response(body, catch_all.baseline_body_length):
                            logger.debug("SUPPRESSED false positive: %s body matches catch-all baseline size", probe_url)
                            continue

                    # Step 2: Verify the response body actually matches what this file type should contain
                    verify_result = self.verify_response(
                        path_config, body, content_type, body_len, catch_all=catch_all
                    )

                    if not verify_result.confirmed:
                        logger.debug(
                            "SUPPRESSED false positive: %s returned HTTP 200 but body verification failed. Reason: %s",
                            probe_url, verify_result.reason
                        )
                        continue

                    # Step 3: Confirmed — body matches expected content for this file type
                    severity = path_config["severity"].lower()
                    findings.append(Finding(
                        id=f"SENSITIVE-PATH-{path_config['path'].replace('/', '-').strip('-').upper()}",
                        title=f"Sensitive Path Accessible: {path_config['path']}",
                        severity=severity,
                        confidence="high",
                        category="web",
                        target=probe_url,
                        description=(
                            f"The file {path_config['path']} is publicly accessible and returned content "
                            f"consistent with a real {path_config['path'].lstrip('/')} file, not a generic error page."
                        ),
                        evidence=(
                            f"Probed URL: {probe_url}\n"
                            f"HTTP: {status}\n"
                            f"Content-Type: {content_type}\n"
                            f"Body verification: {verify_result.reason}\n"
                            f"Body preview (first 200 chars):\n{body[:200]}"
                        ),
                        recommendation=f"Restrict or remove public access to {path_config['path']}.",
                        verification_method="baseline_differential",
                        cwe="CWE-538",
                    ))

                except Exception as e:
                    logger.debug("Sensitive path probe failed for %s: %s", probe_url, e)
        finally:
            if should_close and client:
                await client.close()

        return findings

    def verify_response(
        self,
        path_config: dict[str, Any],
        body: str,
        content_type: str,
        body_len: int,
        catch_all: Optional[CatchAllResult] = None,
    ) -> VerifyResult:
        verify_type = path_config.get("verify_type")

        # Content-type based verification
        if verify_type == "content_type":
            expected_types = path_config.get("verify_content_type", [])
            min_size = path_config.get("also_check_min_size", 0)
            if min_size and body_len < min_size:
                return VerifyResult(confirmed=False, reason=f"Body size {body_len} < minimum required {min_size}")

            if any(ct.lower() in content_type.lower() for ct in expected_types):
                return VerifyResult(confirmed=True, reason=f"Content-Type matches expected: {content_type}")

            # If content type is text/html, this is almost certainly a catch-all route
            if "text/html" in content_type.lower():
                return VerifyResult(
                    confirmed=False,
                    reason="Content-Type is text/html — likely a catch-all route or error page, not the actual file",
                )
            return VerifyResult(
                confirmed=False,
                reason=f"Content-Type '{content_type}' does not match expected types",
            )

        # Body content verification
        if verify_type == "contains_any":
            patterns = path_config.get("verify_body", [])
            matches = 0
            matching_patterns = []
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    matches += 1
                    matching_patterns.append(pattern)

            # If catch-all was detected, require at least 2 pattern matches if multiple patterns provided,
            # or if only 1 pattern exists require that match
            min_matches = 2 if (catch_all and catch_all.has_catch_all and len(patterns) >= 2) else 1

            if matches >= min_matches:
                # Additional check: if login page check is requested
                if path_config.get("also_check_not_login_page"):
                    if self.check_also_not_login_page(body):
                        return VerifyResult(
                            confirmed=False,
                            reason="Body contains login page indicators — not an exposed admin dashboard",
                        )

                # Additional check: if body contains HTML login page indicators, definitively reject as catch-all false positive
                login_page_indicators = [
                    "<form", "<html", "login", "signin",
                    "username", "password", "DOCTYPE",
                ]
                html_indicators_found = sum(
                    1 for ind in login_page_indicators
                    if ind.lower() in body.lower()
                )
                if html_indicators_found >= 3 and path_config.get("path") not in ("/admin/", "/phpmyadmin/"):
                    return VerifyResult(
                        confirmed=False,
                        reason="Body appears to be an HTML login/error page (catch-all route returning 200) — not an actual sensitive file",
                    )

                return VerifyResult(
                    confirmed=True,
                    reason=f"Body contains expected content pattern(s): {', '.join(repr(p) for p in matching_patterns)}",
                )

            # Additional check: if body contains HTML login page indicators, definitively reject as catch-all false positive
            login_page_indicators = [
                "<form", "<html", "login", "signin",
                "username", "password", "DOCTYPE",
            ]
            html_indicators_found = sum(
                1 for ind in login_page_indicators
                if ind.lower() in body.lower()
            )
            if html_indicators_found >= 3:
                return VerifyResult(
                    confirmed=False,
                    reason="Body appears to be an HTML login/error page (catch-all route returning 200) — not an actual sensitive file",
                )

            return VerifyResult(
                confirmed=False,
                reason="Body does not contain expected content for this file type",
            )

        return VerifyResult(confirmed=False, reason="No verify method")

    def check_also_not_login_page(self, body: str) -> bool:
        """Returns True if body is clearly a login page (i.e. NOT the admin panel we were looking for)."""
        indicators = [
            'type="password"', "type='password'",
            "forgot password", "sign in", "log in",
            "remember me",
        ]
        return sum(1 for i in indicators if i.lower() in body.lower()) >= 2
