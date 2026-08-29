"""Module 7 — Login Anti-Automation Tester.

Tests login endpoints for brute-force protection mechanisms:
CAPTCHA presence, rate limiting, and account lockout detection.
Uses obviously invalid credentials — never attempts real credential stuffing.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)

_CAPTCHA_MARKERS = [
    "recaptcha", "hcaptcha", "turnstile", "g-recaptcha",
    "captcha", "cf-turnstile", "h-captcha",
]


class AntiAutomationTester:
    """Test login endpoints for brute-force protection."""

    def __init__(self, http: RobustHTTPClient) -> None:
        self.http = http

    async def run(self, **kwargs: Any) -> list[dict[str, Any]]:
        """Module interface — find login pages from observations and test them."""
        observations = kwargs.get("observations", [])
        base_url = kwargs.get("base_url", "")

        # Try to find login URLs from crawled pages
        login_urls: list[str] = []
        for obs in observations:
            if obs.get("name") in ("crawled_urls", "interesting_urls"):
                urls = obs.get("value", [])
                if isinstance(urls, list):
                    for url in urls:
                        url_str = url if isinstance(url, str) else str(url)
                        if any(kw in url_str.lower() for kw in [
                            "/login", "/signin", "/auth", "/account/login",
                            "/user/login", "/wp-login", "/admin/login",
                        ]):
                            login_urls.append(url_str)

        # Also check common login paths concurrently if none found
        if not login_urls and base_url:
            async def probe_login_path(path: str) -> str | None:
                url = f"{base_url.rstrip('/')}{path}"
                try:
                    resp = await self.http.get(url, retries=1)
                    if getattr(resp, "status", 0) in (200, 301, 302):
                        return url
                except Exception:
                    pass
                return None

            common_paths = ["/login", "/signin", "/auth/login", "/wp-login.php", "/admin", "/rest/user/login"]
            probe_results = await asyncio.gather(*(probe_login_path(p) for p in common_paths), return_exceptions=True)
            for r in probe_results:
                if isinstance(r, str) and r:
                    login_urls.append(r)

        findings: list[dict[str, Any]] = []
        test_results = await asyncio.gather(*(self.test(u) for u in login_urls[:3]), return_exceptions=True)
        for r in test_results:
            if isinstance(r, list):
                findings.extend(r)

        return findings

    async def test(self, login_url: str) -> list[dict[str, Any]]:
        """Test a specific login URL for anti-automation protections."""
        findings: list[dict[str, Any]] = []

        # Test 1: CAPTCHA presence check
        has_captcha = False
        try:
            resp = await self.http.get(login_url, retries=1)
            body = resp.text() if hasattr(resp, "text") and callable(resp.text) else getattr(resp, "body", "")
            if isinstance(body, bytes):
                body = body.decode("utf-8", errors="ignore")
            body_lower = str(body).lower()

            has_captcha = any(marker in body_lower for marker in _CAPTCHA_MARKERS)
        except Exception as exc:
            logger.debug("Failed to fetch login page %s: %s", login_url, exc)
            return findings

        # Test 2: Rapid login attempts with obviously invalid credentials
        # (safe — never attempts real credential stuffing)
        attempt_results: list[dict[str, Any]] = []
        for i in range(5):
            try:
                t1 = time.monotonic()
                resp = await self.http.post(
                    login_url,
                    json={
                        "username": f"phantomscan_test_{i}",
                        "password": "invalid_test_only",
                        "email": f"phantomscan_test_{i}@invalid.test",
                    },
                    retries=1,
                )
                elapsed = time.monotonic() - t1
                attempt_results.append({
                    "attempt": i + 1,
                    "status": getattr(resp, "status", 0),
                    "time": round(elapsed, 3),
                })
            except Exception:
                attempt_results.append({
                    "attempt": i + 1,
                    "status": 0,
                    "time": 0,
                })
            await asyncio.sleep(0.5)

        # Analyze: are all attempts identical? (no throttling/lockout)
        statuses = [r["status"] for r in attempt_results if r["status"] > 0]
        times = [r["time"] for r in attempt_results if r["time"] > 0]

        if len(set(statuses)) <= 1 and not has_captcha and len(statuses) >= 4:
            # Check for progressive delay (rate limiting via timing)
            has_progressive_delay = False
            if len(times) >= 3:
                avg_first = sum(times[:2]) / 2
                avg_last = sum(times[-2:]) / 2
                if avg_last > avg_first * 2:
                    has_progressive_delay = True

            if not has_progressive_delay:
                findings.append({
                    "id": "AUTH-NO-BRUTE-FORCE-PROTECTION",
                    "title": "No Brute Force Protection Detected",
                    "severity": "medium",
                    "confidence": "medium",
                    "category": "authentication",
                    "target": login_url,
                    "evidence": (
                        f"5 rapid login attempts, all returned status {statuses[0] if statuses else 'N/A'}\n"
                        f"No CAPTCHA detected in login page\n"
                        f"No progressive delay observed\n"
                        f"Response times: {[r['time'] for r in attempt_results]}"
                    ),
                    "recommendation": (
                        "Implement rate limiting, CAPTCHA after failed attempts, "
                        "or progressive account lockout. Consider using "
                        "OWASP recommendations for credential stuffing prevention."
                    ),
                    "references": ["CWE-307"],
                    "module": "anti_automation",
                })

        # Test 3: Report CAPTCHA presence (informational)
        if has_captcha:
            findings.append({
                "id": "AUTH-CAPTCHA-PRESENT",
                "title": "CAPTCHA Present on Login (Informational)",
                "severity": "info",
                "confidence": "high",
                "category": "authentication",
                "target": login_url,
                "evidence": "CAPTCHA marker found in login page HTML",
                "recommendation": (
                    "Verify CAPTCHA cannot be bypassed via direct API calls "
                    "that skip the CAPTCHA widget."
                ),
                "references": ["CWE-799"],
                "module": "anti_automation",
            })

        return findings
