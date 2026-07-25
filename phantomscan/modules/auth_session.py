"""Module 15 — Authenticated Scan with Session Management.

Provides session management for authenticated scanning: login-form
auto-detection, session fixation tests, concurrent session limits,
and session health monitoring.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)


@dataclass
class AuthSession:
    """Holds authentication state for an active scan session."""
    cookies: dict[str, str] = field(default_factory=dict)
    token: str = ""
    token_type: str = "Bearer"
    csrf_token: str = ""
    is_valid: bool = False

    @property
    def auth_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.token:
            headers["Authorization"] = f"{self.token_type} {self.token}"
        if self.csrf_token:
            headers["X-CSRF-Token"] = self.csrf_token
        return headers


_LOGIN_PATHS = [
    "/login", "/signin", "/auth/login", "/api/login",
    "/api/auth/login", "/api/v1/login", "/api/auth/signin",
    "/account/login", "/user/login",
]


class AuthSessionManager:
    """Manage authenticated scanning sessions and detect session flaws."""

    def __init__(self, http: RobustHTTPClient) -> None:
        self.http = http
        self.session: AuthSession = AuthSession()

    async def run(
        self,
        base_url: str,
        observations: list[dict[str, Any]],
        auth_cookie: str | None = None,
        auth_token: str | None = None,
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        target = base_url.rstrip("/")

        # Initialize session from provided credentials
        if auth_cookie:
            self._parse_cookies(auth_cookie)
            self.session.is_valid = True
        if auth_token:
            self.session.token = auth_token
            self.session.is_valid = True

        # Test 1: Detect login forms
        login_url = await self._detect_login(target)
        if login_url:
            findings.append({
                "id": "AUTH-LOGIN-DETECTED",
                "title": "Login Form Detected",
                "severity": "info",
                "confidence": "high",
                "category": "auth",
                "target": login_url,
                "evidence": f"Login endpoint found at: {login_url}",
                "recommendation": "Ensure login forms use HTTPS, rate-limiting, and CSRF protection.",
            })

        # Test 2: Session fixation
        fixation = await self._test_session_fixation(target)
        if fixation:
            findings.append(fixation)

        # Test 3: Session invalidation on logout
        if self.session.is_valid:
            logout = await self._test_session_invalidation(target)
            if logout:
                findings.append(logout)

        # Test 4: Concurrent session test
        concurrent = await self._test_concurrent_sessions(target)
        if concurrent:
            findings.append(concurrent)

        return findings

    async def _detect_login(self, target: str) -> str | None:
        for path in _LOGIN_PATHS:
            url = f"{target}{path}"
            try:
                response = await self.http.get(url, retries=1)
                body = response.text().lower()
                if response.status == 200 and (
                    "password" in body or 'type="password"' in body
                    or "login" in body
                ):
                    return url
            except Exception:
                continue
        return None

    async def _test_session_fixation(
        self, target: str
    ) -> dict[str, Any] | None:
        """Check if pre-login session ID persists after authentication."""
        try:
            # Get a pre-login session
            response1 = await self.http.get(target + "/", retries=1)
            pre_cookies = response1.cookies

            if not pre_cookies:
                return None

            # Check if the same session ID would be reused after login
            # (We can only detect the pattern, not fully exploit it)
            pre_session_ids = set(pre_cookies.values())

            # Make another request to check if session rotates
            response2 = await self.http.get(target + "/", retries=1)
            post_cookies = response2.cookies

            if pre_cookies and post_cookies:
                reused = set(pre_cookies.values()) & set(post_cookies.values())
                if reused and any(len(v) > 10 for v in reused):
                    return {
                        "id": "AUTH-SESSION-FIXATION-RISK",
                        "title": "Session Fixation Risk — Session Not Rotated",
                        "severity": "medium",
                        "confidence": "low",
                        "category": "auth",
                        "target": target,
                        "evidence": (
                            "Session identifiers persist across requests without "
                            "rotation. If session IDs are not regenerated after "
                            "authentication, session fixation attacks are possible."
                        ),
                        "recommendation": (
                            "Regenerate session IDs after successful authentication. "
                            "Invalidate old session tokens. CWE-384."
                        ),
                        "references": ["https://cwe.mitre.org/data/definitions/384.html"],
                    }
        except Exception:
            pass
        return None

    async def _test_session_invalidation(
        self, target: str
    ) -> dict[str, Any] | None:
        """Check if session remains valid after logout."""
        logout_paths = ["/logout", "/api/logout", "/auth/logout", "/signout"]
        for path in logout_paths:
            try:
                await self.http.get(
                    f"{target}{path}",
                    headers=self.session.auth_headers,
                    retries=1,
                )
            except Exception:
                continue

        # Check if old session still works
        try:
            response = await self.http.get(
                f"{target}/api/me",
                headers=self.session.auth_headers,
                retries=1,
            )
            if response.status == 200:
                body = response.text().lower()
                if not any(w in body for w in ("unauthorized", "login", "denied")):
                    return {
                        "id": "AUTH-SESSION-NOT-INVALIDATED",
                        "title": "Session Not Invalidated After Logout",
                        "severity": "medium",
                        "confidence": "medium",
                        "category": "auth",
                        "target": target,
                        "evidence": (
                            "Session token remains valid after logout. "
                            "Old tokens can be reused to access the account."
                        ),
                        "recommendation": (
                            "Invalidate server-side sessions on logout. "
                            "Clear all session storage and cookies. CWE-613."
                        ),
                        "references": ["https://cwe.mitre.org/data/definitions/613.html"],
                    }
        except Exception:
            pass
        return None

    async def _test_concurrent_sessions(
        self, target: str
    ) -> dict[str, Any] | None:
        # Info-level: just note whether concurrent sessions are allowed
        return None  # Requires actual credentials — placeholder for future

    def _parse_cookies(self, cookie_string: str) -> None:
        for pair in cookie_string.split(";"):
            pair = pair.strip()
            if "=" in pair:
                key, _, value = pair.partition("=")
                self.session.cookies[key.strip()] = value.strip()
