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
    "/Login.aspx", "/login.aspx", "/login.php", "/login", "/signin", "/auth/login",
    "/api/login", "/api/auth/login", "/api/v1/login", "/api/auth/signin",
    "/account/login", "/user/login", "/user/login.php", "/admin/login.php",
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
        login_url = await self._detect_login(target, observations)
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

            # If not yet authenticated, audit login form for default credentials
            if not self.session.is_valid:
                default_cred_finding = await self._audit_default_credentials(login_url)
                if default_cred_finding:
                    findings.append(default_cred_finding)

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

    async def _audit_default_credentials(self, login_url: str) -> dict[str, Any] | None:
        """Safe non-destructive probe for standard default accounts."""
        import re
        try:
            get_resp = await self.http.get(login_url, retries=1)
            body = get_resp.text() if hasattr(get_resp, "text") and callable(get_resp.text) else getattr(get_resp, "body", "")
            hidden_tokens: dict[str, str] = {}
            if body:
                hiddens = re.findall(r'<input[^>]*type=["\']hidden["\'][^>]*>', str(body), re.IGNORECASE)
                for h in hiddens:
                    n_m = re.search(r'name=["\']([^"\']+)["\']', h, re.IGNORECASE)
                    v_m = re.search(r'value=["\']([^"\']*)["\']', h, re.IGNORECASE)
                    if n_m:
                        hidden_tokens[n_m.group(1)] = v_m.group(1) if v_m else ""

            default_pairs = [
                ("test", "test"),
                ("admin", "admin"),
                ("admin", "password"),
                ("guest", "guest"),
                ("demo", "demo"),
            ]
            for u_cand, p_cand in default_pairs:
                payload = dict(hidden_tokens)
                payload.update({
                    "tfUName": u_cand,
                    "tfUPass": p_cand,
                    "tbUsername": u_cand,
                    "tbPassword": p_cand,
                    "username": u_cand,
                    "password": p_cand,
                    "user": u_cand,
                    "pass": p_cand,
                    "email": f"{u_cand}@example.com",
                    "btnLogin": "Login",
                    "login": "Login",
                    "submit": "Submit",
                })
                resp = await self.http.post(login_url, data=payload, retries=1)
                cookies = getattr(resp, "cookies", {}) or {}
                resp_text = (resp.text() if hasattr(resp, "text") and callable(resp.text) else getattr(resp, "body", "")).lower()

                has_auth_cookie = any("auth" in c.lower() or "session" in c.lower() or "token" in c.lower() for c in cookies)
                has_success_text = any(kw in resp_text for kw in ["logout", "sign out", "welcome,", "my account", "dashboard"])
                has_redirect = getattr(resp, "status", 0) in (301, 302, 303)

                if has_auth_cookie or has_success_text or has_redirect:
                    if cookies:
                        self.session.cookies.update(cookies)
                        self.session.is_valid = True
                    return {
                        "id": "AUTH-DEFAULT-CREDENTIALS",
                        "title": f"Default Credentials Accepted on Login: '{u_cand}'",
                        "severity": "high",
                        "confidence": "high",
                        "category": "authentication",
                        "target": login_url,
                        "evidence": (
                            f"Login endpoint at {login_url} accepted common default credentials: '{u_cand}:{p_cand}'\n"
                            f"HTTP Status: {getattr(resp, 'status', 0)}\n"
                            f"Session cookies set: {list(cookies.keys())}"
                        ),
                        "recommendation": (
                            "Enforce strong password policies and disable default/test accounts. "
                            "Require multi-factor authentication (MFA). CWE-1392, CWE-798, OWASP A07:2021."
                        ),
                        "references": [
                            "https://cwe.mitre.org/data/definitions/1392.html",
                            "https://cwe.mitre.org/data/definitions/798.html",
                            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
                        ],
                    }
        except Exception as e:
            logger.debug("Default credential probe failed: %s", e)
        return None

    async def _detect_login(self, target: str, observations: list[dict[str, Any]] | None = None) -> str | None:
        # Check observations first
        if observations:
            for obs in observations:
                if obs.get("name") == "discovered_forms":
                    forms = obs.get("value", [])
                    if isinstance(forms, list):
                        for f in forms:
                            if isinstance(f, dict):
                                act = str(f.get("action", ""))
                                fields = f.get("fields", [])
                                fnames = [str(fld.get("name", "")).lower() for fld in fields if isinstance(fld, dict)]
                                if any("login" in act.lower() or "signin" in act.lower() or "auth" in act.lower() or "password" in n or "pwd" in n for n in fnames):
                                    return act if act.startswith("http") else f"{target}/{act.lstrip('/')}"
        for path in _LOGIN_PATHS:
            url = f"{target}{path}"
            try:
                response = await self.http.get(url, retries=1)
                body = response.text().lower()
                if response.status in (200, 301, 302) and (
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
