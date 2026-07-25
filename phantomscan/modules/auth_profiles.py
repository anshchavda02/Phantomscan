"""Module 1 — Authenticated Scan Profiles.

Store and reuse encrypted authentication state across scans.
Supports cookie, bearer_token, basic, form_login, and oauth auth types.
Credentials are Fernet-encrypted with a passphrase-derived key (PBKDF2).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class AuthType(str, Enum):
    COOKIE = "cookie"
    BEARER_TOKEN = "bearer_token"
    BASIC = "basic"
    FORM_LOGIN = "form_login"
    OAUTH = "oauth"


@dataclass
class AuthProfile:
    """Stored authentication profile."""
    name: str
    role_label: str  # "guest", "user", "admin"
    auth_type: AuthType
    encrypted_credentials: bytes = b""
    session_cookies: dict[str, str] = field(default_factory=dict)
    bearer_token: str = ""
    login_url: str = ""
    login_form_selector: dict[str, str] = field(default_factory=dict)


@dataclass
class AuthSession:
    """Live authenticated session."""
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    role: str = "guest"


@dataclass
class RoleComparisonResult:
    """Result of multi-role access comparison."""
    findings: list[dict[str, Any]] = field(default_factory=list)
    role_access_map: dict[str, list[str]] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Encryption helpers
# ---------------------------------------------------------------------------

def _derive_key(passphrase: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """Derive a Fernet-compatible key from a passphrase using PBKDF2."""
    try:
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
    except ImportError:
        raise RuntimeError(
            "cryptography package is required for auth profiles. "
            "Install with: pip install cryptography"
        )
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480_000)
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
    return key, salt


def encrypt_credentials(data: dict[str, str], passphrase: str) -> tuple[bytes, bytes]:
    """Encrypt credential dict → (ciphertext, salt)."""
    from cryptography.fernet import Fernet
    key, salt = _derive_key(passphrase)
    f = Fernet(key)
    plaintext = json.dumps(data).encode()
    return f.encrypt(plaintext), salt


def decrypt_credentials(ciphertext: bytes, passphrase: str, salt: bytes) -> dict[str, str]:
    """Decrypt credential dict from ciphertext."""
    from cryptography.fernet import Fernet
    key, _ = _derive_key(passphrase, salt)
    f = Fernet(key)
    plaintext = f.decrypt(ciphertext)
    return json.loads(plaintext)


# ---------------------------------------------------------------------------
# Profile persistence
# ---------------------------------------------------------------------------

def save_profile(profile: AuthProfile, passphrase: str, profiles_dir: Path | None = None) -> Path:
    """Save an encrypted auth profile to disk."""
    if profiles_dir is None:
        profiles_dir = Path("profiles")
    profiles_dir.mkdir(parents=True, exist_ok=True)

    safe_name = re.sub(r"[^\w.-]", "_", profile.name)
    path = profiles_dir / f"{safe_name}_{profile.role_label}.enc"

    creds_to_encrypt = {
        "session_cookies": json.dumps(profile.session_cookies),
        "bearer_token": profile.bearer_token,
    }
    ciphertext, salt = encrypt_credentials(creds_to_encrypt, passphrase)

    envelope = {
        "name": profile.name,
        "role_label": profile.role_label,
        "auth_type": profile.auth_type.value,
        "login_url": profile.login_url,
        "login_form_selector": profile.login_form_selector,
        "salt": base64.b64encode(salt).decode(),
        "encrypted_credentials": base64.b64encode(ciphertext).decode(),
    }
    path.write_text(json.dumps(envelope, indent=2))
    logger.info("Saved auth profile to %s", path)
    return path


def load_profile(path: Path, passphrase: str) -> AuthProfile:
    """Load and decrypt an auth profile from disk."""
    envelope = json.loads(path.read_text())
    salt = base64.b64decode(envelope["salt"])
    ciphertext = base64.b64decode(envelope["encrypted_credentials"])
    creds = decrypt_credentials(ciphertext, passphrase, salt)

    return AuthProfile(
        name=envelope["name"],
        role_label=envelope["role_label"],
        auth_type=AuthType(envelope["auth_type"]),
        login_url=envelope.get("login_url", ""),
        login_form_selector=envelope.get("login_form_selector", {}),
        session_cookies=json.loads(creds.get("session_cookies", "{}")),
        bearer_token=creds.get("bearer_token", ""),
    )


# ---------------------------------------------------------------------------
# Authenticated Scanner
# ---------------------------------------------------------------------------

class AuthenticatedScanner:
    """Perform authenticated scans with role-based access comparison."""

    def __init__(self, http: RobustHTTPClient) -> None:
        self.http = http

    async def run(self, **kwargs: Any) -> list[dict[str, Any]]:
        """Module interface — returns findings list."""
        # This module is typically invoked directly via CLI, not the orchestrator
        return []

    async def login(self, profile: AuthProfile, passphrase: str = "") -> AuthSession:
        """Establish an authenticated session from a profile."""
        if profile.auth_type == AuthType.BEARER_TOKEN:
            return AuthSession(
                headers={"Authorization": f"Bearer {profile.bearer_token}"},
                role=profile.role_label,
            )

        if profile.auth_type == AuthType.COOKIE:
            return AuthSession(
                cookies=profile.session_cookies,
                role=profile.role_label,
            )

        if profile.auth_type == AuthType.BASIC:
            creds = profile.session_cookies  # username/password stored here
            import base64 as b64
            token = b64.b64encode(
                f"{creds.get('username', '')}:{creds.get('password', '')}".encode()
            ).decode()
            return AuthSession(
                headers={"Authorization": f"Basic {token}"},
                role=profile.role_label,
            )

        if profile.auth_type == AuthType.FORM_LOGIN:
            # Attempt browser-based login if Playwright available
            try:
                from playwright.async_api import async_playwright
                async with async_playwright() as p:
                    browser = await p.chromium.launch(headless=True)
                    context = await browser.new_context()
                    page = await context.new_page()
                    await page.goto(profile.login_url, timeout=15000)

                    selectors = profile.login_form_selector
                    if "username" in selectors and "password" in selectors:
                        creds = decrypt_credentials(
                            profile.encrypted_credentials, passphrase,
                            b""  # salt handled at load time
                        ) if profile.encrypted_credentials else {}
                        await page.fill(selectors["username"], creds.get("username", ""))
                        await page.fill(selectors["password"], creds.get("password", ""))
                        if "submit" in selectors:
                            await page.click(selectors["submit"])
                        await page.wait_for_load_state("networkidle", timeout=10000)

                    cookies = await context.cookies()
                    await browser.close()
                    return AuthSession(
                        cookies={c["name"]: c["value"] for c in cookies},
                        role=profile.role_label,
                    )
            except ImportError:
                logger.warning("Playwright not available — form_login requires it")
                return AuthSession(role=profile.role_label)

        # Fallback
        return AuthSession(cookies=profile.session_cookies, role=profile.role_label)

    async def crawl_with_auth(
        self, base_url: str, session: AuthSession, max_pages: int = 50
    ) -> list[str]:
        """Crawl a target using an authenticated session and collect accessible URLs."""
        visited: set[str] = set()
        queue = [base_url]
        accessible: list[str] = []

        while queue and len(visited) < max_pages:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)

            try:
                resp = await self.http.request(
                    "GET", url,
                    cookies=session.cookies,
                    extra_headers=session.headers,
                    timeout=10,
                )
                if resp.get("status") in (200, 301, 302):
                    accessible.append(url)
                    # Extract links from response body
                    body = resp.get("body", "")
                    if isinstance(body, bytes):
                        body = body.decode("utf-8", errors="ignore")
                    links = re.findall(r'href=["\']([^"\']+)["\']', body)
                    for link in links:
                        if link.startswith("/"):
                            link = base_url.rstrip("/") + link
                        if link.startswith(base_url) and link not in visited:
                            queue.append(link)
            except Exception as exc:
                logger.debug("Crawl error for %s: %s", url, exc)

        return accessible

    async def multi_role_scan(
        self,
        target: str,
        profiles: list[AuthProfile],
        passphrase: str = "",
    ) -> RoleComparisonResult:
        """Compare access across roles and detect broken authorization."""
        results: dict[str, list[str]] = {}
        sessions: dict[str, AuthSession] = {}

        for profile in profiles:
            session = await self.login(profile, passphrase)
            sessions[profile.role_label] = session
            accessible_urls = await self.crawl_with_auth(target, session)
            results[profile.role_label] = accessible_urls
            logger.info("Role '%s' can access %d URLs", profile.role_label, len(accessible_urls))

        findings: list[dict[str, Any]] = []

        # Compare: what can lower-privilege roles access that should be restricted?
        if "guest" in results and "admin" in results:
            admin_only = set(results["admin"]) - set(results["guest"])
            guest_session = sessions["guest"]

            for admin_url in admin_only:
                try:
                    resp = await self.http.request(
                        "GET", admin_url,
                        cookies=guest_session.cookies,
                        extra_headers=guest_session.headers,
                        timeout=10,
                    )
                    if resp.get("status") == 200:
                        findings.append({
                            "title": "Broken Function Level Authorization",
                            "severity": "critical",
                            "confidence": "high",
                            "category": "authorization",
                            "target": admin_url,
                            "evidence": f"Guest session got HTTP 200 from admin-only endpoint {admin_url}",
                            "recommendation": "Implement server-side role checks on all endpoints",
                            "references": ["CWE-285", "OWASP API5:2023 BFLA"],
                            "module": "auth_profiles",
                        })
                except Exception:
                    pass

        return RoleComparisonResult(findings=findings, role_access_map=results)
