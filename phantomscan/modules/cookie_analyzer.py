"""Cookie Analyzer module for PhantomScan.

Inspects Set-Cookie headers, filters out tracking cookies and expired cookies,
recognizes __Secure- and __Host- prefixes, and groups missing flags into at most
two findings (Cookies Missing Secure Flag, Cookies Missing HttpOnly Flag).
"""

from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

from phantomscan.models import Finding


class CookieAnalyzer:
    """Accurate, non-noisy cookie security attribute analyzer."""

    def __init__(self, http: Any = None) -> None:
        self.http = http

    TRACKING_COOKIES = frozenset([
        "_ga", "_gid", "_fbp", "_fbc", "_hjid",
        "_hjfirstseen", "__utma", "__utmb", "__utmc",
        "__utmz", "__utmv", "nid", "ide", "_gcl_au",
        "fr", "datr", "c_user", "xs", "wd",
        "__secure-3papisid", "__secure-3psidcc",
        "1p_jar", "consent", "aec", "socs", "anid", "otz", "dv",
        "search_samesite", "__secure-strp", "__secure-enid", "__secure-3psidts",
    ])

    def analyze(self, set_cookie_headers: list[str], url: str = "") -> list[Finding]:
        """Analyze raw Set-Cookie header strings and return grouped findings."""
        findings: list[Finding] = []
        grouped_secure: list[str] = []
        grouped_httponly: list[str] = []

        for cookie_str in set_cookie_headers:
            parsed = self._parse_set_cookie(cookie_str)
            name = parsed.get("name", "")
            if not name:
                continue

            lower_name = name.lower()

            # Skip tracking cookies
            if lower_name in self.TRACKING_COOKIES:
                continue
            if any(lower_name.startswith(t) for t in ("_ga", "_gid", "_gtm", "__utm", "_gcl")):
                continue

            # Skip expired cookies
            expires = parsed.get("expires")
            if expires and self._is_expired(expires):
                continue

            # __Secure- and __Host- prefix implies Secure flag
            has_secure = (
                parsed.get("secure", False)
                or name.startswith("__Secure-")
                or name.startswith("__Host-")
            )
            has_httponly = parsed.get("httponly", False)

            if not has_secure:
                if name not in grouped_secure:
                    grouped_secure.append(name)
            if not has_httponly:
                if name not in grouped_httponly:
                    grouped_httponly.append(name)

        # Group into maximum 2 findings
        if grouped_secure:
            evidence_str = f"Cookies without Secure flag:\n{', '.join(grouped_secure[:10])}"
            if len(grouped_secure) > 10:
                evidence_str += "..."
            findings.append(Finding(
                id="COOKIES-MISSING-SECURE-FLAG",
                title="Cookies Missing Secure Flag",
                severity="medium",
                confidence="high",
                verification_method="passive_observation",
                category="web",
                target=url,
                evidence=evidence_str,
                recommendation="Add Secure attribute to all non-tracking cookies transmitted over HTTPS.",
                cwe="CWE-614",
            ))

        if grouped_httponly:
            evidence_str = f"Cookies without HttpOnly:\n{', '.join(grouped_httponly[:10])}"
            if len(grouped_httponly) > 10:
                evidence_str += "..."
            findings.append(Finding(
                id="COOKIES-MISSING-HTTPONLY-FLAG",
                title="Cookies Missing HttpOnly Flag",
                severity="low",
                confidence="high",
                verification_method="passive_observation",
                category="web",
                target=url,
                evidence=evidence_str,
                recommendation="Add HttpOnly attribute to prevent client-side script access.",
                cwe="CWE-1004",
            ))

        return findings

    def _parse_set_cookie(self, cookie_str: str) -> dict[str, Any]:
        parts = [p.strip() for p in cookie_str.split(";")]
        result: dict[str, Any] = {"secure": False, "httponly": False}
        if not parts:
            return result

        name_val = parts[0].split("=", 1)
        result["name"] = name_val[0].strip()
        result["value"] = name_val[1].strip() if len(name_val) > 1 else ""

        for part in parts[1:]:
            lower = part.lower()
            if lower == "secure":
                result["secure"] = True
            elif lower == "httponly":
                result["httponly"] = True
            elif lower.startswith("samesite="):
                result["samesite"] = part.split("=", 1)[1].strip() if "=" in part else ""
            elif lower.startswith("expires="):
                result["expires"] = part.split("=", 1)[1].strip() if "=" in part else ""
        return result

    def _is_expired(self, expires_str: str) -> bool:
        try:
            exp = parsedate_to_datetime(expires_str)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            return exp < datetime.now(timezone.utc)
        except Exception:
            return False

    async def run(
        self,
        base_url: str,
        observations: list[dict[str, Any]],
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        """DAG pipeline execution method for Cookie analysis."""
        cookie_headers: list[str] = []

        # 1. Gather Set-Cookie headers from observations
        for obs in observations:
            name = obs.get("name", "")
            val = obs.get("value")
            if name in ("set_cookie", "set_cookies") and isinstance(val, list):
                cookie_headers.extend(str(c) for c in val)
            elif name in ("headers", "http_headers", "response_headers") and isinstance(val, dict):
                for k, v in val.items():
                    if k.lower() == "set-cookie":
                        if isinstance(v, list):
                            cookie_headers.extend(str(item) for item in v)
                        else:
                            cookie_headers.append(str(v))

        # 2. If none found and http client is available, fetch headers directly
        if not cookie_headers and self.http:
            try:
                res = await self.http.get(base_url)
                if res and hasattr(res, "headers"):
                    hdrs = getattr(res, "headers", {})
                    for k, v in hdrs.items():
                        if k.lower() == "set-cookie":
                            if isinstance(v, list):
                                cookie_headers.extend(str(item) for item in v)
                            else:
                                cookie_headers.append(str(v))
            except Exception:
                pass

        findings = self.analyze(cookie_headers, url=base_url)
        return [f.to_dict() if hasattr(f, "to_dict") else f for f in findings]

