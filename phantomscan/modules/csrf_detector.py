"""Anti-CSRF Token Scanner.

Audits discovered HTML forms and session-modifying endpoints for missing
cryptographic anti-CSRF protection tokens.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)

# Known CSRF token field names
_CSRF_FIELD_PATTERNS = [
    r"csrf",
    r"xsrf",
    r"token",
    r"authenticity_token",
    r"__requestverificationtoken",
    r"anti_forgery",
    r"nonce",
    r"_token",
    r"form_token",
]

# Sensitive / State-changing action keywords
_STATE_CHANGING_KEYWORDS = [
    "login", "signin", "auth", "register", "signup", "user", "profile",
    "password", "pass", "email", "account", "guestbook", "comment", "post",
    "feedback", "cart", "checkout", "buy", "order", "update", "delete",
    "edit", "save", "admin", "setting", "transfer", "submit", "change",
]


class CSRFDetector:
    """Detect missing Anti-CSRF tokens on state-changing HTML forms."""

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
        discovered_forms: list[dict[str, Any]] = []

        for obs in observations:
            if obs.get("name") == "discovered_forms":
                val = obs.get("value", [])
                if isinstance(val, list):
                    for f in val:
                        if isinstance(f, dict):
                            discovered_forms.append(f)

        tested_actions: set[str] = set()

        for form in discovered_forms:
            action = form.get("action", target)
            method = form.get("method", "GET").upper()
            fields = form.get("fields", [])

            # Safe HTTP methods (GET, HEAD, OPTIONS) do not alter server-side state
            # per RFC 7231 / RFC 9110. CSRF protection applies exclusively to state-modifying
            # methods (POST, PUT, DELETE, PATCH). Transmitting anti-CSRF tokens in GET queries
            # is itself a security anti-pattern (CWE-598: token leakage via logs and Referer).
            if method not in ("POST", "PUT", "DELETE", "PATCH"):
                continue

            parsed = urlparse(action)
            action_path = parsed.path.lower()

            # Ignore pure search queries (non-state-changing query interfaces)
            _SEARCH_FIELD_PATTERNS = [
                r"^(q|k|s|query|search|keywords?|search_?terms?|field[-_]?keywords?|find)$",
            ]
            field_names_preview = [
                fld.get("name", "") if isinstance(fld, dict) else getattr(fld, "name", "")
                for fld in fields
            ]
            field_names_clean = [f for f in field_names_preview if f]
            if field_names_clean and all(
                any(re.search(pat, f.lower()) for pat in _SEARCH_FIELD_PATTERNS)
                for f in field_names_clean
            ):
                continue

            # Filter out purely non-actionable telemetry / tracking tokens
            _TRACKING_FIELDS = {"ue_back", "_ga", "_gid", "timestamp", "ts"}
            actionable_fields = [f for f in field_names_clean if f.lower() not in _TRACKING_FIELDS]
            if not actionable_fields:
                continue

            if action in tested_actions:
                continue
            tested_actions.add(action)

            # Check if any field matches anti-CSRF token patterns
            has_csrf_token = False
            field_names = []

            for fld in fields:
                fname = fld.get("name", "") if isinstance(fld, dict) else getattr(fld, "name", "")
                if fname:
                    field_names.append(fname)
                    fname_lower = fname.lower()
                    if any(re.search(pat, fname_lower) for pat in _CSRF_FIELD_PATTERNS):
                        has_csrf_token = True
                        break

            if not has_csrf_token and actionable_fields:
                findings.append({
                    "id": "CSRF-TOKEN-MISSING",
                    "title": f"Absence of Anti-CSRF Tokens: Form at '{action}'",
                    "severity": "medium",
                    "confidence": "high",
                    "category": "csrf",
                    "target": action,
                    "verification_method": "passive_observation",
                    "evidence": (
                        f"Form Action: {action}\n"
                        f"HTTP Method: {method}\n"
                        f"Form Fields: {', '.join(field_names)}\n"
                        f"No unique cryptographic CSRF token found in form inputs. "
                        f"Actions on this form can be forged by third-party origins."
                    ),
                    "recommendation": (
                        "Implement unique, unpredictable anti-CSRF tokens for all "
                        "state-changing requests (Synchronizer Token Pattern or Double Submit Cookie). "
                        "Set SameSite=Lax or Strict on session cookies. CWE-352, OWASP A01:2021."
                    ),
                    "references": [
                        "https://cwe.mitre.org/data/definitions/352.html",
                        "https://owasp.org/www-community/attacks/csrf",
                    ],
                })

        return findings
