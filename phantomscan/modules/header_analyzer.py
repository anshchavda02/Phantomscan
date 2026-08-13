"""Case-insensitive HTTP header analysis utility.

Per RFC 7230, HTTP header field names are case-insensitive.  This module
provides :class:`HeaderAnalyzer` which normalises all header keys to
lowercase at the single point of entry, so every downstream check uses
a consistent view.

Every module that inspects HTTP headers must use this utility rather than
performing direct ``dict.get()`` / ``in`` checks on raw header dicts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class CSPResult:
    """Result of Content-Security-Policy detection."""

    present: bool
    source: str = ""        # "http_header" | "meta_tag" | ""
    policy: str = ""
    frame_ancestors: str = ""
    note: str = ""


@dataclass
class HeaderCheckResult:
    """Result of a single header protection check."""

    protected: bool
    mechanism: str = ""
    note: str = ""


class HeaderAnalyzer:
    """Case-insensitive header access and security analysis.

    Normalises ALL header keys to lowercase at construction time.
    """

    def __init__(self, raw_headers: dict[str, Any]) -> None:
        self.headers: dict[str, str] = {
            k.lower(): str(v) for k, v in raw_headers.items()
        }

    def has_header(self, name: str) -> bool:
        """Check if a header is present (case-insensitive)."""
        return name.lower() in self.headers

    def get_header(self, name: str) -> Optional[str]:
        """Get a header value (case-insensitive), or ``None``."""
        return self.headers.get(name.lower())


# ── CSP Detection (header + meta tag) ─────────────────────────────────────────

_META_CSP_RE = re.compile(
    r'<meta[^>]+http-equiv=["\']Content-Security-Policy["\']'
    r'[^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# Also handle reversed attribute order: content before http-equiv
_META_CSP_RE_ALT = re.compile(
    r'<meta[^>]+content=["\']([^"\']+)["\']'
    r'[^>]+http-equiv=["\']Content-Security-Policy["\']',
    re.IGNORECASE,
)


def detect_csp(headers: dict[str, Any], html_body: str = "") -> CSPResult:
    """Detect Content-Security-Policy from HTTP headers or HTML meta tag.

    Args:
        headers: Raw HTTP response headers (any casing).
        html_body: The HTML response body to scan for ``<meta>`` CSP.

    Returns:
        :class:`CSPResult` with detection details.
    """
    analyzer = HeaderAnalyzer(headers)

    # Source 1: HTTP header (preferred, higher trust)
    header_csp = analyzer.get_header("content-security-policy")
    if header_csp:
        return CSPResult(
            present=True,
            source="http_header",
            policy=header_csp,
            frame_ancestors=_extract_directive(header_csp, "frame-ancestors"),
        )

    # Source 2: <meta> tag (valid alternative per spec)
    if html_body:
        for pattern in (_META_CSP_RE, _META_CSP_RE_ALT):
            meta_match = pattern.search(html_body)
            if meta_match:
                policy = meta_match.group(1)
                return CSPResult(
                    present=True,
                    source="meta_tag",
                    policy=policy,
                    frame_ancestors=_extract_directive(policy, "frame-ancestors"),
                    note=(
                        "CSP delivered via meta tag rather than HTTP header. "
                        "Note: meta-tag CSP cannot enforce frame-ancestors or "
                        "report-uri directives per spec."
                    ),
                )

    return CSPResult(present=False)


def check_frame_protection(
    headers: dict[str, Any], csp_result: CSPResult
) -> HeaderCheckResult:
    """Check clickjacking protection via X-Frame-Options OR CSP frame-ancestors.

    Only reports a gap if NEITHER mechanism is present.
    """
    analyzer = HeaderAnalyzer(headers)
    has_xfo = analyzer.has_header("x-frame-options")
    has_frame_ancestors = bool(csp_result.frame_ancestors)

    if has_xfo or has_frame_ancestors:
        mechanism = (
            "CSP frame-ancestors" if has_frame_ancestors else "X-Frame-Options"
        )
        return HeaderCheckResult(
            protected=True,
            mechanism=mechanism,
            note=(
                f"Clickjacking protection present via {mechanism}"
                + (
                    " (modern standard, takes precedence in supporting browsers)"
                    if has_frame_ancestors
                    else ""
                )
            ),
        )

    return HeaderCheckResult(
        protected=False,
        note=(
            "Neither X-Frame-Options nor CSP frame-ancestors present — "
            "page can be framed by any origin"
        ),
    )


def _extract_directive(policy: str, directive: str) -> str:
    """Extract a specific directive value from a CSP policy string."""
    for part in policy.split(";"):
        part = part.strip()
        if part.lower().startswith(directive.lower()):
            return part
    return ""
