"""WAF block-page detection.

Identifies HTTP responses that are WAF/CDN rejection pages rather than
genuine application errors.  A response matching a WAF block signature
must be excluded from SQL injection (and other injection) confirmation
entirely — a blocked request means the payload did NOT reach the
database.
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)


# Signatures that strongly indicate the response is a WAF/CDN block page
# rather than an application-generated error.
BLOCK_PAGE_SIGNATURES: list[str] = [
    "Request blocked",
    "Access Denied",
    "Attention Required! | Cloudflare",
    "The requested URL was rejected",
    "ModSecurity Action",
    "Incapsula incident ID",
    "Sucuri WebSite Firewall",
    "has been blocked in accordance",
    "Your request has been blocked",
    "AWS WAF",
    "awswaf",
    "token.awswaf.com",
    "awswafcookiedomainlist",
    "awswafintegration",
    "verify that you're not a robot",
    "we need to verify that you're not a robot",
    "blocked by security policy",
    "Web Application Firewall",
    "This request was blocked by the security rules",
    "The resource you are looking for has been removed",
    "Sorry, you have been blocked",
    "Please verify you are a human",
    "DDoS protection by",
    "Forbidden - Fortinet",
    "URL Filtered",
    "SonicWall",
    "Barracuda WAF",
    "F5 BIG-IP",
    "Imperva",
    "Akamai Ghost",
]

# Pre-lowercase for fast matching
_LOWER_SIGNATURES: list[str] = [s.lower() for s in BLOCK_PAGE_SIGNATURES]


def is_waf_block_page(
    body: str,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> bool:
    """Return ``True`` if *body* or *headers* look like a WAF/CDN block or challenge page.

    Considers HTTP status codes (403, 405, 406, 429, and 202 for bot challenges)
    as well as vendor-specific response headers.
    """
    if headers:
        lowered_headers = {str(k).lower(): str(v).lower() for k, v in headers.items()}
        if "x-amzn-waf-action" in lowered_headers:
            return True
        if lowered_headers.get("cf-mitigated") == "challenge":
            return True

    lower_body = body.lower()
    for sig in _LOWER_SIGNATURES:
        if sig in lower_body:
            return True

    # 202 Accepted (AWS WAF challenge) or 403/405/406/429 with generic indicators
    if status_code in (202, 403, 405, 406, 429) and len(body) < 10000:
        if any(kw in lower_body for kw in ("blocked", "denied", "forbidden", "rejected", "challenge", "robot", "captcha")):
            return True

    return False


def classify_waf_response(
    body: str,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> Optional[str]:
    """Return the WAF product name if detected, else ``None``."""
    if headers:
        lowered_headers = {str(k).lower(): str(v).lower() for k, v in headers.items()}
        if "x-amzn-waf-action" in lowered_headers:
            return "AWS WAF"
        if lowered_headers.get("cf-mitigated") == "challenge":
            return "Cloudflare"

    lower = body.lower()
    mapping = {
        "cloudflare": "Cloudflare",
        "incapsula": "Imperva/Incapsula",
        "sucuri": "Sucuri",
        "modsecurity": "ModSecurity",
        "aws waf": "AWS WAF",
        "awswaf": "AWS WAF",
        "barracuda": "Barracuda",
        "f5 big-ip": "F5 BIG-IP",
        "fortinet": "Fortinet",
        "sonicwall": "SonicWall",
        "akamai": "Akamai",
        "imperva": "Imperva",
    }
    for keyword, name in mapping.items():
        if keyword in lower:
            return name
    return None


is_waf_blocked = is_waf_block_page

