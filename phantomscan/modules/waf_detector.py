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


def is_waf_block_page(body: str, status_code: int = 200) -> bool:
    """Return ``True`` if *body* looks like a WAF/CDN block page.

    Also considers the HTTP status code — WAF blocks typically use
    403, 406, or 429 alongside signature text.
    """
    lower_body = body.lower()
    for sig in _LOWER_SIGNATURES:
        if sig in lower_body:
            return True
    # A 403 with very short body and no useful content is suspicious
    if status_code in (403, 406, 429) and len(body) < 2000:
        # Check for generic block indicators
        if any(kw in lower_body for kw in ("blocked", "denied", "forbidden", "rejected")):
            return True
    return False


def classify_waf_response(
    body: str, status_code: int = 200
) -> Optional[str]:
    """Return the WAF product name if detected, else ``None``."""
    lower = body.lower()
    mapping = {
        "cloudflare": "Cloudflare",
        "incapsula": "Imperva/Incapsula",
        "sucuri": "Sucuri",
        "modsecurity": "ModSecurity",
        "aws waf": "AWS WAF",
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
