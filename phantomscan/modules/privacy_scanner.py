"""Module 8 — PII / Privacy Exposure Scanner.

Scans HTTP responses for personally identifiable information (PII) exposure.
Detects emails, SSNs, credit cards, phone numbers, IP addresses, AWS keys, IBANs.
Outputs masked evidence only — never exposes real PII.

False-positive hardening:
 - HTML tags are stripped before scanning to prevent matching asset filenames,
   data attributes, CSS class names, and JavaScript source code.
 - Email: rejects image filenames (e.g., image@2x.jpg), noreply/system addresses.
 - Credit card: enforces BIN prefix validation + rejects timestamps/product IDs.
 - Phone: requires at least one separator to distinguish from bare numeric IDs.
 - IP: extended version-number and infrastructure-IP filtering.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# HTML tag stripping — removes markup so PII regex only scans visible text
# and JSON/API response bodies, not src=, href=, data-* attributes.
# ---------------------------------------------------------------------------

_HTML_TAG_RE = re.compile(r"<[^>]+>", re.DOTALL)
_SCRIPT_STYLE_RE = re.compile(
    r"<(?:script|style|noscript|svg|link)[^>]*>.*?</(?:script|style|noscript|svg|link)>",
    re.DOTALL | re.IGNORECASE,
)


def _strip_html(body: str) -> str:
    """Strip HTML tags, <script>/<style> blocks, and CSS/JS to yield text-only content."""
    # Remove entire script/style/svg/noscript blocks first
    text = _SCRIPT_STYLE_RE.sub(" ", body)
    # Remove remaining HTML tags
    text = _HTML_TAG_RE.sub(" ", text)
    return text


# ---------------------------------------------------------------------------
# PII detection patterns
# ---------------------------------------------------------------------------

PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    ),
    "us_ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    # Credit card: must start with a valid card-network prefix digit
    # Visa=4, MC=5(1-5)/2(221-720), Amex=3(4/7), Discover=6, JCB=35, Diners=3(0/6/8)
    "credit_card": re.compile(r"\b[3-6](?:\d[ -]*?){12,15}\b"),
    # Phone: require at least ONE separator (dash, dot, space, or parentheses)
    # to distinguish from bare 10-digit numbers in product IDs / timestamps.
    # Note: Uses lookbehind/lookahead instead of \b because ( is not a word char.
    "phone_us": re.compile(
        r"(?<!\w)(?:"
        r"\(\d{3}\)\s?[-.]?\d{3}[-.\s]?\d{4}"  # (xxx) xxx-xxxx or (xxx)xxx-xxxx
        r"|"
        r"\d{3}[-.\s]\d{3}[-.\s]?\d{4}"  # xxx-xxx-xxxx or xxx.xxx.xxxx
        r"|"
        r"\d{3}[-.\s]?\d{3}[-.\s]\d{4}"  # xxx xxx-xxxx or xxxxxxx-xxxx
        r")(?!\d)"
    ),
    "ip_address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "iban": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b"),
}

_FAKE_EMAIL_DOMAINS = {
    "example.com", "test.com", "domain.com", "localhost",
    "example.org", "example.net", "invalid.test",
}

# Image / asset file extensions that trigger email FPs when used with @ in
# responsive image filenames (e.g., icon@2x.png, logo@3x.webp).
_ASSET_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".avif", ".ico",
    ".bmp", ".tiff", ".tif", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".css", ".js", ".map", ".json",
}

# Valid credit card BIN first-digit to network mapping (for prefix validation)
_VALID_CARD_PREFIXES = {
    "3": {"4", "7", "0", "6", "8", "5"},  # Amex(34,37), JCB(35), Diners(30,36,38)
    "4": set(),                             # Visa: any 4xxxx
    "5": {"0", "1", "2", "3", "4", "5"},   # MC: 51-55, some Maestro: 50
    "6": {"0", "2", "5"},                   # Discover: 6011, 65; UnionPay: 62
}

# Standard ISO 3166-1 alpha-2 country codes registered for IBAN with exact length requirements
_IBAN_COUNTRY_LENGTHS = {
    "AL": 28, "AD": 24, "AT": 20, "AZ": 28, "BH": 22, "BY": 28, "BE": 16, "BA": 20,
    "BR": 29, "BG": 22, "CR": 22, "HR": 21, "CY": 28, "CZ": 24, "DK": 18, "DO": 28,
    "EE": 20, "EG": 29, "SV": 28, "FO": 18, "FI": 18, "FR": 27, "GE": 22, "DE": 22,
    "GI": 23, "GR": 27, "GL": 18, "GT": 28, "HU": 28, "IS": 26, "IQ": 23, "IE": 22,
    "IL": 23, "IT": 27, "JO": 30, "KZ": 20, "XK": 20, "KW": 30, "LV": 21, "LB": 28,
    "LI": 21, "LT": 20, "LU": 20, "MK": 19, "MT": 31, "MR": 27, "MU": 30, "MD": 24,
    "MC": 27, "ME": 22, "NL": 18, "NO": 15, "OM": 23, "PK": 24, "PS": 29, "PL": 28,
    "PT": 25, "QA": 29, "RO": 24, "LC": 32, "SM": 27, "ST": 25, "SA": 24, "RS": 22,
    "SC": 31, "SK": 24, "SI": 19, "ES": 24, "SD": 18, "SE": 24, "CH": 21, "TN": 24,
    "TR": 26, "UA": 29, "AE": 23, "GB": 22, "VA": 22, "VG": 24,
}

_HIGH_RISK_TYPES = {"us_ssn", "credit_card", "iban", "aws_key"}


class PrivacyScanner:
    """Scan responses for PII and privacy exposure."""

    def __init__(self, http: RobustHTTPClient) -> None:
        self.http = http

    async def run(self, **kwargs: Any) -> list[dict[str, Any]]:
        """Module interface — scan crawled URLs for PII in responses."""
        observations = kwargs.get("observations", [])
        base_url = kwargs.get("base_url", "")

        # Collect URLs to scan from observations
        urls_to_check: list[str] = []
        for obs in observations:
            if obs.get("name") in ("crawled_urls", "interesting_urls", "api_endpoints", "discovered_urls", "discovered_api_routes"):
                val = obs.get("value", [])
                if isinstance(val, list):
                    for item in val:
                        if isinstance(item, str):
                            urls_to_check.append(item if item.startswith("http") else f"{base_url.rstrip('/')}{item if item.startswith('/') else '/' + item}")
                        elif isinstance(item, dict):
                            u = item.get("url", "")
                            if u:
                                urls_to_check.append(u if u.startswith("http") else f"{base_url.rstrip('/')}{u if u.startswith('/') else '/' + u}")

        # Also check the base URL itself
        if base_url and base_url not in urls_to_check:
            urls_to_check.insert(0, base_url)

        import asyncio
        findings: list[dict[str, Any]] = []
        checked = set()
        unique_urls = []
        for url in urls_to_check[:30]:
            if url and url not in checked:
                checked.add(url)
                unique_urls.append(url)

        sem = asyncio.Semaphore(15)

        async def check_url(url: str) -> list[dict[str, Any]]:
            async with sem:
                try:
                    resp = await self.http.get(url, retries=1)
                    body = resp.text() if hasattr(resp, "text") and callable(resp.text) else getattr(resp, "body", "")
                    if isinstance(body, bytes):
                        body = body.decode("utf-8", errors="ignore")
                    return await self.scan_response(url, str(body))
                except Exception as exc:
                    logger.debug("Privacy scan error for %s: %s", url, exc)
                    return []

        results = await asyncio.gather(*(check_url(u) for u in unique_urls), return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)

        return findings

    async def scan_response(
        self, url: str, body: str
    ) -> list[dict[str, Any]]:
        """Scan a single response body for PII patterns."""
        findings: list[dict[str, Any]] = []

        # Strip HTML tags so regex doesn't match image filenames, CSS class names,
        # data attributes, or JavaScript source code.  This dramatically reduces
        # false positives on content-rich pages.
        clean_body = _strip_html(body)

        for pii_type, pattern in PII_PATTERNS.items():
            matches = pattern.findall(clean_body)
            # Filter false positives
            matches = [
                m for m in matches
                if not self._is_false_positive(m, pii_type)
            ]

            if matches:
                severity = "high" if pii_type in _HIGH_RISK_TYPES else "medium"
                findings.append({
                    "id": f"PII-EXPOSURE-{pii_type.upper().replace('_', '-')}",
                    "title": f"PII Exposure: {pii_type.replace('_', ' ').title()} Found",
                    "severity": severity,
                    "confidence": "medium",
                    "category": "privacy",
                    "target": url,
                    "evidence": (
                        f"URL: {url}\n"
                        f"Pattern: {pii_type}\n"
                        f"Sample (masked): {self._mask(matches[0])}\n"
                        f"Total found: {len(matches)}"
                    ),
                    "recommendation": (
                        "Review the endpoint to ensure PII is not unintentionally "
                        "exposed. Implement data masking, access controls, and ensure "
                        "GDPR/CCPA compliance for personal data handling."
                    ),
                    "references": ["CWE-359"],
                    "module": "privacy_scanner",
                    "gdpr_relevant": True,
                })

        return findings

    @staticmethod
    def _mask(value: str) -> str:
        """Mask a PII value for safe display."""
        value = value.strip()
        if len(value) <= 4:
            return "*" * len(value)
        return value[:2] + "*" * (len(value) - 4) + value[-2:]

    @staticmethod
    def _is_false_positive(match: str, pii_type: str) -> bool:
        """Filter out common false positives."""
        if pii_type == "email":
            lower = match.lower()
            # Fake/test domains
            if any(d in lower for d in _FAKE_EMAIL_DOMAINS):
                return True
            # Asset filenames with @ (e.g., image@2x.jpg, icon@3x.png)
            if re.search(r"@\d+x\.\w+$", lower):
                return True
            # Matches ending with image/asset file extensions
            if any(lower.endswith(ext) for ext in _ASSET_EXTENSIONS):
                return True
            # System / no-reply addresses (not user PII)
            local_part = lower.split("@")[0] if "@" in lower else ""
            if local_part in ("noreply", "no-reply", "donotreply", "do-not-reply",
                              "mailer-daemon", "postmaster", "webmaster", "hostmaster",
                              "abuse", "admin", "info", "support", "contact", "sales",
                              "marketing", "security", "privacy", "legal", "compliance"):
                return True
            return False

        if pii_type == "ip_address":
            parts = match.split(".")
            if len(parts) == 4:
                try:
                    octets = [int(p) for p in parts]
                    # Filter private/special IPs
                    if octets[0] in (0, 10, 127, 255):
                        return True
                    if octets[0] == 172 and 16 <= octets[1] <= 31:
                        return True
                    if octets[0] == 192 and octets[1] == 168:
                        return True
                    if octets[0] == 169 and octets[1] == 254:
                        return True
                    # Filter version numbers (any octet > 255)
                    if any(o > 255 for o in octets):
                        return True
                    # Filter common version-like patterns (low first octet, small later octets)
                    if octets[0] <= 9 and all(o <= 30 for o in octets[1:]):
                        return True
                except ValueError:
                    return True
            return False

        if pii_type == "credit_card":
            digits = re.sub(r"[- ]", "", match)
            if not digits.isdigit() or len(digits) < 13:
                return True
            # BIN / IIN prefix validation: first digit + second digit must
            # correspond to a real card network.
            first = digits[0]
            if first not in _VALID_CARD_PREFIXES:
                return True
            valid_seconds = _VALID_CARD_PREFIXES[first]
            if valid_seconds and len(digits) > 1 and digits[1] not in valid_seconds:
                return True
            # Reject sequences that look like UNIX timestamps (13-digit numbers
            # starting with 16/17/18/19/20 — these are epoch-milliseconds)
            if len(digits) == 13 and digits[:2] in ("16", "17", "18", "19", "20"):
                return True
            # Luhn check
            return not _luhn_check(digits)

        if pii_type == "phone_us":
            stripped = match.strip()
            # Require at least one separator character (already enforced by the
            # updated regex, but double-check for safety)
            if not any(c in stripped for c in "()-.  "):
                return True
            return False

        if pii_type == "iban":
            # Must be valid country code, exact country length, and pass ISO 7064 Mod-97 check
            return not _validate_iban(match)
        return False


def _luhn_check(card_number: str) -> bool:
    """Validate a credit card number using the Luhn algorithm."""
    digits = [int(d) for d in card_number]
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    total = sum(odd_digits)
    for d in even_digits:
        total += sum(divmod(d * 2, 10))
    return total % 10 == 0


def _validate_iban(candidate: str) -> bool:
    """Validate an IBAN candidate via country code, length, and ISO 7064 Mod-97 check."""
    s = candidate.strip().upper().replace(" ", "").replace("-", "")
    if len(s) < 15 or len(s) > 34:
        return False
    country = s[:2]
    if country not in _IBAN_COUNTRY_LENGTHS:
        return False
    if len(s) != _IBAN_COUNTRY_LENGTHS[country]:
        return False
    # ISO 7064 Mod 97-10 check:
    # Move the first 4 characters to the end
    rearranged = s[4:] + s[:4]
    # Replace letters with digits A=10 ... Z=35
    digits: list[str] = []
    for ch in rearranged:
        if ch.isdigit():
            digits.append(ch)
        elif ch.isalpha():
            digits.append(str(ord(ch) - 55))
        else:
            return False
    try:
        return int("".join(digits)) % 97 == 1
    except ValueError:
        return False
