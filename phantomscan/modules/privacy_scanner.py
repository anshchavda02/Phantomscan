"""Module 8 — PII / Privacy Exposure Scanner.

Scans HTTP responses for personally identifiable information (PII) exposure.
Detects emails, SSNs, credit cards, phone numbers, IP addresses, AWS keys, IBANs.
Outputs masked evidence only — never exposes real PII.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# PII detection patterns
# ---------------------------------------------------------------------------

PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    ),
    "us_ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    "phone_us": re.compile(
        r"\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    ),
    "ip_address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "iban": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b"),
}

_FAKE_EMAIL_DOMAINS = {
    "example.com", "test.com", "domain.com", "localhost",
    "example.org", "example.net", "invalid.test",
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
            if obs.get("name") in ("crawled_urls", "interesting_urls", "api_endpoints"):
                val = obs.get("value", [])
                if isinstance(val, list):
                    for item in val:
                        if isinstance(item, str):
                            urls_to_check.append(item)
                        elif isinstance(item, dict):
                            urls_to_check.append(item.get("url", ""))

        # Also check the base URL itself
        if base_url and base_url not in urls_to_check:
            urls_to_check.insert(0, base_url)

        findings: list[dict[str, Any]] = []
        checked = set()
        for url in urls_to_check[:30]:  # Limit to 30 URLs
            if not url or url in checked:
                continue
            checked.add(url)
            try:
                resp = await self.http.request("GET", url, timeout=10)
                body = resp.get("body", "")
                if isinstance(body, bytes):
                    body = body.decode("utf-8", errors="ignore")
                findings.extend(await self.scan_response(url, body))
            except Exception as exc:
                logger.debug("Privacy scan error for %s: %s", url, exc)

        return findings

    async def scan_response(
        self, url: str, body: str
    ) -> list[dict[str, Any]]:
        """Scan a single response body for PII patterns."""
        findings: list[dict[str, Any]] = []

        for pii_type, pattern in PII_PATTERNS.items():
            matches = pattern.findall(body)
            # Filter false positives
            matches = [
                m for m in matches
                if not self._is_false_positive(m, pii_type)
            ]

            if matches:
                severity = "high" if pii_type in _HIGH_RISK_TYPES else "medium"
                findings.append({
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
            return any(d in match.lower() for d in _FAKE_EMAIL_DOMAINS)
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
                    # Filter version numbers (e.g., 3.9.1)
                    if any(o > 255 for o in octets):
                        return True
                except ValueError:
                    return True
        if pii_type == "credit_card":
            # Luhn check to reduce false positives
            digits = re.sub(r"[- ]", "", match)
            if not digits.isdigit() or len(digits) < 13:
                return True
            return not _luhn_check(digits)
        if pii_type == "iban":
            # Must be at least 15 chars and start with valid country code
            if len(match) < 15:
                return True
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
