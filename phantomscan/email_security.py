"""Real email-security checks using authoritative DNS lookups.

Checks performed:
  - MX record presence (authoritative, not A-record guessing)
  - SPF TXT record presence and policy strength
  - DMARC TXT record presence and policy strength
  - DKIM _domainkey TXT presence (best-effort)
"""

from __future__ import annotations

import asyncio
import logging

import dns.asyncresolver
import dns.exception
import dns.rdatatype

from .models import Finding, Observation
from .scope import Target, root_domain

logger = logging.getLogger(__name__)

# Known platforms that manage their own email posture — suppress noise.
_KNOWN_GOOD_PLATFORMS = {
    "google.com", "gmail.com", "googlemail.com",
    "microsoft.com", "outlook.com", "hotmail.com", "live.com",
    "yahoo.com", "apple.com", "icloud.com",
    "amazon.com", "amazonaws.com",
    "cloudflare.com",
    "github.com",
}


def _make_resolver() -> dns.asyncresolver.Resolver:
    """Return an async resolver using public, reliable nameservers."""
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
    resolver.timeout = 3.0
    resolver.lifetime = 5.0
    return resolver


async def _resolve_txt(resolver: dns.asyncresolver.Resolver, name: str, lifetime: float = 5.0) -> list[str]:
    """Resolve TXT records for *name*; return an empty list on any failure."""
    try:
        answers = await resolver.resolve(name, "TXT", lifetime=lifetime)
        result = []
        for rdata in answers:
            # Each TXT record may be split into multiple strings — join them.
            joined = "".join(s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s for s in rdata.strings)
            result.append(joined)
        return result
    except (dns.exception.DNSException, OSError):
        return []


async def _resolve_mx(resolver: dns.asyncresolver.Resolver, name: str, lifetime: float = 5.0) -> list[str]:
    """Resolve MX records for *name*; return an empty list on any failure."""
    try:
        answers = await resolver.resolve(name, "MX", lifetime=lifetime)
        return sorted(str(r.exchange).rstrip(".") for r in answers)
    except (dns.exception.DNSException, OSError):
        return []


async def analyze_email(
    target: Target,
    logger: logging.Logger | None = None,
) -> tuple[list[Observation], list[Finding]]:
    """Analyze high-level email posture using authoritative DNS lookups.

    Args:
        target: The normalised scan target.
        logger: Optional per-scan logger.

    Returns:
        A pair of ``(observations, findings)`` lists.
    """
    log = logger or logging.getLogger(__name__)

    if target.target_type != "domain":
        return [Observation("email_skipped", "non-domain target", "email")], []

    domain = root_domain(target.host)

    # Skip known platforms that manage their own posture correctly.
    if domain in _KNOWN_GOOD_PLATFORMS:
        log.info("Email check: skipping known-good platform %s", domain)
        return [
            Observation("email_domain", domain, "email"),
            Observation("email_skipped", f"Known-good platform: {domain}", "email"),
        ], []

    resolver = _make_resolver()
    observations: list[Observation] = [Observation("email_domain", domain, "email")]
    findings: list[Finding] = []

    # ── MX records ───────────────────────────────────────────────────────────
    mx_hosts = await _resolve_mx(resolver, domain)
    observations.append(Observation("mx_records", mx_hosts, "email"))
    log.info("Email MX for %s: %s", domain, mx_hosts or "none found")

    if not mx_hosts:
        findings.append(
            Finding(
                id="EMAIL-MX-MISSING",
                title="No MX records found",
                severity="info",
                confidence="medium",
                category="email",
                target=domain,
                evidence=f"DNS MX query for {domain} returned no records.",
                recommendation="Add MX records if this domain is used for email.",
            )
        )

    # ── SPF ───────────────────────────────────────────────────────────────────
    txt_records = await _resolve_txt(resolver, domain)
    spf_record: str | None = next((r for r in txt_records if r.startswith("v=spf1")), None)
    observations.append(Observation("spf_record", spf_record or "", "email"))

    if spf_record is None:
        findings.append(
            Finding(
                id="EMAIL-SPF-MISSING",
                title="SPF record missing",
                severity="medium",
                confidence="high",
                category="email",
                target=domain,
                evidence=f"No TXT record starting with 'v=spf1' found for {domain}.",
                recommendation="Add an SPF TXT record to authorise legitimate mail senders.",
            )
        )
    elif "+all" in spf_record:
        findings.append(
            Finding(
                id="EMAIL-SPF-PERMISSIVE",
                title="SPF record uses +all (permits any sender)",
                severity="high",
                confidence="high",
                category="email",
                target=domain,
                evidence=f"SPF record: {spf_record}",
                recommendation="Replace '+all' with '-all' or '~all' to restrict spoofing.",
            )
        )
    elif "?all" in spf_record:
        findings.append(
            Finding(
                id="EMAIL-SPF-NEUTRAL",
                title="SPF record uses ?all (neutral policy)",
                severity="low",
                confidence="high",
                category="email",
                target=domain,
                evidence=f"SPF record: {spf_record}",
                recommendation="Replace '?all' with '-all' to explicitly reject unauthorised senders.",
            )
        )
    log.info("SPF for %s: %s", domain, spf_record or "missing")

    # ── DMARC ─────────────────────────────────────────────────────────────────
    dmarc_name = f"_dmarc.{domain}"
    dmarc_records = await _resolve_txt(resolver, dmarc_name)
    dmarc_record: str | None = next((r for r in dmarc_records if r.startswith("v=DMARC1")), None)
    observations.append(Observation("dmarc_record", dmarc_record or "", "email"))

    if dmarc_record is None:
        findings.append(
            Finding(
                id="EMAIL-DMARC-MISSING",
                title="DMARC record missing",
                severity="medium",
                confidence="high",
                category="email",
                target=domain,
                evidence=f"No TXT record starting with 'v=DMARC1' found at {dmarc_name}.",
                recommendation="Add a DMARC TXT record to _dmarc.{domain} with at least p=quarantine.",
            )
        )
    elif "p=none" in dmarc_record:
        findings.append(
            Finding(
                id="EMAIL-DMARC-WEAK",
                title="DMARC policy set to monitor-only (p=none)",
                severity="low",
                confidence="high",
                category="email",
                target=domain,
                evidence=f"DMARC record: {dmarc_record}",
                recommendation="Change DMARC policy to p=quarantine or p=reject.",
            )
        )
    log.info("DMARC for %s: %s", domain, dmarc_record or "missing")

    # ── DKIM (best-effort — we can't enumerate selectors) ────────────────────
    dkim_name = f"_domainkey.{domain}"
    dkim_records = await _resolve_txt(resolver, dkim_name)
    observations.append(Observation("dkim_present", bool(dkim_records), "email"))
    if not dkim_records:
        log.debug("DKIM _domainkey check returned nothing for %s (selectors not known)", domain)

    return observations, findings
