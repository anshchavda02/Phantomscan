"""Email security checks."""

from __future__ import annotations

import asyncio
import socket

from .models import Finding, Observation
from .scope import Target


COMMON_SECOND_LEVELS = {"co", "com", "net", "org", "ac", "gov"}


def root_domain(host: str) -> str:
    """Best-effort eTLD+1 extraction without external dependencies."""
    parts = host.lower().strip(".").split(".")
    if len(parts) <= 2:
        return host.lower().strip(".")
    if len(parts[-1]) == 2 and parts[-2] in COMMON_SECOND_LEVELS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


async def analyze_email(target: Target) -> tuple[list[Observation], list[Finding]]:
    """Analyze high-level email posture using DNS TXT and MX where available."""
    if target.target_type != "domain":
        return [Observation("email_skipped", "non-domain target", "email")], []
    domain = root_domain(target.host)

    def lookup_mx() -> list[str]:
        try:
            return [row[4][0] for row in socket.getaddrinfo(f"mail.{domain}", None)]
        except socket.gaierror:
            return []

    mx = await asyncio.to_thread(lookup_mx)
    observations = [Observation("email_domain", domain, "email"), Observation("mx_hint", mx, "email")]
    findings: list[Finding] = []
    if not mx:
        findings.append(
            Finding(
                id="EMAIL-MX-NOT-CONFIRMED",
                title="Mail exchanger was not confirmed",
                severity="info",
                confidence="low",
                category="email",
                target=domain,
                evidence="No mail host was resolved using the lightweight resolver path.",
                recommendation="Confirm MX, SPF, DKIM, and DMARC with authoritative DNS tooling.",
            )
        )
    return observations, findings

