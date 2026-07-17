"""Strict CPE-only CVE matching helpers.

This module intentionally refuses keyword matching. It returns no CVE findings
unless exact vendor, product, and version evidence is supplied by callers.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TechnologyVersion:
    """A versioned technology suitable for CPE construction."""

    vendor: str
    product: str
    version: str
    evidence_methods: int


def build_cpe(technology: TechnologyVersion) -> str | None:
    """Build a CPE 2.3 URI when evidence is strong enough."""
    if technology.evidence_methods < 2 or not technology.version:
        return None
    vendor = technology.vendor.strip().lower().replace(" ", "_")
    product = technology.product.strip().lower().replace(" ", "_")
    version = technology.version.strip()
    if not vendor or not product or not version:
        return None
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*:*"


def suppress_without_exact_cpe(technology: TechnologyVersion) -> bool:
    """Return true when a CVE candidate must be suppressed."""
    return build_cpe(technology) is None

