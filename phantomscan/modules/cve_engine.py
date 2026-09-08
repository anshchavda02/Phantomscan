"""CVE Engine module adapter for PhantomScan DAG pipeline.

Strict CPE 2.3 correlation matching detected server, framework, and language technologies
against the National Vulnerability Database (NVD).
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from modules.cve_engine import CVEEngine, TechnologyVersion
from phantomscan.models import Finding

logger = logging.getLogger(__name__)


class CVEEngineScanner:
    """DAG pipeline module that correlates detected technologies with known CVEs via strict CPE matching."""

    def __init__(self, http: Any = None) -> None:
        self.http = http
        self.engine = CVEEngine()

    async def run(
        self,
        base_url: str,
        observations: list[dict[str, Any]],
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        host = urlparse(base_url).hostname or base_url

        # Extract technologies with versions from observations
        techs_to_check: list[TechnologyVersion] = []
        for obs in observations:
            name = obs.get("name", "")
            source = obs.get("source", "")
            val = obs.get("value")

            if source in ("tech", "technology") or name in ("tech", "technology", "technologies", "tech_stack"):
                if isinstance(val, dict):
                    vendor = str(val.get("vendor", val.get("name", ""))).strip()
                    product = str(val.get("product", val.get("name", ""))).strip()
                    version = str(val.get("version", "")).strip()
                    ev_count = int(val.get("evidence_count", val.get("evidence_methods", 2)))
                    if vendor and product and version:
                        techs_to_check.append(TechnologyVersion(
                            vendor=vendor, product=product, version=version, evidence_methods=ev_count
                        ))
                elif isinstance(val, list):
                    for item in val:
                        if isinstance(item, dict):
                            vendor = str(item.get("vendor", item.get("name", ""))).strip()
                            product = str(item.get("product", item.get("name", ""))).strip()
                            version = str(item.get("version", "")).strip()
                            ev_count = int(item.get("evidence_count", item.get("evidence_methods", 2)))
                            if vendor and product and version:
                                techs_to_check.append(TechnologyVersion(
                                    vendor=vendor, product=product, version=version, evidence_methods=ev_count
                                ))

        for tech in techs_to_check[:5]:
            try:
                cve_findings = await self.engine.lookup_cves(
                    technology=tech,
                    http_client=self.http,
                    target_host=host,
                )
                for f in cve_findings:
                    findings.append(f.to_dict() if hasattr(f, "to_dict") else f)
            except Exception as exc:
                logger.debug("CVE lookup for %s %s failed: %s", tech.vendor, tech.product, exc)

        return findings
