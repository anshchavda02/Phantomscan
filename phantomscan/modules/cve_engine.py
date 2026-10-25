"""CVE Engine module adapter for PhantomScan DAG pipeline.

Strict CPE 2.3 correlation matching detected server, framework, and language technologies
against the National Vulnerability Database (NVD).
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from modules.cve_engine import CVEEngine, TechnologyVersion

logger = logging.getLogger(__name__)


def normalize_tech(vendor: str, product: str) -> tuple[str, str]:
    """Map detected web technology labels into canonical CPE vendor and product identifiers."""
    v = vendor.strip().lower()
    p = product.strip().lower()

    if v in ("php",) or p in ("php",):
        return ("php", "php")
    if v in ("apache", "apache_http_server", "apache http server") or p in ("http_server", "apache", "httpd"):
        return ("apache", "http_server")
    if v in ("nginx",) or p in ("nginx",):
        return ("nginx", "nginx")
    if v in ("wordpress",) or p in ("wordpress",):
        return ("wordpress", "wordpress")
    if v in ("openssl",) or p in ("openssl",):
        return ("openssl", "openssl")
    if v in ("log4j",) or p in ("log4j",):
        return ("apache", "log4j")
    if v in ("spring", "spring_framework", "spring framework") or p in ("spring_framework", "spring"):
        return ("spring", "spring_framework")
    if v in ("confluence", "atlassian") or p in ("confluence", "confluence_server"):
        return ("atlassian", "confluence_server")
    if v in ("drupal",) or p in ("drupal",):
        return ("drupal", "drupal")
    if v in ("node", "nodejs", "node.js") or p in ("node", "nodejs", "node.js"):
        return ("nodejs", "node.js")
    return (vendor, product)


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
        seen_combos: set[tuple[str, str, str]] = set()

        def _add_tech(raw_vendor: str, raw_product: str, ver: str, count: int) -> None:
            norm_v, norm_p = normalize_tech(raw_vendor, raw_product)
            clean_ver = ver.strip()
            combo = (norm_v.lower(), norm_p.lower(), clean_ver.lower())
            if norm_v and norm_p and clean_ver and combo not in seen_combos:
                seen_combos.add(combo)
                techs_to_check.append(TechnologyVersion(
                    vendor=norm_v, product=norm_p, version=clean_ver, evidence_methods=max(count, 2)
                ))

        for obs in observations:
            name = obs.get("name", "")
            source = obs.get("source", "")
            val = obs.get("value")

            if source in ("tech", "technology", "fingerprint", "profile") or name in ("tech", "technology", "technologies", "tech_stack"):
                if isinstance(val, dict):
                    v = str(val.get("vendor", val.get("name", ""))).strip()
                    p = str(val.get("product", val.get("name", ""))).strip()
                    ver = str(val.get("version", "")).strip()
                    ev_count = int(val.get("evidence_count", val.get("evidence_methods", 2)))
                    _add_tech(v, p, ver, ev_count)
                elif isinstance(val, list):
                    for item in val:
                        if isinstance(item, dict):
                            v = str(item.get("vendor", item.get("name", ""))).strip()
                            p = str(item.get("product", item.get("name", ""))).strip()
                            ver = str(item.get("version", "")).strip()
                            ev_count = int(item.get("evidence_count", item.get("evidence_methods", 2)))
                            _add_tech(v, p, ver, ev_count)

        for tech in techs_to_check[:10]:
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
