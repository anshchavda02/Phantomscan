"""Strict CPE-only CVE matching helpers and NVD Engine.

This module intentionally refuses keyword matching. It returns no CVE findings
unless exact vendor, product, and version evidence is supplied by callers.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from phantomscan.models import Finding

logger = logging.getLogger(__name__)


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


class CVEEngine:
    """NVD CPE 2.3 CVE query engine with circuit breaker, rate limiting, and hard filters."""

    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, cache: Any = None, api_key: str | None = None) -> None:
        self.cache = cache
        self.api_key = api_key
        self.rate_limit_seconds = 0.6 if api_key else 6.0
        self._last_request_time = 0.0
        self._consecutive_failures = 0
        self._circuit_open = False
        self._circuit_reset_time = 0.0

    async def _throttle(self) -> None:
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < self.rate_limit_seconds:
            await asyncio.sleep(self.rate_limit_seconds - elapsed)
        self._last_request_time = time.time()

    def _is_circuit_open(self) -> bool:
        if self._circuit_open:
            if time.time() > self._circuit_reset_time:
                self._circuit_open = False
                self._consecutive_failures = 0
                return False
            return True
        return False

    def _record_failure(self) -> None:
        self._consecutive_failures += 1
        if self._consecutive_failures >= 3:
            self._circuit_open = True
            self._circuit_reset_time = time.time() + 60.0  # Cool off for 60s
            logger.warning("NVD CVE API circuit breaker tripped (3 consecutive failures). Cooling down for 60s.")

    def _record_success(self) -> None:
        self._consecutive_failures = 0
        self._circuit_open = False

    async def lookup_cves(
        self,
        technology: TechnologyVersion,
        http_client: Any = None,
        target_host: str = "",
    ) -> list[Finding]:
        """Query NVD for CVEs matching technology CPE, applying all hard filters."""
        if suppress_without_exact_cpe(technology):
            return []

        cpe = build_cpe(technology)
        if not cpe:
            return []

        # Check cache
        cache_key = f"cve:{cpe}"
        if self.cache:
            cached = None
            if hasattr(self.cache, "get"):
                cached = self.cache.get("cve", cache_key)
            if cached is not None and isinstance(cached, list):
                return [Finding.from_dict(f) if isinstance(f, dict) else f for f in cached]

        if self._is_circuit_open():
            logger.debug("NVD lookup skipped: circuit open")
            return []

        cve_items = await self._fetch_nvd(cpe, http_client)
        findings = self._filter_and_convert(cve_items, technology, target_host)

        if self.cache and hasattr(self.cache, "set"):
            self.cache.set("cve", cache_key, [f.to_dict() if hasattr(f, "to_dict") else f for f in findings], ttl=86400)

        return findings

    async def _fetch_nvd(self, cpe: str, http_client: Any = None) -> list[dict[str, Any]]:
        await self._throttle()
        url = f"{self.NVD_API_URL}?cpeName={cpe}"
        headers = {"User-Agent": "PhantomScan/2.0 authorized-security-assessment"}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            if http_client and hasattr(http_client, "get"):
                res = await http_client.get(url, headers=headers)
                if getattr(res, "status", 0) != 200:
                    self._record_failure()
                    return []
                data = json.loads(getattr(res, "body", "{}"))
            else:
                import urllib.request
                req = urllib.request.Request(url, headers=headers)
                loop = asyncio.get_running_loop()
                def _do_fetch():
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        return json.loads(resp.read().decode("utf-8", errors="replace"))
                data = await loop.run_in_executor(None, _do_fetch)

            self._record_success()
            return data.get("vulnerabilities", [])
        except Exception as exc:
            logger.debug("NVD API fetch failed for %s: %s", cpe, exc)
            self._record_failure()
            return []

    def _filter_and_convert(
        self,
        vulnerabilities: list[dict[str, Any]],
        technology: TechnologyVersion,
        target_host: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        now = datetime.now(timezone.utc)
        min_age_cutoff = now - timedelta(days=7)

        for item in vulnerabilities:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue

            # Hard filter 1: Published >= 7 days ago
            published_str = cve.get("published", "")
            if published_str:
                try:
                    pub_dt = datetime.fromisoformat(published_str.replace("Z", "+00:00"))
                    if pub_dt.tzinfo is None:
                        pub_dt = pub_dt.replace(tzinfo=timezone.utc)
                    if pub_dt > min_age_cutoff:
                        continue  # Published < 7 days ago -> suppress
                except Exception:
                    pass

            # Hard filter 2: CVSS score >= 4.0
            metrics = cve.get("metrics", {})
            cvss_score = 0.0
            severity_str = "medium"
            cvss_data = None
            for m_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if m_key in metrics and metrics[m_key]:
                    cvss_data = metrics[m_key][0].get("cvssData", {})
                    cvss_score = float(cvss_data.get("baseScore", 0.0))
                    break

            if cvss_score < 4.0:
                continue  # Suppress CVSS < 4.0

            if cvss_score >= 9.0:
                severity_str = "critical"
            elif cvss_score >= 7.0:
                severity_str = "high"
            elif cvss_score >= 4.0:
                severity_str = "medium"

            # Hard filter 3: Affected versions field non-empty
            configurations = cve.get("configurations", [])
            if not configurations:
                continue

            # Description
            descriptions = cve.get("descriptions", [])
            desc_text = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    desc_text = d.get("value", "")
                    break

            findings.append(Finding(
                id=cve_id,
                title=f"{cve_id}: {technology.vendor} {technology.product} Vulnerability",
                severity=severity_str,
                confidence="high",
                verification_method="external_verification",
                category="cve",
                target=target_host or f"{technology.vendor}:{technology.product}",
                evidence=f"CPE: {build_cpe(technology)}\nCVSS: {cvss_score}\nSummary: {desc_text[:300]}",
                recommendation=f"Update {technology.product} to the latest secure version.",
                cwe="CWE-1395",
            ))

        return findings
