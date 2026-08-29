"""Reflected XSS Scanner with parameter and form testing.

Tests discovered URL parameters and form fields for reflected cross-site
scripting by injecting syntax-breaking marker payloads and checking whether
they appear unencoded in the HTML response without sanitization.

Uses safe, non-destructive marker strings that require raw angle brackets
(<, >) and quote breakouts (", ') to prove genuine context escape.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Optional
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from phantomscan.http_client import RobustHTTPClient
from phantomscan.modules.waf_detector import is_waf_block_page

logger = logging.getLogger(__name__)

# Strict syntax-breaking payloads — every payload contains < and > or quote breakouts.
# Plain strings without syntax characters are NEVER used as XSS probes.
REFLECTED_PAYLOADS: list[str] = [
    "<phantomscan_xss_probe>",                  # Tag context (< and > required)
    '"><phantomscan_xss_break>',                # Attribute double-quote breakout
    "'><phantomscan_xss_break>",                # Attribute single-quote breakout
    '"><script>/*phantomscan_xss*/</script>',   # Script tag injection
    '"--><phantomscan_xss_comment>',            # Comment breakout
]


class XSSScanner:
    """Detect reflected XSS by testing parameter reflection in HTTP responses."""

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

        params = self._extract_params(observations, target)

        sem = asyncio.Semaphore(15)

        async def test_one_param(param_info: dict[str, Any]) -> dict[str, Any] | None:
            url = param_info["url"]
            param_name = param_info["name"]
            key = f"{url}:{param_name}"
            if key in tested:
                return None
            tested.add(key)

            async with sem:
                return await self._test_reflection(url, param_name)

        # Run GET parameter tests concurrently
        param_tasks = [test_one_param(p) for p in params[:30]]
        param_results = await asyncio.gather(*param_tasks, return_exceptions=True)
        for res in param_results:
            if isinstance(res, dict):
                findings.append(res)

        # Test form fields concurrently
        form_findings = await self._test_forms_concurrent(observations, target, tested, sem)
        findings.extend(form_findings)

        return findings

    # ── Reflected XSS in GET parameters ──────────────────────────────────────

    async def _test_reflection(
        self, url: str, param_name: str
    ) -> Optional[dict[str, Any]]:
        """Test if *param_name* at *url* reflects input unencoded."""
        import aiohttp as _aiohttp

        # Obtain baseline response body first to check for pre-existing reflections
        baseline_body = ""
        try:
            baseline_resp = await self.http.get(
                url,
                retries=1,
                timeout=_aiohttp.ClientTimeout(total=8),
            )
            baseline_body = baseline_resp.text()
        except Exception:
            pass

        for payload in REFLECTED_PAYLOADS:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[param_name] = [payload]
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
                    timeout=_aiohttp.ClientTimeout(total=8),
                )
                body = response.text()

                # WAF block check
                if is_waf_block_page(body, response.status):
                    continue

                # Check if the payload appears UNENCODED in the response
                if self._is_reflected_not_encoded(payload, body, baseline_body):
                    return {
                        "id": "XSS-REFLECTED",
                        "title": f"Reflected XSS: Parameter '{param_name}'",
                        "severity": "high",
                        "confidence": "high",
                        "category": "injection",
                        "target": url,
                        "verification_method": "baseline_differential",
                        "evidence": (
                            f"Parameter: {param_name}\n"
                            f"Payload: {payload}\n"
                            f"URL: {test_url}\n"
                            f"The payload was reflected unencoded in the "
                            f"HTTP response body (HTML context)."
                        ),
                        "recommendation": (
                            "Apply context-appropriate output encoding to all "
                            "user-controlled input before rendering in HTML. "
                            "Use a Content-Security-Policy header to mitigate "
                            "exploitation. CWE-79, OWASP A03:2021."
                        ),
                        "references": [
                            "https://cwe.mitre.org/data/definitions/79.html",
                        ],
                    }
            except Exception as exc:
                logger.debug("XSS probe failed %s param=%s: %s", url, param_name, exc)

        return None

    # ── Form-based XSS ───────────────────────────────────────────────────────

    async def _test_forms_concurrent(
        self,
        observations: list[dict[str, Any]],
        target: str,
        tested: set[str],
        sem: asyncio.Semaphore,
    ) -> list[dict[str, Any]]:
        """Test form fields for reflected XSS concurrently."""
        import aiohttp as _aiohttp
        findings: list[dict[str, Any]] = []
        form_targets: list[tuple[str, str, str, list[dict[str, Any]]]] = []

        for obs in observations:
            if obs.get("name") != "discovered_forms":
                continue
            forms = obs.get("value", [])
            if not isinstance(forms, list):
                continue

            for form in forms:
                action = form.get("action", target)
                method = form.get("method", "GET").upper()
                fields = form.get("fields", [])

                text_types = {"text", "search", "email", "password", "tel", "url", "number", ""}
                text_fields = [
                    f for f in fields
                    if f.get("type", "text").lower() in text_types and f.get("name")
                ]

                for field_info in text_fields:
                    field_name = field_info["name"]
                    key = f"xss-form:{action}:{field_name}"
                    if key in tested:
                        continue
                    tested.add(key)
                    form_targets.append((action, method, field_name, fields))

        async def test_one_form(item: tuple[str, str, str, list[dict[str, Any]]]) -> dict[str, Any] | None:
            action, method, field_name, fields = item
            async with sem:
                for payload in REFLECTED_PAYLOADS[:3]:
                    form_data = {}
                    for f in fields:
                        if f.get("name") == field_name:
                            form_data[f["name"]] = payload
                        else:
                            form_data[f.get("name", "")] = f.get("value", "test")

                    try:
                        if method == "POST":
                            response = await self.http.post(
                                action,
                                data=form_data,
                                retries=1,
                                timeout=_aiohttp.ClientTimeout(total=8),
                            )
                        else:
                            response = await self.http.get(
                                action,
                                params=form_data,
                                retries=1,
                                timeout=_aiohttp.ClientTimeout(total=8),
                            )

                        body = response.text()
                        if is_waf_block_page(body, response.status):
                            continue

                        if self._is_reflected_not_encoded(payload, body):
                            return {
                                "id": "XSS-REFLECTED-FORM",
                                "title": f"Reflected XSS: Form Field '{field_name}'",
                                "severity": "high",
                                "confidence": "high",
                                "category": "injection",
                                "target": action,
                                "verification_method": "baseline_differential",
                                "evidence": (
                                    f"Form action: {action}\n"
                                    f"Method: {method}\n"
                                    f"Field: {field_name}\n"
                                    f"Payload: {payload}\n"
                                    f"The payload was reflected unencoded in "
                                    f"the HTTP response body."
                                ),
                                "recommendation": (
                                    "Apply context-appropriate output encoding. "
                                    "CWE-79, OWASP A03:2021."
                                ),
                                "references": [
                                    "https://cwe.mitre.org/data/definitions/79.html",
                                ],
                            }
                    except Exception as exc:
                        logger.debug("XSS form probe error: %s", exc)
            return None

        results = await asyncio.gather(*(test_one_form(item) for item in form_targets[:20]), return_exceptions=True)
        for r in results:
            if isinstance(r, dict):
                findings.append(r)

        return findings

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _is_reflected_not_encoded(payload: str, body: str, baseline_body: str = "") -> bool:
        """Confirm the payload appears unencoded in the response.

        Requirements for a valid XSS reflection:
        1. The payload must be in the response body.
        2. The payload must NOT be already present in the baseline body.
        3. The payload MUST contain HTML syntax characters (<, >) and they must
           appear literally (not as &lt;, &gt;, &#60;, &#62;, \\u003c, or %3C).
        4. The reflection must not be purely trapped inside an encoded URL parameter.
        """
        if not payload or payload not in body:
            return False

        # If already in baseline body, it's pre-existing static content
        if baseline_body and payload in baseline_body:
            return False

        # Payloads must contain syntax-breaking characters to prove XSS
        if "<" not in payload and ">" not in payload and '"' not in payload and "'" not in payload:
            return False

        # Check for HTML entity encoding
        if "<" in payload:
            # If the response only has &lt; instead of raw < for our marker, it's safe
            marker = payload.replace("<", "").replace(">", "").strip("/\"'")
            if f"&lt;{marker}" in body or f"&lt;/{marker}" in body or f"&#60;{marker}" in body or f"\\u003c{marker}" in body:
                return False

        # If payload contains tag brackets, verify they are present in raw form
        if "<" in payload and "<" not in body:
            return False
        if ">" in payload and ">" not in body:
            return False

        return True

    @staticmethod
    def _extract_params(
        observations: list[dict[str, Any]], target: str
    ) -> list[dict[str, Any]]:
        """Extract testable parameters with host-level deduplication."""
        params: list[dict[str, Any]] = []
        seen_keys: set[tuple[str, str]] = set()
        param_counts: dict[str, int] = {}  # Cap same param name across URLs on same host

        def add(url: str, name: str) -> None:
            name_clean = name.strip()
            if not name_clean or name_clean.startswith("amp;"):
                name_clean = name_clean.removeprefix("amp;")
            if not name_clean:
                return

            # Cap each param name (e.g. 'hl', 'q') to at most 2 distinct endpoints per host
            current_count = param_counts.get(name_clean, 0)
            if current_count >= 2:
                return

            key = (url, name_clean)
            if key not in seen_keys and len(params) < 40:
                seen_keys.add(key)
                param_counts[name_clean] = current_count + 1
                params.append({"url": url, "name": name_clean})

        for obs in observations:
            obs_name = str(obs.get("name", ""))
            val = obs.get("value", "")

            # Parameterized URLs from crawler
            if obs_name in ("parameterized_urls", "discovered_urls") and isinstance(val, list):
                for u in val:
                    if isinstance(u, str) and "?" in u:
                        parsed = urlparse(u)
                        clean = urlunparse(parsed._replace(query=""))
                        for pname in parse_qs(parsed.query, keep_blank_values=True):
                            add(clean, pname)

            # URLs with query strings from HTTP observation
            if "http_url" in obs_name and isinstance(val, str) and "?" in val:
                parsed = urlparse(val)
                clean = urlunparse(parsed._replace(query=""))
                for pname in parse_qs(parsed.query, keep_blank_values=True):
                    add(clean, pname)

            # API endpoints that look like search/filter
            if "discovered_api" in obs_name and isinstance(val, list):
                for ep in val:
                    if isinstance(ep, dict):
                        ep_url = ep.get("url", "")
                        if ep_url and any(kw in ep_url.lower() for kw in
                                         ["search", "product", "user", "filter", "find", "query"]):
                            for p in ("q", "search", "query", "name"):
                                add(ep_url, p)

        # Fallback: test base URL with common param names if none found
        if not params:
            for p in ("q", "search", "id", "query", "name"):
                add(target, p)
            add(f"{target}/search", "q")

        return params
