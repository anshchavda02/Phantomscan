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

def is_reflected_unencoded(payload: str, body: str) -> bool:
    """Check if payload appears unencoded in body and not HTML-encoded."""
    if not payload or payload not in body:
        return False
    encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
    # If HTML-encoded version appears and raw payload is not present outside of it
    if encoded in body and payload not in body.replace(encoded, ""):
        return False
    # If < is in payload, verify literal < is present in body
    if "<" in payload and "<" not in body:
        return False
    # If > is in payload, verify literal > is present in body
    if ">" in payload and ">" not in body:
        return False
    # Check for HTML entity marker escaping
    marker = payload.replace("<", "").replace(">", "").strip("/\"'")
    if f"&lt;{marker}" in body or f"&lt;/{marker}" in body or f"&#60;{marker}" in body or f"\\u003c{marker}" in body:
        return False
    return True


def _determine_context(payload: str, body: str) -> tuple[str, str]:
    """Determine reflection context (severity, context_name)."""
    idx = body.find(payload)
    if idx == -1:
        return "high", "html_body"

    prefix = body[max(0, idx - 100):idx]
    suffix = body[idx + len(payload):min(len(body), idx + len(payload) + 100)]

    # Trapped in HTML comment
    if "<!--" in prefix and "-->" in suffix and "-->" not in prefix:
        return "info", "html_comment"

    # Trapped inside script string literal without breakout
    if "<script" in prefix.lower() and "</script>" in suffix.lower():
        in_double = prefix.count('"') % 2 == 1 and suffix.count('"') % 2 == 1 and '"' not in payload
        in_single = prefix.count("'") % 2 == 1 and suffix.count("'") % 2 == 1 and "'" not in payload
        if in_double or in_single:
            return "info", "script_string_literal"

    return "high", "html_body"


# Safe non-destructive marker payloads for reflection testing
REFLECTED_PAYLOADS: list[str] = [
    "<phantomscan-xss-test>",
    '"phantomscan_xss_attr"',
    "phantomscan'xss",
    "<phantomscan_xss_probe>",
    '"><phantomscan_xss_break>',
    "'><phantomscan_xss_break>",
]


from phantomscan.injection_target import InjectionTarget, extract_injection_targets


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

        targets = extract_injection_targets(observations, target, max_targets=40)

        sem = asyncio.Semaphore(15)

        async def test_one_target(inj_target: InjectionTarget) -> dict[str, Any] | None:
            key = inj_target.key
            if key in tested:
                return None
            tested.add(key)

            async with sem:
                return await self._test_reflection(inj_target, inj_target.param_name)

        # Run parameter tests concurrently
        tasks = [test_one_target(t) for t in targets[:35]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, dict):
                findings.append(res)

        return findings

    # ── Reflected XSS testing ────────────────────────────────────────────────

    async def _test_reflection(
        self, target: InjectionTarget | str, param_name: str
    ) -> Optional[dict[str, Any]]:
        """Test if *param_name* reflects input unencoded."""
        import aiohttp as _aiohttp

        target_url = target.url if isinstance(target, InjectionTarget) else target

        # Obtain baseline response body first to check for pre-existing reflections
        baseline_body = ""
        try:
            if isinstance(target, InjectionTarget) and target.method == "POST":
                baseline_resp = await self.http.post(
                    target.url,
                    data={**target.hidden_fields, **target.all_params},
                    retries=1,
                    timeout=_aiohttp.ClientTimeout(total=8),
                )
            else:
                params = target.all_params if isinstance(target, InjectionTarget) else None
                baseline_resp = await self.http.get(
                    target_url,
                    params=params,
                    retries=1,
                    timeout=_aiohttp.ClientTimeout(total=8),
                )
            baseline_body = baseline_resp.text()
        except Exception:
            pass

        for payload in REFLECTED_PAYLOADS:
            try:
                if isinstance(target, InjectionTarget) and target.method == "POST":
                    form_data = dict(target.hidden_fields)
                    form_data.update(target.all_params)
                    form_data[param_name] = payload
                    response = await self.http.post(
                        target.url,
                        data=form_data,
                        retries=1,
                        timeout=_aiohttp.ClientTimeout(total=8),
                    )
                    test_evidence_url = f"{target.url} [POST: {param_name}={payload}]"
                elif isinstance(target, InjectionTarget):
                    query_params = dict(target.all_params)
                    query_params[param_name] = payload
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
                    params[param_name] = [payload]
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

                # Check if the payload appears UNENCODED in the response
                if self._is_reflected_not_encoded(payload, body, baseline_body):
                    severity, context_type = _determine_context(payload, body)
                    confidence = "high" if severity == "high" else "low"
                    return {
                        "id": "XSS-REFLECTED",
                        "title": f"Reflected XSS: Parameter '{param_name}'",
                        "severity": severity,
                        "confidence": confidence,
                        "category": "injection",
                        "target": target_url,
                        "verification_method": "baseline_differential",
                        "evidence": (
                            f"Parameter: {param_name}\n"
                            f"Payload: {payload}\n"
                            f"Tested URL: {test_evidence_url}\n"
                            f"Context: {context_type}\n"
                            f"The payload was reflected unencoded in the "
                            f"HTTP response body."
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
                logger.debug("XSS probe failed %s param=%s: %s", target_url, param_name, exc)

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

                # Exclude password fields from testing
                text_types = {"text", "search", "email", "tel", "url", "number", ""}
                text_fields = [
                    f for f in fields
                    if f.get("type", "text").lower() in text_types
                    and f.get("type", "text").lower() != "password"
                    and f.get("name")
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
                            severity, context_type = _determine_context(payload, body)
                            confidence = "high" if severity == "high" else "low"
                            return {
                                "id": "XSS-REFLECTED-FORM",
                                "title": f"Reflected XSS: Form Field '{field_name}'",
                                "severity": severity,
                                "confidence": confidence,
                                "category": "injection",
                                "target": action,
                                "verification_method": "baseline_differential",
                                "evidence": (
                                    f"Form action: {action}\n"
                                    f"Method: {method}\n"
                                    f"Field: {field_name}\n"
                                    f"Payload: {payload}\n"
                                    f"Context: {context_type}\n"
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
        """Confirm the payload appears unencoded in the response."""
        if not is_reflected_unencoded(payload, body):
            return False
        if baseline_body and payload in baseline_body:
            return False
        return True

    @staticmethod
    def _extract_params(
        observations: list[dict[str, Any]], target: str
    ) -> list[dict[str, Any]]:
        """Extract testable parameters with backward compatibility."""
        targets = extract_injection_targets(observations, target)
        return [
            {"url": t.url, "name": t.param_name, "target_obj": t}
            for t in targets
        ]
