"""Server-Side Template Injection (SSTI) Detector.

Probes discovered injection targets with mathematical template expressions
({{7*7}}, ${7*7}, <%= 7*7 %>, #{7*7}, etc.) and confirms execution by verifying
evaluated output (49) with baseline differential comparison.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional
from urllib.parse import urlencode, urlparse, urlunparse

from phantomscan.http_client import RobustHTTPClient
from phantomscan.injection_target import InjectionTarget, extract_injection_targets
from phantomscan.modules.waf_detector import is_waf_block_page

logger = logging.getLogger(__name__)

# Template injection probe expressions and expected evaluated products
SSTI_PROBES = [
    # Jinja2 / Twig / Django / Nunjucks / Pebble
    ("{{7*7}}", "49"),
    ("{{7*'7'}}", "7777777"),
    # Freemarker / Spring / Java EL
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    # ERB / EJS
    ("<%= 7*7 %>", "49"),
    # Smarty
    ("{7*7}", "49"),
    # Generic math probe
    ("*{7*7}", "49"),
]


class SSTIDetector:
    """Detect Server-Side Template Injection (SSTI) across parameters and forms."""

    def __init__(self, http: RobustHTTPClient) -> None:
        self.http = http

    async def run(
        self,
        base_url: str,
        observations: list[dict[str, Any]],
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        target = base_url.rstrip("/")
        tested: set[str] = set()

        targets = extract_injection_targets(observations, target, max_targets=40)
        sem = asyncio.Semaphore(15)

        async def test_one(inj_target: InjectionTarget) -> dict[str, Any] | None:
            key = inj_target.key
            if key in tested:
                return None
            tested.add(key)

            async with sem:
                return await self._test_ssti(inj_target, inj_target.param_name, inj_target.original_value)

        tasks = [test_one(t) for t in targets[:35]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict):
                findings.append(r)

        return findings

    async def _test_ssti(
        self, target: InjectionTarget, param: str, original_value: str
    ) -> Optional[dict[str, Any]]:
        import aiohttp as _aiohttp

        # Step 1: Capture baseline to ensure '49' isn't already naturally present
        baseline_body = ""
        try:
            if target.method == "POST":
                form_data = dict(target.hidden_fields)
                form_data.update(target.all_params)
                baseline_resp = await self.http.post(
                    target.url,
                    data=form_data,
                    retries=1,
                    timeout=_aiohttp.ClientTimeout(total=8),
                )
            else:
                baseline_resp = await self.http.get(
                    target.url,
                    params=target.all_params,
                    retries=1,
                    timeout=_aiohttp.ClientTimeout(total=8),
                )
            baseline_body = baseline_resp.text()
        except Exception:
            pass

        for payload, expected in SSTI_PROBES:
            try:
                if target.method == "POST":
                    form_data = dict(target.hidden_fields)
                    form_data.update(target.all_params)
                    form_data[param] = payload
                    resp = await self.http.post(
                        target.url,
                        data=form_data,
                        retries=1,
                        timeout=_aiohttp.ClientTimeout(total=8),
                    )
                    test_url = f"{target.url} [POST: {param}={payload}]"
                else:
                    query_params = dict(target.all_params)
                    query_params[param] = payload
                    parsed = urlparse(target.url)
                    new_query = urlencode(query_params, doseq=True)
                    full_url = urlunparse((
                        parsed.scheme, parsed.netloc,
                        parsed.path, parsed.params,
                        new_query, parsed.fragment,
                    ))
                    resp = await self.http.get(
                        full_url,
                        retries=1,
                        timeout=_aiohttp.ClientTimeout(total=8),
                    )
                    test_url = full_url

                body = resp.text()
                if is_waf_block_page(body, resp.status):
                    continue

                # If the payload was reflected verbatim without evaluation, it's NOT SSTI
                if payload in body:
                    continue

                # Check if evaluated result appears in response but was absent from baseline
                if expected in body and expected not in baseline_body:
                    return {
                        "id": "SSTI-INJECTION",
                        "title": f"Server-Side Template Injection (SSTI): Parameter '{param}'",
                        "severity": "critical",
                        "confidence": "high",
                        "category": "injection",
                        "target": target.url,
                        "verification_method": "baseline_differential",
                        "evidence": (
                            f"Parameter: {param}\n"
                            f"Payload: {payload}\n"
                            f"Evaluated output: {expected}\n"
                            f"Tested URL: {test_url}\n"
                            f"The template engine evaluated the expression on the server."
                        ),
                        "recommendation": (
                            "Do not pass user-controlled input directly into template engines. "
                            "Use static templates with parameterized variables and sandbox "
                            "template execution engines. CWE-1336, OWASP A03:2021."
                        ),
                        "references": [
                            "https://cwe.mitre.org/data/definitions/1336.html",
                            "https://owasp.org/Top10/A03_2021-Injection/",
                        ],
                    }
            except Exception as exc:
                logger.debug("SSTI test error on %s param=%s: %s", target.url, param, exc)

        return None
