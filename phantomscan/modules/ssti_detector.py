"""Server-Side Template Injection (SSTI) Detector.

Probes discovered injection targets with dynamic mathematical template expressions
({{A*B}}, ${A*B}, <%= A*B %>, #{A*B}, etc.) and confirms execution by verifying
evaluated output with dynamic factors and two-phase mathematical confirmation.
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Any, Optional
from urllib.parse import urlencode, urlparse, urlunparse

from phantomscan.http_client import RobustHTTPClient
from phantomscan.injection_target import InjectionTarget, extract_injection_targets
from phantomscan.modules.waf_detector import is_waf_block_page

logger = logging.getLogger(__name__)

# Template syntax formats with placeholders for dynamic operands
SSTI_TEMPLATES = [
    # Jinja2 / Twig / Django / Nunjucks / Pebble
    ("{{{{ {a}*{b} }}}}", "{a}*{b}"),
    ("{{{{'{a}'*3}}}}", "'{a}'*3"),
    # Freemarker / Spring / Java EL
    ("${{ {a}*{b} }}", "{a}*{b}"),
    ("#{{ {a}*{b} }}", "{a}*{b}"),
    # ERB / EJS
    ("<%= {a}*{b} %>", "{a}*{b}"),
    # Smarty
    ("{{{a}*{b}}}", "{a}*{b}"),
    # Generic math probe
    ("*{{{a}*{b}}}", "{a}*{b}"),
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

    async def _send_probe(
        self, target: InjectionTarget, param: str, payload: str
    ) -> tuple[str, int, str]:
        """Send a probe payload and return (response_body, status, tested_url)."""
        import aiohttp as _aiohttp

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
            return resp.text(), resp.status, f"{target.url} [POST: {param}={payload}]"
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
            return resp.text(), resp.status, full_url

    async def _test_ssti(
        self, target: InjectionTarget, param: str, original_value: str
    ) -> Optional[dict[str, Any]]:
        import aiohttp as _aiohttp

        # Step 1: Capture baseline
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

        for template_fmt, calc_type in SSTI_TEMPLATES:
            try:
                # Generate unique multi-digit random operands (product: 5-6 digits)
                a1 = random.randint(113, 987)
                b1 = random.randint(113, 987)
                if "{a}*{b}" in calc_type:
                    payload1 = template_fmt.format(a=a1, b=b1)
                    expected1 = str(a1 * b1)
                else:
                    # String repetition
                    s_token = f"pht{random.randint(10, 99)}"
                    payload1 = template_fmt.format(a=s_token)
                    expected1 = s_token * 3

                body1, status1, test_url1 = await self._send_probe(target, param, payload1)
                if is_waf_block_page(body1, status1):
                    continue

                # If the payload was reflected verbatim without evaluation, it's NOT SSTI
                if payload1 in body1:
                    continue

                # Check if evaluated result appears in response but was absent from baseline
                if expected1 in body1 and expected1 not in baseline_body:
                    # Phase 2: Confirmation probe with different operands to prevent random collision
                    a2 = random.randint(113, 987)
                    b2 = random.randint(113, 987)
                    while a2 * b2 == a1 * b1:
                        a2 = random.randint(113, 987)

                    if "{a}*{b}" in calc_type:
                        payload2 = template_fmt.format(a=a2, b=b2)
                        expected2 = str(a2 * b2)
                    else:
                        s_token2 = f"chk{random.randint(10, 99)}"
                        payload2 = template_fmt.format(a=s_token2)
                        expected2 = s_token2 * 3

                    body2, status2, test_url2 = await self._send_probe(target, param, payload2)
                    if is_waf_block_page(body2, status2) or payload2 in body2:
                        continue

                    # Confirmed only if secondary distinct evaluation also succeeded
                    if expected2 in body2 and expected2 not in baseline_body:
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
                                f"Probe 1: {payload1} -> Evaluated: {expected1}\n"
                                f"Confirmation Probe 2: {payload2} -> Evaluated: {expected2}\n"
                                f"Tested URL: {test_url1}\n"
                                f"Server-side template engine confirmed dynamic mathematical evaluation."
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

