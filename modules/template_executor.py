"""Template Executor for running YAML security templates against targets."""
from __future__ import annotations

import logging
from urllib.parse import urlparse
from typing import Any, Optional

from modules.catch_all_detector import CatchAllResult
from modules.extractor_engine import ExtractorEngine
from modules.matcher_engine import MatcherEngine, MatchResult
from modules.template_loader import Template, RequestDefinition
from phantomscan.models import Finding
from phantomscan.modules.finding_gate import gate_finding

logger = logging.getLogger(__name__)


class TemplateExecutor:
    """Executes a single YAML Template against a target with strict web-root isolation."""

    def __init__(self, http_client: Any) -> None:
        self.http = http_client
        self.matcher_engine = MatcherEngine()
        self.extractor_engine = ExtractorEngine()

    def _get_web_root(self, target: str) -> str:
        """Derive pure scheme://netloc web root from any target URL."""
        target_clean = target.strip()
        if not target_clean.startswith(("http://", "https://")):
            target_clean = f"http://{target_clean}"

        parsed = urlparse(target_clean)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
        return target_clean.rstrip("/")

    async def execute(
        self,
        template: Template,
        target: str,
        catch_all: Optional[CatchAllResult] = None,
    ) -> Optional[Finding]:
        """Execute template requests and return a validated Finding if matched."""
        web_root = self._get_web_root(target)
        variables: dict[str, str] = {}
        matched_evidences: list[str] = []
        last_matched_url: str = web_root
        current_oob_id: Optional[str] = None

        step_results: list[bool] = []

        for req_idx, req_def in enumerate(template.requests):
            step_matched = False
            method = req_def.method.upper()

            for path_tmpl in req_def.path:
                # 1. Substitute BaseURL with pure web_root
                url = path_tmpl.replace("{{BaseURL}}", web_root)
                # 2. Substitute extracted variables
                url = self.extractor_engine.substitute_variables(url, variables)

                req_body = req_def.body
                if req_body:
                    req_body = self.extractor_engine.substitute_variables(req_body, variables)

                # 3. Handle OOB payload substitution if template uses {{oob_url}}
                if "{{oob_url}}" in url or (req_body and "{{oob_url}}" in req_body):
                    try:
                        from phantomscan.oob import oob_listener
                        if not oob_listener.is_running:
                            oob_listener.start()
                        current_oob_id, oob_endpoint = oob_listener.generate_payload_url()
                        url = url.replace("{{oob_url}}", oob_endpoint)
                        if req_body:
                            req_body = req_body.replace("{{oob_url}}", oob_endpoint)
                    except Exception as e:
                        logger.debug("OOB listener setup error: %s", e)

                # 4. Execute HTTP request
                headers = dict(req_def.headers)
                try:
                    if method == "POST":
                        resp = await self.http.post(url, data=req_body, headers=headers, retries=1)
                    else:
                        resp = await self.http.get(url, headers=headers, retries=1)
                except Exception as e:
                    logger.debug("Template %s request failed for %s: %s", template.id, url, e)
                    continue

                if resp is None:
                    continue

                # 5. Evaluate matchers
                match_result: MatchResult = self.matcher_engine.evaluate(
                    response=resp,
                    matchers=req_def.matchers,
                    condition=req_def.matchers_condition,
                    current_oob_id=current_oob_id,
                )

                # 6. Apply Catch-All Differential Verification if catch-all server confirmed
                if match_result.matched and catch_all and catch_all.has_catch_all:
                    body_text = resp.text() if hasattr(resp, "text") and callable(resp.text) else getattr(resp, "body_text", "")
                    body_len = len(body_text)
                    baseline_len = catch_all.baseline_body_length
                    # If response is within 20% size variance of catch-all baseline and contains HTML markers, reject
                    if baseline_len > 0 and abs(body_len - baseline_len) <= (0.20 * max(baseline_len, 1)):
                        if "<html" in body_text.lower() or "<!doctype" in body_text.lower():
                            match_result = MatchResult(
                                matched=False,
                                evidence="Rejected by catch-all baseline differential",
                            )

                if match_result.matched:
                    step_matched = True
                    last_matched_url = url
                    if match_result.evidence:
                        matched_evidences.append(f"[{method} {url}] {match_result.evidence}")

                    # 7. Run extractors and store variables for subsequent requests
                    if req_def.extractors:
                        extracted = self.extractor_engine.extract(resp, req_def.extractors)
                        variables.update(extracted)

                    break  # Request matched for this request block

            step_results.append(step_matched)

            # Check flow stopping condition
            # Default flow: every defined request step must succeed
            if not step_matched:
                return None

        # Check overall flow condition if specified (e.g. flow: http(1) && http(2))
        if template.flow:
            # Simple flow check: if flow requires http(1) && http(2), ensure all steps passed
            if not all(step_results):
                return None
        else:
            if not all(step_results):
                return None

        # Construct Finding
        evidence_text = f"Template '{template.id}' matched against {last_matched_url}."
        if matched_evidences:
            evidence_text += " Evidence: " + " | ".join(matched_evidences)

        # Categorize
        tags = template.info.tags
        category = "vulnerability"
        if any(t in tags for t in ("exposure", "config", "sensitive", "git", "env")):
            category = "exposure"

        raw_finding = {
            "id": f"TEMPLATE-{template.id.upper()}",
            "title": template.info.name,
            "severity": template.info.severity,
            "confidence": "high",
            "category": category,
            "target": last_matched_url,
            "evidence": evidence_text,
            "recommendation": f"Review and restrict access to {last_matched_url}. Ensure sensitive endpoints are secured.",
            "verification_method": "baseline_differential" if catch_all and catch_all.has_catch_all else "active_confirmation",
        }

        # Gate finding to enforce quality invariants
        gated = gate_finding(raw_finding)
        if not gated:
            return None

        return Finding.from_dict(gated) if hasattr(Finding, "from_dict") else Finding(**gated)
