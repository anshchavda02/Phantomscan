"""Module 19 — Stateful Multi-Step Scanner.

Provides a workflow engine for multi-step testing (e.g., register -> login -> action).
Propagates state (cookies, CSRF tokens) between steps and detects workflow bypasses.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)


@dataclass
class WorkflowState:
    cookies: dict[str, str] = field(default_factory=dict)
    csrf_token: str = ""
    extracted_data: dict[str, str] = field(default_factory=dict)


class StatefulScanner:
    """Execute multi-step workflows and detect bypass vulnerabilities."""

    def __init__(self, http: RobustHTTPClient) -> None:
        self.http = http
        self.state = WorkflowState()

    async def run(
        self,
        base_url: str,
        observations: list[dict[str, Any]],
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        target = base_url.rstrip("/")

        # Auto-discover a simple shopping cart / checkout workflow if present
        workflow = self._discover_workflow(target, observations)
        if not workflow:
            return findings

        # Test 1: Happy path execution to establish baseline
        happy_path_success = await self._execute_workflow(workflow)
        if not happy_path_success:
            return findings

        # Test 2: Workflow Bypass (skip intermediate steps)
        bypass = await self._test_workflow_bypass(workflow)
        if bypass:
            findings.append(bypass)

        return findings

    def _discover_workflow(
        self, target: str, observations: list[dict[str, Any]]
    ) -> list[dict[str, Any]] | None:
        """Heuristically assemble a testable workflow from observations."""
        endpoints = set()
        for obs in observations:
            val = str(obs.get("value", "")).lower()
            if "http" in val or "/" in val:
                endpoints.add(val if val.startswith("http") else f"{target}{val}")

        cart_url = None
        checkout_url = None
        confirm_url = None

        for ep in endpoints:
            if "cart" in ep or "add" in ep:
                cart_url = ep
            elif "checkout" in ep or "pay" in ep:
                checkout_url = ep
            elif "confirm" in ep or "complete" in ep:
                confirm_url = ep

        if cart_url and checkout_url and confirm_url:
            return [
                {"step": 1, "method": "POST", "url": cart_url, "payload": {"item_id": "1", "qty": 1}},
                {"step": 2, "method": "POST", "url": checkout_url, "payload": {"shipping": "standard"}},
                {"step": 3, "method": "POST", "url": confirm_url, "payload": {"confirm": True}},
            ]
        return None

    async def _execute_workflow(self, workflow: list[dict[str, Any]]) -> bool:
        """Execute the workflow in order, accumulating state."""
        self.state = WorkflowState()  # Reset state

        for step in workflow:
            headers = {}
            if self.state.csrf_token:
                headers["X-CSRF-Token"] = self.state.csrf_token

            try:
                response = await self.http.request(
                    step["method"],
                    step["url"],
                    json=step.get("payload"),
                    headers=headers,
                    cookies=self.state.cookies,
                    retries=1,
                )

                if response.status >= 400:
                    return False

                # Update state
                self.state.cookies.update(response.cookies)

                # Heuristically extract CSRF token if present
                body = response.text()
                match = re.search(r'name=["\']csrf_token["\'] value=["\']([^"\']+)["\']', body, re.I)
                if match:
                    self.state.csrf_token = match.group(1)

            except Exception:
                return False

        return True

    async def _test_workflow_bypass(
        self, workflow: list[dict[str, Any]]
    ) -> dict[str, Any] | None:
        """Attempt to skip steps in the workflow (e.g., jump straight to confirm)."""
        if len(workflow) < 3:
            return None

        # Reset state
        self.state = WorkflowState()
        first_step = workflow[0]
        last_step = workflow[-1]

        # Execute only step 1
        try:
            response1 = await self.http.request(
                first_step["method"],
                first_step["url"],
                json=first_step.get("payload"),
                retries=1,
            )
            self.state.cookies.update(response1.cookies)
        except Exception:
            return None

        # Jump directly to final step, skipping intermediate steps
        try:
            response_final = await self.http.request(
                last_step["method"],
                last_step["url"],
                json=last_step.get("payload"),
                cookies=self.state.cookies,
                retries=1,
            )

            # If the final step succeeds without the intermediate steps, it's a bypass
            if response_final.status in (200, 201):
                return {
                    "id": "WORKFLOW-BYPASS",
                    "title": "Stateful Workflow Bypass (Forced Browsing)",
                    "severity": "high",
                    "confidence": "medium",
                    "category": "business-logic",
                    "target": last_step["url"],
                    "evidence": (
                        f"Successfully executed final step ({last_step['url']}) "
                        f"immediately after step 1 ({first_step['url']}), "
                        f"bypassing intermediate validation steps."
                    ),
                    "recommendation": (
                        "Enforce strict server-side state machines. Do not rely "
                        "on the client to navigate pages in the correct order. "
                        "Verify prerequisites before executing business actions. "
                        "CWE-840."
                    ),
                    "references": ["https://cwe.mitre.org/data/definitions/840.html"],
                }
        except Exception:
            pass

        return None
