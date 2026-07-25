"""Module 14 — Embedded Finding Chat & AI Explanation.

Provides interactive assistance and explanation for findings.
Can query a local Ollama LLM endpoint or fall back to static security FAQs.
"""

from __future__ import annotations

import logging
from typing import Any

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)

STATIC_FAQS: dict[str, str] = {
    "cwe": "Common Weakness Enumeration (CWE) provides a universal dictionary of software security weaknesses.",
    "cvss": "Common Vulnerability Scoring System (CVSS) calculates severity based on exploitability and impact.",
    "remediation": "Review the recommendation field for step-by-step guidance to patch this vulnerability.",
    "xss": "Cross-Site Scripting allows attackers to inject malicious client-side scripts into web pages.",
    "sqli": "SQL Injection occurs when untrusted user input is directly concatenated into database queries.",
    "idor": "Insecure Direct Object Reference occurs when an application exposes a reference to an internal implementation object.",
}


class FindingChatAssistant:
    """Assist users in understanding findings via LLM or Static FAQ."""

    def __init__(self, http: RobustHTTPClient | None = None) -> None:
        self.http = http or RobustHTTPClient()

    async def run(self, **kwargs: Any) -> list[dict[str, Any]]:
        """Module interface."""
        return []

    async def ask_question(
        self,
        finding: dict[str, Any],
        question: str,
        llm_endpoint: str | None = None,
    ) -> str:
        """Ask LLM or fallback to static FAQ about finding."""
        if llm_endpoint:
            try:
                payload = {
                    "model": "llama3",
                    "messages": [
                        {
                            "role": "system",
                            "content": (
                                "You are a security analyst assistant. Answer questions "
                                "concisely about this specific vulnerability finding."
                            ),
                        },
                        {
                            "role": "user",
                            "content": (
                                f"Finding: {finding.get('title')}\n"
                                f"Severity: {finding.get('severity')}\n"
                                f"Description: {finding.get('description')}\n"
                                f"Evidence: {finding.get('evidence')}\n\n"
                                f"Question: {question}"
                            ),
                        },
                    ],
                }
                resp = await self.http.request(
                    "POST",
                    llm_endpoint,
                    data=payload,
                    timeout=10,
                )
                body = resp.get("body", {})
                if isinstance(body, dict) and "message" in body:
                    return body["message"].get("content", "")
            except Exception as exc:
                logger.warning("LLM endpoint query failed, falling back to static FAQ: %s", exc)

        # Fallback to static FAQ analysis
        q_lower = question.lower()
        for key, answer in STATIC_FAQS.items():
            if key in q_lower:
                return f"[Static FAQ] {answer}"

        if "why" in q_lower:
            return (
                f"[Static FAQ] This issue was flagged as {finding.get('severity', 'info')} "
                f"because of evidence: {finding.get('evidence', 'detected pattern')[:150]}"
            )
        if "fix" in q_lower or "how to" in q_lower:
            return f"[Static FAQ] Recommended Remediation: {finding.get('recommendation', 'Apply standard security patches.')}"

        return (
            "[Static FAQ] Configure a local LLM endpoint (e.g. Ollama at http://localhost:11434/api/chat) "
            "in the report settings to enable interactive AI-powered answers."
        )
