"""Module 18 — AI-Powered Narrative Reporting.

Generates executive summaries, remediation narratives, and risk prioritization
using a rule-based Natural Language Generation (NLG) engine. No external LLM
API is required, keeping PhantomScan self-contained.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# ── Templates ────────────────────────────────────────────────────────────────

_INTRO_TEMPLATE = (
    "The PhantomScan Advanced Security assessment of {target} identified "
    "{total} vulnerabilities. The risk profile is {risk_level}, driven "
    "primarily by {critical_count} critical and {high_count} high severity findings."
)

_NO_FINDINGS_TEMPLATE = (
    "The PhantomScan Advanced Security assessment of {target} identified "
    "0 vulnerabilities. The application demonstrates a strong baseline security "
    "posture against automated testing methodologies."
)

_REMEDIATION_NARRATIVES = {
    "injection": (
        "Injection vulnerabilities (SQLi, XSS, Command Injection) were identified. "
        "These represent fundamental flaws in data-flow trust boundaries. "
        "Remediation must focus on strict input validation, parameterized queries, "
        "and context-aware output encoding across the entire application stack."
    ),
    "auth": (
        "Authentication or session management weaknesses were detected. "
        "These flaws can allow attackers to compromise passwords, keys, or "
        "session tokens, assuming the identities of legitimate users. "
        "Implement robust credential management, enforce session timeouts, "
        "and mandate multi-factor authentication for sensitive access."
    ),
    "business-logic": (
        "Business logic flaws were discovered. These are high-impact issues "
        "where the application functions as designed, but the design itself "
        "permits abuse (e.g., mass assignment, negative values). "
        "Remediation requires implementing strict state-machine controls and "
        "server-side validation of all business constraints, rather than "
        "relying on client-side controls."
    ),
    "idor": (
        "Insecure Direct Object Reference (BOLA/IDOR) vulnerabilities were found. "
        "These allow attackers to access or modify data belonging to other users "
        "by manipulating identifiers. Ensure that every data access request "
        "includes a server-side check verifying the authenticated user's "
        "authorization to access that specific object ID."
    ),
    "cloud": (
        "Cloud-specific misconfigurations (e.g., exposed metadata or public buckets) "
        "were identified. These issues frequently lead to total environment "
        "compromise. Enforce IMDSv2 (if AWS), restrict metadata access via "
        "network policies, and implement least-privilege IAM controls."
    ),
    "supply-chain": (
        "Supply chain or third-party risks (e.g., hardcoded secrets, missing SRI, "
        "outdated libraries) were detected. Revoke and rotate any exposed secrets "
        "immediately. Implement Subresource Integrity for all CDN assets and "
        "establish a regular dependency patching cadence."
    ),
}


class AINarrativeReporter:
    """Generate narrative executive summaries using rule-based NLG."""

    def __init__(self, http: Any = None) -> None:
        pass  # Pure analysis module

    async def run(
        self,
        base_url: str,
        observations: list[dict[str, Any]],
        findings: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        if findings is None:
            findings = []

        target = base_url.rstrip("/")
        narrative = self.generate_narrative(findings, target)

        return [{
            "id": "AI-NARRATIVE-SUMMARY",
            "title": "Executive Summary & Remediation Narrative",
            "severity": "info",
            "confidence": "high",
            "category": "reporting",
            "target": target,
            "evidence": narrative,
            "recommendation": "Distribute this narrative to technical leadership.",
        }]

    def generate_narrative(self, findings: list[dict[str, Any]], target: str) -> str:
        if not findings:
            return _NO_FINDINGS_TEMPLATE.format(target=target)

        critical_count = sum(1 for f in findings if f.get("severity") == "critical")
        high_count = sum(1 for f in findings if f.get("severity") == "high")
        med_count = sum(1 for f in findings if f.get("severity") == "medium")

        if critical_count > 0:
            risk_level = "CRITICAL"
        elif high_count > 0:
            risk_level = "HIGH"
        elif med_count > 0:
            risk_level = "MODERATE"
        else:
            risk_level = "LOW"

        # 1. Introduction
        intro = _INTRO_TEMPLATE.format(
            target=target,
            total=len(findings),
            risk_level=risk_level,
            critical_count=critical_count,
            high_count=high_count,
        )

        # 2. Risk Prioritization
        categories = {str(f.get("category", "other")): 0 for f in findings}
        for f in findings:
            categories[str(f.get("category", "other"))] += 1

        top_categories = sorted(categories.items(), key=lambda x: x[1], reverse=True)[:3]
        prioritization = (
            "The primary areas of concern, ranked by finding density, are: " +
            ", ".join([f"{cat} ({count})" for cat, count in top_categories]) + "."
        )

        # 3. Remediation Narrative
        remediation_paragraphs = []
        for cat, _ in top_categories:
            if cat in _REMEDIATION_NARRATIVES:
                remediation_paragraphs.append(_REMEDIATION_NARRATIVES[cat])

        if not remediation_paragraphs:
            remediation_paragraphs.append(
                "Address critical and high severity findings immediately. "
                "Establish a routine vulnerability management process to ensure "
                "continuous security posture improvement."
            )

        return f"{intro}\n\n{prioritization}\n\n" + "\n\n".join(remediation_paragraphs)
