"""Module 3 — Vulnerability Chain Engine.

Post-scan analysis that correlates individual findings into multi-step attack
chains.  Each chain represents a realistic attack path where combining
low/medium findings escalates to critical severity.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# ── Known chain definitions ──────────────────────────────────────────────────

CHAIN_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "Account Takeover via CSRF + XSS",
        "requires": {"csrf", "xss"},
        "severity": "critical",
        "description": (
            "Missing CSRF protection combined with reflected or stored XSS "
            "enables forced actions and session theft, leading to full "
            "account takeover."
        ),
        "attack_path": [
            "1. Attacker identifies XSS injection point",
            "2. Crafts payload that executes in victim's session",
            "3. CSRF-vulnerable form allows forced state-changing action",
            "4. Session cookie exfiltrated to attacker-controlled server",
        ],
    },
    {
        "name": "Full Data Enumeration via IDOR + No Rate Limit",
        "requires": {"idor", "no_rate_limit"},
        "severity": "critical",
        "description": (
            "IDOR combined with absent rate limiting enables automated "
            "enumeration of all user records in minutes."
        ),
        "attack_path": [
            "1. Discover IDOR in user/object endpoint",
            "2. Script sequential ID enumeration (no rate limit blocks it)",
            "3. Extract all user data at scale",
        ],
    },
    {
        "name": "SSRF to Cloud Credential Theft",
        "requires": {"ssrf", "cloud_metadata"},
        "severity": "critical",
        "description": (
            "Server-Side Request Forgery on a cloud-hosted application "
            "reaches the instance metadata service, leaking IAM credentials."
        ),
        "attack_path": [
            "1. Exploit SSRF with cloud metadata URL (169.254.169.254)",
            "2. Read IAM role temporary credentials",
            "3. Use stolen credentials for lateral movement in cloud environment",
        ],
    },
    {
        "name": "Admin Takeover via Stored XSS",
        "requires": {"xss_stored", "admin_panel"},
        "severity": "critical",
        "description": (
            "Stored XSS payload executes in an admin's browser context, "
            "enabling full administrative takeover."
        ),
        "attack_path": [
            "1. Store XSS payload in user-generated content",
            "2. Admin views content — JavaScript executes in admin session",
            "3. Admin session stolen or admin actions forced",
        ],
    },
    {
        "name": "Privilege Escalation via Mass Assignment + Weak Session",
        "requires": {"mass_assignment", "weak_session"},
        "severity": "critical",
        "description": (
            "Mass assignment allows injecting privilege fields while weak "
            "session management allows persistent access after escalation."
        ),
        "attack_path": [
            "1. Inject admin/privilege parameter via mass assignment",
            "2. Gain elevated access within current session",
            "3. Weak session controls allow persistent admin access",
        ],
    },
    {
        "name": "SQL Injection to Data Exfiltration",
        "requires": {"sqli", "verbose_error"},
        "severity": "critical",
        "description": (
            "SQL injection combined with verbose error messages reveals "
            "database schema and enables systematic data exfiltration."
        ),
        "attack_path": [
            "1. Discover SQL injection point",
            "2. Use verbose errors to map database schema",
            "3. Extract sensitive data via UNION-based or error-based SQLi",
        ],
    },
    {
        "name": "Authentication Bypass via JWT Weakness + Missing MFA",
        "requires": {"jwt_weakness", "no_mfa"},
        "severity": "critical",
        "description": (
            "JWT signing weakness allows token forgery. Combined with "
            "absent MFA, attacker achieves full authenticated access."
        ),
        "attack_path": [
            "1. Exploit JWT none-algorithm or weak secret",
            "2. Forge token for any user (no MFA blocks the forged session)",
            "3. Access any account without further verification",
        ],
    },
    {
        "name": "Open Redirect to Credential Phishing",
        "requires": {"open_redirect", "login_page"},
        "severity": "high",
        "description": (
            "Open redirect on authenticated domain combined with a login "
            "page enables convincing credential phishing attacks."
        ),
        "attack_path": [
            "1. Craft legitimate-looking URL using open redirect",
            "2. Redirect victim to attacker-controlled phishing page",
            "3. Victim enters credentials believing they are on the real site",
        ],
    },
]

# Mapping from common finding titles/IDs to chain tags
_FINDING_TAG_MAP: dict[str, str] = {
    "csrf": "csrf",
    "cross-site request forgery": "csrf",
    "xss": "xss",
    "cross-site scripting": "xss",
    "reflected xss": "xss",
    "stored xss": "xss_stored",
    "xss_stored": "xss_stored",
    "idor": "idor",
    "bola": "idor",
    "object reference": "idor",
    "rate limit": "no_rate_limit",
    "no rate limit": "no_rate_limit",
    "ssrf": "ssrf",
    "server-side request forgery": "ssrf",
    "cloud metadata": "cloud_metadata",
    "mass assignment": "mass_assignment",
    "session fixation": "weak_session",
    "session management": "weak_session",
    "cookie missing": "weak_session",
    "sql injection": "sqli",
    "sqli": "sqli",
    "blind sql": "sqli",
    "verbose error": "verbose_error",
    "error disclosure": "verbose_error",
    "stack trace": "verbose_error",
    "php error": "verbose_error",
    "jwt none": "jwt_weakness",
    "jwt weak": "jwt_weakness",
    "jwt algorithm": "jwt_weakness",
    "no mfa": "no_mfa",
    "multi-factor": "no_mfa",
    "open redirect": "open_redirect",
    "redirect": "open_redirect",
    "login": "login_page",
    "admin panel": "admin_panel",
    "admin": "admin_panel",
}


class VulnChainEngine:
    """Correlate individual findings into multi-step attack chains."""

    def __init__(self, http: RobustHTTPClient | None = None) -> None:
        # http client is not needed — this is a post-scan analysis module
        pass

    async def run(
        self,
        base_url: str,
        observations: list[dict[str, Any]],
        findings: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        """Analyze *findings* for vulnerability chains."""
        if not findings:
            return []
        return self.analyze_chains(findings)

    def analyze_chains(
        self, findings: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Return chain findings for any matched patterns."""
        tags = self._tag_findings(findings)
        chain_findings: list[dict[str, Any]] = []

        for chain in CHAIN_DEFINITIONS:
            required: set[str] = chain["requires"]
            if required.issubset(tags):
                component_titles = [
                    f.get("title", "")
                    for f in findings
                    if self._finding_matches_tags(f, required)
                ]
                chain_findings.append({
                    "id": f"CHAIN-{chain['name'].upper().replace(' ', '-')[:40]}",
                    "title": f"Attack Chain: {chain['name']}",
                    "severity": chain["severity"],
                    "confidence": "medium",
                    "category": "vuln-chain",
                    "target": "",
                    "evidence": (
                        f"Component findings: {', '.join(component_titles[:5])}\n\n"
                        f"Attack path:\n" +
                        "\n".join(chain["attack_path"])
                    ),
                    "recommendation": (
                        "This finding results from chaining multiple lower-severity "
                        "issues. Fix all component vulnerabilities — addressing only "
                        "one may not eliminate the attack path. "
                        f"Chain: {chain['description']}"
                    ),
                })

        return chain_findings

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _tag_findings(self, findings: list[dict[str, Any]]) -> set[str]:
        tags: set[str] = set()
        for f in findings:
            title = str(f.get("title", "")).lower()
            fid = str(f.get("id", "")).lower()
            combined = f"{title} {fid}"
            for keyword, tag in _FINDING_TAG_MAP.items():
                if keyword in combined:
                    tags.add(tag)
        return tags

    @staticmethod
    def _finding_matches_tags(
        finding: dict[str, Any], required_tags: set[str]
    ) -> bool:
        title = str(finding.get("title", "")).lower()
        fid = str(finding.get("id", "")).lower()
        combined = f"{title} {fid}"
        for keyword, tag in _FINDING_TAG_MAP.items():
            if keyword in combined and tag in required_tags:
                return True
        return False
