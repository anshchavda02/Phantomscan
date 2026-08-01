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
    # ── Vibe App / AI-Generated Application Attack Chains ────────────────
    {
        "name": "Supabase RLS Bypass → Full Database Compromise",
        "requires": {"supabase_rls_missing", "supabase_service_key"},
        "severity": "critical",
        "description": (
            "Exposed Supabase service_role key combined with missing RLS on "
            "tables allows complete database read/write/delete by any visitor."
        ),
        "attack_path": [
            "1. Extract service_role key from client-side JavaScript",
            "2. Use key to bypass ALL Row Level Security policies",
            "3. Read, modify, or delete any data in any table",
            "4. Manage user accounts, reset passwords, impersonate users",
        ],
    },
    {
        "name": "Firebase Test-Mode → Full Data Dump",
        "requires": {"firebase_no_auth", "firebase_public_write"},
        "severity": "critical",
        "description": (
            "Firebase Realtime Database in test mode (public read+write) "
            "allows any visitor to read all data and inject malicious records."
        ),
        "attack_path": [
            "1. Access Firebase RTDB via /.json endpoint (no auth)",
            "2. Dump entire database contents",
            "3. Write malicious data that other users will consume",
            "4. Potentially inject XSS payloads or modify business data",
        ],
    },
    {
        "name": "AI Proxy Abuse → Unlimited LLM Cost Drain",
        "requires": {"ai_proxy_unauth", "no_rate_limit"},
        "severity": "critical",
        "description": (
            "Unauthenticated AI proxy endpoint with no rate limiting allows "
            "unlimited API cost accumulation by any visitor."
        ),
        "attack_path": [
            "1. Discover unauthenticated /api/chat or /api/ai endpoint",
            "2. Script automated requests (no rate limit blocks them)",
            "3. Drain API credits — OpenAI/Anthropic charges accumulate",
            "4. Optionally extract system prompt via prompt injection",
        ],
    },
    {
        "name": "Slopsquatting → Supply Chain RCE",
        "requires": {"slopsquatting_target"},
        "severity": "critical",
        "description": (
            "AI-hallucinated package name creates a slopsquatting opportunity "
            "where an attacker can register the missing package with malicious "
            "code that executes on install."
        ),
        "attack_path": [
            "1. AI generates code referencing non-existent npm/PyPI package",
            "2. Attacker registers the hallucinated package name",
            "3. Developer runs npm install / pip install and executes malicious postinstall",
            "4. Attacker gains RCE on developer machine or CI/CD pipeline",
        ],
    },
    {
        "name": ".env Leak → Cloud Credential Compromise",
        "requires": {"env_file_exposed", "cloud_key_exposed"},
        "severity": "critical",
        "description": (
            "Exposed .env file contains cloud provider credentials (AWS, GCP, "
            "Azure) enabling full cloud infrastructure compromise."
        ),
        "attack_path": [
            "1. Access publicly served .env file",
            "2. Extract cloud credentials (AWS_SECRET_ACCESS_KEY, etc.)",
            "3. Use credentials to access cloud resources (S3, databases, etc.)",
            "4. Lateral movement through cloud environment",
        ],
    },
    {
        "name": "Prisma Error Leak + IDOR → Schema-Guided Data Theft",
        "requires": {"prisma_error_leak", "idor"},
        "severity": "high",
        "description": (
            "Prisma error messages leak table/column names, and IDOR allows "
            "accessing other users' records — combining schema knowledge with "
            "access bypass for targeted data exfiltration."
        ),
        "attack_path": [
            "1. Trigger Prisma errors to discover table/column schema",
            "2. Use IDOR to access other users' records",
            "3. Target specific sensitive columns discovered via errors",
        ],
    },
    {
        "name": "tRPC Unauth + Default Creds → Admin Takeover",
        "requires": {"trpc_unauth", "default_creds"},
        "severity": "critical",
        "description": (
            "Unauthenticated tRPC admin procedures combined with default "
            "credentials enables full administrative control."
        ),
        "attack_path": [
            "1. Discover unprotected tRPC admin procedures",
            "2. Use default credentials to authenticate as admin",
            "3. Full admin takeover with unrestricted API access",
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
    # ── Vibe App / AI-Generated Application Tags ─────────────────────
    "ai-supabase-rls": "supabase_rls_missing",
    "supabase table": "supabase_rls_missing",
    "supabase-rls": "supabase_rls_missing",
    "service role key": "supabase_service_key",
    "service_role": "supabase_service_key",
    "sb_secret_": "supabase_service_key",
    "ai-firebase-no-auth": "firebase_no_auth",
    "firebase publicly readable": "firebase_no_auth",
    "ai-firebase-rtdb-public-read": "firebase_no_auth",
    "firebase publicly writable": "firebase_public_write",
    "ai-firebase-rtdb-public-write": "firebase_public_write",
    "ai-proxy-unauth": "ai_proxy_unauth",
    "unauthenticated ai proxy": "ai_proxy_unauth",
    "slopsquatting": "slopsquatting_target",
    "does not exist on npm": "slopsquatting_target",
    "does not exist on pypi": "slopsquatting_target",
    "ai-env-file-exposed": "env_file_exposed",
    ".env file": "env_file_exposed",
    "aws access key": "cloud_key_exposed",
    "ai-key-exposed": "cloud_key_exposed",
    "prisma error": "prisma_error_leak",
    "ai-prisma-error-leak": "prisma_error_leak",
    "trpc procedure": "trpc_unauth",
    "ai-trpc-unauth": "trpc_unauth",
    "default credentials": "default_creds",
    "ai-default-creds": "default_creds",
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
                matched_titles = []
                for req_tag in required:
                    for f in findings:
                        if self._finding_matches_single_tag(f, req_tag):
                            t = f.get("title", "")
                            if t and t not in matched_titles:
                                matched_titles.append(t)
                                break
                chain_findings.append({
                    "id": f"CHAIN-{chain['name'].upper().replace(' ', '-')[:40]}",
                    "title": f"Attack Chain: {chain['name']}",
                    "severity": chain["severity"],
                    "confidence": "medium",
                    "category": "vuln-chain",
                    "target": "",
                    "evidence": (
                        f"Component findings: {', '.join(matched_titles[:5])}\n\n"
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
    def _finding_matches_single_tag(
        finding: dict[str, Any], target_tag: str
    ) -> bool:
        title = str(finding.get("title", "")).lower()
        fid = str(finding.get("id", "")).lower()
        combined = f"{title} {fid}"
        for keyword, tag in _FINDING_TAG_MAP.items():
            if keyword in combined and tag == target_tag:
                return True
        return False
