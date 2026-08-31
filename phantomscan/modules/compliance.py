"""Module 16 — Compliance-Ready Report Generator.

Maps findings to OWASP Top 10 (2021), PCI DSS v4.0, and NIST 800-53
controls, generating compliance status reports.
"""

from __future__ import annotations

import logging
from typing import Any

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)

# ── Compliance Mappings ──────────────────────────────────────────────────────

OWASP_TOP10_2021 = {
    "A01:2021": {
        "name": "Broken Access Control",
        "keywords": [
            "idor", "bola", "access control", "privilege escalation", "authorization",
            "mass assignment", "path traversal", "path-traversal", "lfi", "rfi",
            "directory traversal", "cors misconfiguration", "csrf",
        ],
    },
    "A02:2021": {
        "name": "Cryptographic Failures",
        "keywords": [
            "ssl 2.0", "ssl 3.0", "tls 1.0", "tls 1.1", "weak cipher",
            "expired certificate", "self-signed certificate", "plaintext credential",
            "unencrypted transmission", "cleartext http", "weak secret",
            "broken crypto", "weak hash", "md5", "sha1",
        ],
    },
    "A03:2021": {
        "name": "Injection",
        "keywords": [
            "sql injection", "sqli", "cross-site scripting", "xss", "command injection",
            "ssti", "prototype pollution", "graphql injection", "nosql injection",
            "ldap injection", "code injection", "rce",
        ],
    },
    "A04:2021": {
        "name": "Insecure Design",
        "keywords": [
            "business logic", "race condition", "workflow bypass", "rate limit bypass",
            "design flaw", "anti-automation",
        ],
    },
    "A05:2021": {
        "name": "Security Misconfiguration",
        "keywords": [
            "security header", "header", "directory listing", "debug mode",
            "default configuration", "introspection", "misconfiguration", "phpinfo",
            "server-status", "stack trace",
        ],
    },
    "A06:2021": {
        "name": "Vulnerable Components",
        "keywords": [
            "outdated library", "vulnerable component", "supply chain", "cve-",
            "subresource integrity", "outdated dependency", "known vulnerability",
        ],
    },
    "A07:2021": {
        "name": "Auth Failures",
        "keywords": [
            "authentication failure", "auth failure", "login bypass", "session fixation",
            "brute force", "credential leak", "hardcoded password", "missing mfa",
            "broken authentication", "weak jwt",
        ],
    },
    "A08:2021": {
        "name": "Software and Data Integrity",
        "keywords": [
            "insecure deserialization", "prototype pollution", "dependency confusion",
            "slopsquatting", "data integrity", "cicd vulnerability", "untrusted dependency",
        ],
    },
    "A09:2021": {
        "name": "Logging and Monitoring",
        "keywords": [
            "insufficient logging", "log injection", "missing audit log",
            "unlogged action", "monitoring failure",
        ],
    },
    "A10:2021": {
        "name": "SSRF",
        "keywords": [
            "ssrf", "server-side request forgery", "cloud metadata exposure",
            "internal metadata",
        ],
    },
}

PCIDSS_V4 = {
    "1.3": {
        "name": "Network Security Controls",
        "keywords": [
            "firewall bypass", "exposed port", "insecure port", "insecure service",
            "exposed telnet", "exposed rdp", "exposed smb", "exposed ftp",
            "network exposure", "unauthorized service",
        ],
    },
    "2.2": {
        "name": "System Hardening",
        "keywords": [
            "default credentials", "default password", "server version leak",
            "security header", "header", "misconfiguration", "debug mode",
            "directory listing", "unhardened", "phpinfo", "server-status",
        ],
    },
    "3.4": {
        "name": "Protect Stored Data",
        "keywords": [
            "unencrypted data", "cleartext credential", "plaintext password",
            "exposed secret", "hardcoded secret", "api key exposed",
            "private key exposed", "sensitive data exposure", "cardholder data",
        ],
    },
    "4.1": {
        "name": "Encrypt Transmissions",
        "keywords": [
            "cleartext http", "unencrypted transmission", "ssl 2.0", "ssl 3.0",
            "tls 1.0", "tls 1.1", "weak cipher", "expired certificate",
            "self-signed certificate", "missing hsts", "mixed content",
            "plaintext transmission", "insecure transport",
        ],
    },
    "6.2": {
        "name": "Secure Development",
        "keywords": [
            "sql injection", "sqli", "cross-site scripting", "xss", "command injection",
            "ssti", "cve-", "vulnerable dependency", "outdated library",
            "known vulnerability",
        ],
    },
    "6.4": {
        "name": "Public Application Protection",
        "keywords": [
            "sql injection", "sqli", "cross-site scripting", "xss", "command injection",
            "csrf", "path traversal", "ssrf", "waf bypass", "injection vulnerability",
        ],
    },
    "8.3": {
        "name": "Strong Authentication",
        "keywords": [
            "missing mfa", "weak password", "brute force", "credential stuffing",
            "session fixation", "hardcoded password", "broken authentication",
            "auth bypass",
        ],
    },
    "11.3": {
        "name": "Vulnerability Remediation",
        "keywords": [
            "critical vulnerability", "high severity vulnerability",
            "unpatched vulnerability", "unremediated cve",
        ],
    },
}

NIST_80053 = {
    "AC-3": {
        "name": "Access Enforcement",
        "keywords": [
            "broken access control", "idor", "bola", "privilege escalation",
            "unauthorized access", "authorization bypass", "path traversal",
            "insecure direct object", "mass assignment",
        ],
    },
    "AU-2": {
        "name": "Audit Events",
        "keywords": [
            "insufficient logging", "missing audit log", "log injection",
            "unlogged access", "audit trail missing",
        ],
    },
    "IA-5": {
        "name": "Authenticator Management",
        "keywords": [
            "weak password", "hardcoded credentials", "hardcoded secret",
            "default credentials", "weak jwt", "session token leak",
            "broken authentication",
        ],
    },
    "SC-8": {
        "name": "Transmission Confidentiality",
        "keywords": [
            "cleartext transmission", "unencrypted traffic", "missing hsts",
            "weak tls", "weak ssl", "tls 1.0", "tls 1.1", "deprecated ssl",
            "plaintext transmission", "mixed content",
        ],
    },
    "SC-13": {
        "name": "Cryptographic Protection",
        "keywords": [
            "weak cipher", "md5 hash", "sha1 certificate", "weak cryptography",
            "insecure encryption", "broken crypto", "weak secret",
        ],
    },
    "SI-10": {
        "name": "Information Input Validation",
        "keywords": [
            "sql injection", "sqli", "cross-site scripting", "xss", "command injection",
            "input validation failure", "prototype pollution", "ssti",
            "nosql injection",
        ],
    },
    "SA-11": {
        "name": "Developer Security Testing",
        "keywords": [
            "vulnerable component", "outdated package", "known cve", "cve-",
            "unpatched dependency", "supply chain risk",
        ],
    },
}


class ComplianceReporter:
    """Map findings to compliance frameworks and report status."""

    def __init__(self, http: RobustHTTPClient | None = None) -> None:
        pass  # No HTTP needed — pure analysis

    async def run(
        self,
        base_url: str,
        observations: list[dict[str, Any]],
        findings: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        """Generate compliance-mapped findings."""
        if not findings:
            return []
        return self.generate_compliance_report(findings, base_url)

    def generate_compliance_report(
        self, findings: list[dict[str, Any]], target: str
    ) -> list[dict[str, Any]]:
        compliance_findings: list[dict[str, Any]] = []

        # OWASP Top 10
        owasp_results = self._map_to_framework(
            findings, OWASP_TOP10_2021, "OWASP Top 10 (2021)"
        )
        if owasp_results:
            compliance_findings.append({
                "id": "COMPLIANCE-OWASP-TOP10",
                "title": "OWASP Top 10 (2021) Compliance Status",
                "severity": "info",
                "confidence": "high",
                "category": "compliance",
                "target": target,
                "evidence": self._format_compliance(owasp_results, "OWASP Top 10"),
                "recommendation": (
                    "Address all OWASP Top 10 categories with violations. "
                    "See https://owasp.org/Top10/ for remediation guidance."
                ),
                "references": ["https://owasp.org/Top10/"],
            })

        # PCI DSS
        pci_results = self._map_to_framework(
            findings, PCIDSS_V4, "PCI DSS v4.0"
        )
        if pci_results:
            compliance_findings.append({
                "id": "COMPLIANCE-PCIDSS",
                "title": "PCI DSS v4.0 Compliance Status",
                "severity": "info",
                "confidence": "high",
                "category": "compliance",
                "target": target,
                "evidence": self._format_compliance(pci_results, "PCI DSS v4.0"),
                "recommendation": (
                    "Remediate findings mapped to PCI DSS requirements "
                    "before the next assessment cycle."
                ),
            })

        # NIST 800-53
        nist_results = self._map_to_framework(
            findings, NIST_80053, "NIST 800-53"
        )
        if nist_results:
            compliance_findings.append({
                "id": "COMPLIANCE-NIST",
                "title": "NIST 800-53 Control Mapping",
                "severity": "info",
                "confidence": "high",
                "category": "compliance",
                "target": target,
                "evidence": self._format_compliance(nist_results, "NIST 800-53"),
                "recommendation": (
                    "Review NIST 800-53 control implementations "
                    "for identified gaps."
                ),
            })

        return compliance_findings

    def _map_to_framework(
        self,
        findings: list[dict[str, Any]],
        framework: dict[str, dict[str, Any]],
        framework_name: str,
    ) -> dict[str, dict[str, Any]]:
        # Filter out meta-reporting findings, compliance status findings, and suppressed/FP items
        eval_findings = [
            f for f in findings
            if str(f.get("category", "")).lower() not in ("reporting", "compliance")
            and not str(f.get("id", "")).upper().startswith((
                "COMPLIANCE-", "AI-NARRATIVE-", "ATTACK-PATH-", "VULN-CHAIN-",
                "SCAN-STATUS-", "PORT-SCAN-", "SSL-INFO-", "EXCLUDED-"
            ))
            and not f.get("suppression_reason")
            and not f.get("false_positive")
            and not f.get("suppressed")
            and str(f.get("severity", "")).lower() in ("critical", "high", "medium", "low")
        ]

        results: dict[str, dict[str, Any]] = {}
        for control_id, control in framework.items():
            matching = []
            for f in eval_findings:
                text = (
                    f"{f.get('title', '')} {f.get('category', '')} "
                    f"{f.get('id', '')} {f.get('cwe', '')} {f.get('owasp_category', '')} "
                    f"{f.get('recommendation', '')}"
                ).lower()
                if any(kw in text for kw in control["keywords"]):
                    matching.append(f)
            results[control_id] = {
                "name": control["name"],
                "status": "FAIL" if matching else "PASS",
                "finding_count": len(matching),
                "findings": [f.get("title", "") for f in matching[:5]],
            }
        return results

    @staticmethod
    def _format_compliance(
        results: dict[str, dict[str, Any]], framework: str
    ) -> str:
        lines = [f"{framework} Compliance Assessment:\n"]
        pass_count = sum(1 for r in results.values() if r["status"] == "PASS")
        fail_count = sum(1 for r in results.values() if r["status"] == "FAIL")
        total = len(results)
        lines.append(f"  PASS: {pass_count}/{total}  FAIL: {fail_count}/{total}\n")

        for control_id, result in sorted(results.items()):
            icon = "✓" if result["status"] == "PASS" else "✗"
            line = f"  {icon} {control_id}: {result['name']} — {result['status']}"
            if result["finding_count"]:
                line += f" ({result['finding_count']} findings)"
            lines.append(line)
        return "\n".join(lines)
