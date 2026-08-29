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
    "A01:2021": {"name": "Broken Access Control", "keywords": [
        "idor", "bola", "access control", "privilege", "authorization",
        "mass assignment", "session", "csrf", "cors", "path traversal",
        "path-traversal", "lfi", "directory traversal",
    ]},
    "A02:2021": {"name": "Cryptographic Failures", "keywords": [
        "ssl", "tls", "certificate", "cipher", "encryption", "jwt",
        "weak secret", "crypto", "hash", "md5", "sha1",
    ]},
    "A03:2021": {"name": "Injection", "keywords": [
        "sql injection", "sqli", "xss", "command injection", "ssti",
        "injection", "prototype pollution", "graphql injection",
    ]},
    "A04:2021": {"name": "Insecure Design", "keywords": [
        "business logic", "race condition", "workflow", "bypass",
        "design flaw",
    ]},
    "A05:2021": {"name": "Security Misconfiguration", "keywords": [
        "header", "cors", "directory listing", "debug", "default",
        "introspection", "misconfiguration", "phpinfo", "server-status",
    ]},
    "A06:2021": {"name": "Vulnerable Components", "keywords": [
        "outdated", "library", "supply chain", "cve", "sri",
        "third-party", "component", "dependency",
    ]},
    "A07:2021": {"name": "Auth Failures", "keywords": [
        "authentication", "login", "session fixation", "brute force",
        "credential", "password", "mfa", "oauth", "enumeration",
    ]},
    "A08:2021": {"name": "Software and Data Integrity", "keywords": [
        "integrity", "sri", "deserialization", "prototype pollution",
        "supply chain", "cicd",
    ]},
    "A09:2021": {"name": "Logging and Monitoring", "keywords": [
        "logging", "monitoring", "audit", "alerting",
    ]},
    "A10:2021": {"name": "SSRF", "keywords": [
        "ssrf", "server-side request", "metadata", "cloud",
        "internal", "request forgery",
    ]},
}

PCIDSS_V4 = {
    "1.3": {"name": "Network Security Controls", "keywords": [
        "firewall", "network", "port", "exposure", "service",
    ]},
    "2.2": {"name": "System Hardening", "keywords": [
        "default", "misconfiguration", "hardening", "server version",
        "header", "debug",
    ]},
    "3.4": {"name": "Protect Stored Data", "keywords": [
        "encryption", "ssl", "tls", "data exposure", "sensitive",
    ]},
    "4.1": {"name": "Encrypt Transmissions", "keywords": [
        "ssl", "tls", "https", "certificate", "mixed content", "http",
    ]},
    "6.2": {"name": "Secure Development", "keywords": [
        "injection", "xss", "sqli", "vulnerability", "code",
    ]},
    "6.4": {"name": "Public Application Protection", "keywords": [
        "waf", "attack", "xss", "injection", "csrf",
    ]},
    "8.3": {"name": "Strong Authentication", "keywords": [
        "authentication", "password", "mfa", "session", "credential",
    ]},
    "11.3": {"name": "Vulnerability Scanning", "keywords": [
        "scan", "vulnerability", "assessment", "testing",
    ]},
}

NIST_80053 = {
    "AC-3": {"name": "Access Enforcement", "keywords": [
        "access control", "authorization", "idor", "bola", "privilege",
    ]},
    "AU-2": {"name": "Audit Events", "keywords": [
        "logging", "monitoring", "audit",
    ]},
    "IA-5": {"name": "Authenticator Management", "keywords": [
        "authentication", "password", "credential", "jwt", "token",
    ]},
    "SC-8": {"name": "Transmission Confidentiality", "keywords": [
        "ssl", "tls", "encryption", "https", "certificate",
    ]},
    "SC-13": {"name": "Cryptographic Protection", "keywords": [
        "crypto", "cipher", "hash", "encryption", "jwt", "weak secret",
    ]},
    "SI-10": {"name": "Information Input Validation", "keywords": [
        "injection", "xss", "sqli", "input validation", "sanitize",
    ]},
    "SA-11": {"name": "Developer Security Testing", "keywords": [
        "vulnerability", "testing", "scan", "assessment",
    ]},
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
        results: dict[str, dict[str, Any]] = {}
        for control_id, control in framework.items():
            matching = []
            for f in findings:
                text = (
                    f"{f.get('title', '')} {f.get('category', '')} "
                    f"{f.get('evidence', '')} {f.get('id', '')}"
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
