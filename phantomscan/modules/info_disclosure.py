"""Information Disclosure Detector.

Detects internal IP addresses, stack traces, and verbose server/framework
version banners disclosed in HTTP response bodies and headers.
"""

from __future__ import annotations

import re
from typing import Any

from phantomscan.models import Finding


class InfoDisclosureDetector:
    """Detector for sensitive information leaks and verbose disclosures."""

    def __init__(self, http: Any = None) -> None:
        self.http = http

    INTERNAL_IP_REGEX = re.compile(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
        r"172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|"
        r"192\.168\.\d{1,3}\.\d{1,3})\b"
    )

    STACK_TRACE_PATTERNS = [
        (re.compile(r"Traceback \(most recent call last\):", re.I), "Python Traceback"),
        (re.compile(r"(?:java\.lang\.\w*Exception|at [a-zA-Z0-9_.]+\([A-Za-z0-9_.]+\.java:\d+\))"), "Java Stack Trace"),
        (re.compile(r"(?:Fatal error:|Uncaught exception '|Stack trace:\n#0 )", re.I), "PHP Fatal Error"),
        (re.compile(r"(?:System\.NullReferenceException|Microsoft\.AspNetCore\.|at System\.Web\.)"), ".NET Stack Trace"),
        (re.compile(r"(?:UnhandledPromiseRejection|at [a-zA-Z0-9_. ]+\([a-zA-Z0-9_/\\.-]+:\d+:\d+\))"), "Node.js Stack Trace"),
    ]

    VERSION_DISCLOSURE_REGEX = re.compile(r"/(\d+\.\d+(?:\.\d+)?)")

    def detect(self, body: str = "", headers: dict[str, str] | None = None, url: str = "") -> list[Finding]:
        """Detect internal IPs, stack traces, and version disclosures."""
        findings: list[Finding] = []
        hdrs = headers or {}
        lowered_headers = {k.lower(): str(v) for k, v in hdrs.items()}

        # 1. Stack trace detection in response body
        if body:
            for pattern, trace_name in self.STACK_TRACE_PATTERNS:
                m = pattern.search(body)
                if m:
                    snippet = body[max(0, m.start() - 50):min(len(body), m.end() + 200)].strip()
                    findings.append(Finding(
                        id=f"INFO-DISCLOSURE-STACK-TRACE-{trace_name.split()[0].upper()}",
                        title=f"Stack Trace Disclosed: {trace_name}",
                        severity="medium",
                        confidence="high",
                        verification_method="passive_observation",
                        category="info_disclosure",
                        target=url,
                        evidence=f"Detected pattern: {m.group(0)}\nSnippet:\n{snippet[:250]}",
                        recommendation="Disable verbose error messages in production. Configure custom error pages.",
                        cwe="CWE-209",
                    ))
                    break  # report one stack trace per response

        # 2. Internal IP address disclosure
        combined_text = f"{body[:20000]}\n" + "\n".join(f"{k}: {v}" for k, v in hdrs.items())
        ip_matches = list(set(self.INTERNAL_IP_REGEX.findall(combined_text)))
        real_internal_ips = [
            ip for ip in ip_matches
            if not ip.startswith("127.") and not ip.endswith(".0") and not ip.endswith(".255")
        ]
        if real_internal_ips:
            findings.append(Finding(
                id="INFO-DISCLOSURE-INTERNAL-IP",
                title="Internal IP Address Disclosure",
                severity="low",
                confidence="high",
                verification_method="passive_observation",
                category="info_disclosure",
                target=url,
                evidence="Internal IP addresses found in response:\n" + ", ".join(real_internal_ips[:10]),
                recommendation="Ensure reverse proxies, load balancers, and error handlers do not leak internal network addressing.",
                cwe="CWE-200",
            ))

        # 3. Server version disclosure
        server_val = lowered_headers.get("server", "")
        powered_by = lowered_headers.get("x-powered-by", "")
        disclosed_banners = []
        if server_val and self.VERSION_DISCLOSURE_REGEX.search(server_val):
            disclosed_banners.append(f"Server: {server_val}")
        if powered_by and self.VERSION_DISCLOSURE_REGEX.search(powered_by):
            disclosed_banners.append(f"X-Powered-By: {powered_by}")

        if disclosed_banners:
            findings.append(Finding(
                id="SERVER-VERSION-DISCLOSED",
                title="Web Server / Framework Version Disclosed",
                severity="low",
                confidence="high",
                verification_method="passive_observation",
                category="info_disclosure",
                target=url,
                evidence="\n".join(disclosed_banners),
                recommendation="Suppress detailed version banners in web server and application server configurations.",
                cwe="CWE-200",
            ))

        return findings

    async def run(
        self,
        base_url: str,
        observations: list[dict[str, Any]],
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        """DAG pipeline execution method for Information Disclosure detection."""
        body = ""
        headers: dict[str, str] = {}

        # 1. Extract body and headers from observations
        for obs in observations:
            name = obs.get("name", "")
            val = obs.get("value")
            if name in ("body_sample", "html_body", "response_body") and isinstance(val, str):
                if len(val) > len(body):
                    body = val
            elif name in ("headers", "http_headers", "response_headers") and isinstance(val, dict):
                headers.update({str(k): str(v) for k, v in val.items()})

        # 2. If no body and http client is available, fetch the base page
        if not body and self.http:
            try:
                res = await self.http.get(base_url)
                if res:
                    body = getattr(res, "body", "") or (res.text() if hasattr(res, "text") else "")
                    if hasattr(res, "headers") and isinstance(res.headers, dict):
                        headers.update({str(k): str(v) for k, v in res.headers.items()})
            except Exception:
                pass

        findings = self.detect(body=body, headers=headers, url=base_url)
        return [f.to_dict() if hasattr(f, "to_dict") else f for f in findings]

