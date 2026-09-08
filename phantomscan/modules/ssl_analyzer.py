"""SSL/TLS configuration and certificate analyzer.

Analyzes SSL/TLS handshake results, certificate expiration, self-signed certificates,
and deprecated protocol versions (SSLv2, SSLv3, TLSv1.0, TLSv1.1).
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import socket
import ssl
from typing import Any
from urllib.parse import urlparse

from phantomscan.models import Finding


class SSLAnalyzer:
    """Analyzer for SSL/TLS certificates and protocol configurations."""

    def __init__(self, http: Any = None) -> None:
        self.http = http

    DEPRECATED_PROTOCOLS: dict[str, tuple[str, str, str]] = {
        "sslv2": ("SSLv2", "critical", "SSLv2 is obsolete, insecure, and vulnerable to DROWN attack."),
        "sslv3": ("SSLv3", "high", "SSLv3 is vulnerable to POODLE attack."),
        "tlsv1": ("TLSv1.0", "medium", "TLSv1.0 lacks modern cipher suites and is deprecated by RFC 8996."),
        "tlsv1.0": ("TLSv1.0", "medium", "TLSv1.0 lacks modern cipher suites and is deprecated by RFC 8996."),
        "tlsv1.1": ("TLSv1.1", "medium", "TLSv1.1 lacks modern cipher suites and is deprecated by RFC 8996."),
    }

    WEAK_CIPHER_PATTERNS: list[str] = ["RC4", "3DES", "DES", "EXPORT", "NULL", "MD5"]

    def analyze(self, cert_data: dict[str, Any], host: str = "", port: int = 443) -> list[Finding]:
        """Analyze certificate dictionary or TLS inspection output and return findings."""
        findings: list[Finding] = []
        target = f"{host}:{port}" if host else f"https://target:{port}"

        # 1. Check protocol versions
        protocols = cert_data.get("protocols", [])
        if isinstance(protocols, list):
            for proto in protocols:
                proto_str = str(proto).lower().strip()
                if proto_str in self.DEPRECATED_PROTOCOLS:
                    name, sev, desc = self.DEPRECATED_PROTOCOLS[proto_str]
                    findings.append(Finding(
                        id=f"TLS-DEPRECATED-PROTOCOL-{name.replace('.', '_')}",
                        title=f"Deprecated TLS Protocol Enabled: {name}",
                        severity=sev,
                        confidence="high",
                        verification_method="passive_observation",
                        category="ssl",
                        target=target,
                        evidence=f"Server negotiated or supports {name}. {desc}",
                        recommendation=f"Disable {name} in server TLS configuration and enforce TLS 1.2 or TLS 1.3.",
                    ))

        # 2. Check certificate expiration
        expires_at = cert_data.get("expires_at") or cert_data.get("not_after")
        if expires_at:
            exp_dt = None
            if isinstance(expires_at, (int, float)):
                exp_dt = datetime.fromtimestamp(expires_at, tz=timezone.utc)
            elif isinstance(expires_at, str):
                try:
                    exp_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                except Exception:
                    try:
                        exp_dt = parsedate_to_datetime(expires_at)
                    except Exception:
                        pass
            if exp_dt:
                if exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_left = (exp_dt - now).days
                if days_left < 0:
                    findings.append(Finding(
                        id="SSL-CERT-EXPIRED",
                        title="SSL/TLS Certificate Has Expired",
                        severity="critical",
                        confidence="high",
                        verification_method="passive_observation",
                        category="ssl",
                        target=target,
                        evidence=f"Certificate expired on {exp_dt.isoformat()} ({abs(days_left)} days ago).",
                        recommendation="Renew and deploy a valid SSL certificate immediately to restore secure connections.",
                    ))
                elif days_left < 30:
                    findings.append(Finding(
                        id="SSL-CERT-EXPIRING-SOON",
                        title="SSL/TLS Certificate Expiring Soon (< 30 Days)",
                        severity="high",
                        confidence="high",
                        verification_method="passive_observation",
                        category="ssl",
                        target=target,
                        evidence=f"Certificate will expire on {exp_dt.isoformat()} ({days_left} days remaining).",
                        recommendation="Renew the certificate before it expires to prevent service disruption.",
                    ))

        # 3. Check self-signed certificate
        is_self_signed = cert_data.get("is_self_signed") or cert_data.get("self_signed")
        issuer = str(cert_data.get("issuer", "")).lower()
        subject = str(cert_data.get("subject", "")).lower()
        if is_self_signed or (issuer and subject and issuer == subject and "untrusted" in str(cert_data.get("trust_status", "")).lower()):
            findings.append(Finding(
                id="SSL-SELF-SIGNED-CERT",
                title="Self-Signed SSL/TLS Certificate",
                severity="high",
                confidence="high",
                verification_method="passive_observation",
                category="ssl",
                target=target,
                evidence=f"Certificate is self-signed (Issuer == Subject: {issuer or 'untrusted'}).",
                recommendation="Replace self-signed certificate with a certificate issued by a trusted Certificate Authority.",
            ))

        # 4. Check weak cipher suites
        ciphers = cert_data.get("ciphers", [])
        if isinstance(ciphers, list):
            weak_found = []
            for c in ciphers:
                c_str = str(c).upper()
                if any(w in c_str for w in self.WEAK_CIPHER_PATTERNS):
                    weak_found.append(c_str)
            if weak_found:
                findings.append(Finding(
                    id="TLS-WEAK-CIPHER-SUITES",
                    title="Weak TLS Cipher Suites Supported",
                    severity="medium",
                    confidence="high",
                    verification_method="passive_observation",
                    category="ssl",
                    target=target,
                    evidence=f"Weak ciphers detected:\n" + ", ".join(weak_found[:5]),
                    recommendation="Disable RC4, 3DES, DES, EXPORT, and NULL ciphers in web server TLS settings.",
                ))

        return findings

    async def run(
        self,
        base_url: str,
        observations: list[dict[str, Any]],
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        """DAG pipeline execution method for SSL/TLS inspection."""
        findings: list[Finding] = []
        parsed = urlparse(base_url)
        host = parsed.hostname or base_url
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # 1. Check existing observations for TLS/cert data
        cert_data: dict[str, Any] = {}
        for obs in observations:
            name = obs.get("name", "")
            val = obs.get("value")
            if name in ("tls_inspection", "tls_cert", "tls_result") and isinstance(val, dict):
                cert_data.update(val)
            elif name == "ssl_data" and isinstance(val, dict):
                cert_data.update(val)

        # 2. If no cert data in observations and target supports HTTPS, perform quick TLS inspection
        if not cert_data and (parsed.scheme == "https" or port in (443, 8443)):
            try:
                def _do_inspect() -> dict[str, Any]:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((host, port), timeout=3.0) as sock:
                        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                            cert = ssock.getpeercert(binary_form=False) or {}
                            cipher = ssock.cipher()
                            version = ssock.version()
                            return {
                                "expires_at": cert.get("notAfter"),
                                "not_after": cert.get("notAfter"),
                                "protocols": [version] if version else [],
                                "ciphers": [cipher[0]] if cipher else [],
                                "issuer": cert.get("issuer"),
                                "subject": cert.get("subject"),
                            }
                cert_data = await asyncio.to_thread(_do_inspect)
            except Exception:
                pass

        if cert_data:
            findings = self.analyze(cert_data, host=host, port=port)

        return [f.to_dict() if hasattr(f, "to_dict") else f for f in findings]

