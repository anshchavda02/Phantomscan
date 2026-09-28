"""Module 12 — One-Click Remediation Verification.

Provides token-based verify links for findings and runs a lightweight local HTTP server (aiohttp)
to allow users to re-test individual findings instantly.
"""

from __future__ import annotations

import html
import hmac
import hashlib
import logging
import os
import secrets
from dataclasses import dataclass
from typing import Any
import urllib.parse

from phantomscan.http_client import RobustHTTPClient
from phantomscan.scope import ScopePolicy, normalize_target

logger = logging.getLogger(__name__)

_ENV_KEY = os.environ.get("PHANTOMSCAN_VERIFIER_SECRET")
SECRET_KEY: bytes = _ENV_KEY.encode() if _ENV_KEY else secrets.token_bytes(32)


@dataclass
class VerifyResult:
    status: str  # "RESOLVED" or "STILL_PRESENT"
    message: str
    evidence: str = ""


class RemediationVerifier:
    """Generate verification links and re-test specific findings."""

    def __init__(self, http: RobustHTTPClient | None = None) -> None:
        self.http = http

    async def run(self, **kwargs: Any) -> list[dict[str, Any]]:
        """Module interface."""
        return []

    @classmethod
    def get_secret_key(cls) -> bytes:
        return SECRET_KEY

    @classmethod
    def generate_token(cls, finding_id: str, target: str | None = None) -> str:
        """Generate HMAC-SHA256 verification token for a finding and target."""
        msg = f"{finding_id}:{target or ''}".encode()
        return hmac.new(cls.get_secret_key(), msg, hashlib.sha256).hexdigest()[:16]

    @classmethod
    def validate_token(cls, finding_id: str, token: str, target: str | None = None) -> bool:
        """Validate HMAC token for finding verification."""
        expected = cls.generate_token(finding_id, target)
        if hmac.compare_digest(expected, token):
            return True
        if target:
            fallback = cls.generate_token(finding_id, None)
            return hmac.compare_digest(fallback, token)
        return False

    def generate_verify_link(self, finding_id: str, target: str | None = None, base_url: str = "http://localhost:8420") -> str:
        """Generate full verification URL."""
        token = self.generate_token(finding_id, target)
        target_param = f"&target={urllib.parse.quote(target)}" if target else ""
        return f"{base_url}/verify?finding={urllib.parse.quote(finding_id)}&token={token}{target_param}"

    async def verify_finding(self, finding: dict[str, Any], target: str) -> VerifyResult:
        """Re-run a check against target to see if finding is resolved."""
        if not self.http:
            try:
                norm = normalize_target(target)
                policy = ScopePolicy(target=norm, allow_local=norm.is_local)
                self.http = RobustHTTPClient(scope_policy=policy)
            except Exception:
                self.http = RobustHTTPClient()

        # Verification attempt: re-fetch affected endpoint
        try:
            if hasattr(self.http, "get"):
                resp = await self.http.get(target, retries=1)
            else:
                resp = await self.http.request("GET", target, timeout=8)
            body = resp.text() if hasattr(resp, "text") and callable(resp.text) else str(getattr(resp, "body", ""))

            # Check if evidence snippet still exists in response
            snippet = finding.get("evidence", "").split("\n")[0][:40]
            if snippet and snippet in body:
                return VerifyResult(
                    status="STILL_PRESENT",
                    message="Issue is still present. Evidence match found in response.",
                    evidence=snippet,
                )
            else:
                return VerifyResult(
                    status="RESOLVED",
                    message="Issue appears to be resolved! Evidence snippet no longer detected.",
                )
        except Exception as exc:
            return VerifyResult(
                status="STILL_PRESENT",
                message=f"Could not verify fix: connection error ({exc})",
            )


    async def start_server(self, host: str = "127.0.0.1", port: int = 8420) -> None:
        """Start lightweight aiohttp verification server."""
        try:
            from aiohttp import web
        except ImportError:
            logger.error("aiohttp is required for the verification server.")
            return

        routes = web.RouteTableDef()

        @routes.get("/verify")
        async def handle_verify(request: web.Request) -> web.Response:
            finding_id = request.query.get("finding", "")
            token = request.query.get("token", "")
            target = request.query.get("target", "http://localhost")

            if not self.validate_token(finding_id, token, target=target):
                return web.Response(status=403, text="Invalid or expired verification token.")

            res = await self.verify_finding({"id": finding_id}, target)

            escaped_status = html.escape(str(res.status))
            escaped_msg = html.escape(str(res.message))
            escaped_evidence = html.escape(str(res.evidence)) if res.evidence else ""
            color = "#10b981" if res.status == "RESOLVED" else "#ef4444"
            html_content = f"""<!DOCTYPE html>
<html>
<head><title>PhantomScan Verification</title></head>
<body style="font-family:sans-serif; background:#070710; color:#e2e2f8; padding:40px; text-align:center;">
    <div style="max-width:500px; margin:auto; background:#111124; border:1px solid #1e1e3f; border-radius:12px; padding:30px;">
        <h1 style="color:{color};">{escaped_status}</h1>
        <p>{escaped_msg}</p>
        {f'<pre style="text-align:left; background:#0c0c1a; padding:10px; border-radius:6px; overflow-x:auto;">{escaped_evidence}</pre>' if escaped_evidence else ''}
    </div>
</body>
</html>"""
            return web.Response(text=html_content, content_type="text/html")

        app = web.Application()
        app.add_routes(routes)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, host, port)
        logger.info("Started Remediation Verification server on http://%s:%d", host, port)
        await site.start()
