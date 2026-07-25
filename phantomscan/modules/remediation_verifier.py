"""Module 12 — One-Click Remediation Verification.

Provides token-based verify links for findings and runs a lightweight local HTTP server (aiohttp)
to allow users to re-test individual findings instantly.
"""

from __future__ import annotations

import hmac
import hashlib
import json
import logging
from dataclasses import dataclass
from typing import Any

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)

SECRET_KEY = b"phantomscan_verifier_secret_key_v2"


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

    @staticmethod
    def generate_token(finding_id: str) -> str:
        """Generate HMAC-SHA256 verification token for a finding."""
        return hmac.new(SECRET_KEY, finding_id.encode(), hashlib.sha256).hexdigest()[:16]

    @staticmethod
    def validate_token(finding_id: str, token: str) -> bool:
        """Validate HMAC token for finding verification."""
        expected = hmac.new(SECRET_KEY, finding_id.encode(), hashlib.sha256).hexdigest()[:16]
        return hmac.compare_digest(expected, token)

    def generate_verify_link(self, finding_id: str, base_url: str = "http://localhost:8420") -> str:
        """Generate full verification URL."""
        token = self.generate_token(finding_id)
        return f"{base_url}/verify?finding={finding_id}&token={token}"

    async def verify_finding(self, finding: dict[str, Any], target: str) -> VerifyResult:
        """Re-run a check against target to see if finding is resolved."""
        if not self.http:
            self.http = RobustHTTPClient()

        # Simple verification attempt: re-fetch affected endpoint
        try:
            resp = await self.http.request("GET", target, timeout=8)
            status = resp.get("status", 0)
            body = resp.get("body", "")
            if isinstance(body, bytes):
                body = body.decode("utf-8", errors="ignore")

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

            if not self.validate_token(finding_id, token):
                return web.Response(status=403, text="Invalid or expired verification token.")

            res = await self.verify_finding({"id": finding_id}, target)

            color = "#10b981" if res.status == "RESOLVED" else "#ef4444"
            html = f"""<!DOCTYPE html>
<html>
<head><title>PhantomScan Verification</title></head>
<body style="font-family:sans-serif; background:#070710; color:#e2e2f8; padding:40px; text-align:center;">
    <div style="max-width:500px; margin:auto; background:#111124; border:1px solid #1e1e3f; border-radius:12px; padding:30px;">
        <h1 style="color:{color};">{res.status}</h1>
        <p>{res.message}</p>
        {f'<pre style="text-align:left; background:#0c0c1a; padding:10px; border-radius:6px;">{res.evidence}</pre>' if res.evidence else ''}
    </div>
</body>
</html>"""
            return web.Response(text=html, content_type="text/html")

        app = web.Application()
        app.add_routes(routes)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, host, port)
        logger.info("Started Remediation Verification server on http://%s:%d", host, port)
        await site.start()
