"""Unit tests for Phase 10: Authenticated Scanning, Session Management, JWT & Multi-Role Authorization."""

import base64
import json
import unittest
from unittest.mock import AsyncMock, MagicMock

import pytest

from phantomscan.http_client import HTTPResult, RobustHTTPClient
from phantomscan.modules.auth_session import AuthSession, AuthSessionManager
from phantomscan.modules.idor_detector import IDORDetector
from phantomscan.modules.jwt_oauth import JWTOAuthTester, _b64url_encode


def _create_jwt(header: dict, payload: dict, secret: str = "secret") -> str:
    import hashlib
    import hmac

    h_str = _b64url_encode(json.dumps(header).encode())
    p_str = _b64url_encode(json.dumps(payload).encode())
    sig = _b64url_encode(
        hmac.new(secret.encode(), f"{h_str}.{p_str}".encode(), hashlib.sha256).digest()
    )
    return f"{h_str}.{p_str}.{sig}"


class TestAuthSessionAndJWT(unittest.TestCase):
    def test_jwt_weak_secret_cracking(self):
        """Crack weak HMAC secrets."""
        token = _create_jwt({"alg": "HS256", "typ": "JWT"}, {"user": "alice", "role": "user"}, secret="secret")
        mock_http = MagicMock(spec=RobustHTTPClient)
        tester = JWTOAuthTester(http=mock_http)
        header, payload, _ = tester._decode_jwt(token)
        findings = tester._test_weak_secret(token, header)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["id"], "JWT-WEAK-SECRET")
        self.assertIn("secret", findings[0]["evidence"])

    def test_auth_session_headers(self):
        """AuthSession constructs valid Bearer and CSRF headers."""
        session = AuthSession(token="my-token-123", csrf_token="csrf-abc-xyz")
        headers = session.auth_headers
        self.assertEqual(headers["Authorization"], "Bearer my-token-123")
        self.assertEqual(headers["X-CSRF-Token"], "csrf-abc-xyz")


@pytest.mark.asyncio
async def test_jwt_none_algorithm_acceptance():
    """Detect JWT none-algorithm acceptance."""
    mock_http = MagicMock(spec=RobustHTTPClient)
    mock_http.get = AsyncMock(
        return_value=HTTPResult(
            url="https://api.example.com/admin/dashboard",
            status=200,
            headers={"content-type": "application/json"},
            cookies={},
            body=b'{"admin": true}',
            raw_set_cookies=[],
            redirect_chain=[],
            response_time_ms=30,
            content_type="application/json",
        )
    )

    tester = JWTOAuthTester(http=mock_http)
    findings = await tester._test_none_alg(
        payload={"user": "admin", "role": "admin"},
        endpoint="https://api.example.com/admin/dashboard",
    )
    assert len(findings) == 1
    assert findings[0]["id"] == "JWT-NONE-ALG"


@pytest.mark.asyncio
async def test_oauth_redirect_uri_bypass():
    """Detect OAuth open redirect in redirect_uri parameter."""
    mock_http = MagicMock(spec=RobustHTTPClient)
    mock_http.get = AsyncMock(
        return_value=HTTPResult(
            url="https://auth.example.com/oauth/authorize?redirect_uri=https://evil.com",
            status=302,
            headers={"location": "https://evil.com/callback?code=xyz123"},
            cookies={},
            body=b"",
            raw_set_cookies=[],
            redirect_chain=[],
            response_time_ms=25,
            content_type="text/html",
        )
    )

    tester = JWTOAuthTester(http=mock_http)
    findings = await tester._test_redirect_uri("https://auth.example.com/oauth/authorize")
    assert len(findings) == 1
    assert findings[0]["id"] == "OAUTH-REDIRECT-BYPASS"


@pytest.mark.asyncio
async def test_idor_object_id_detection():
    """Detect candidate numeric and UUID object IDs in URLs."""
    mock_http = MagicMock(spec=RobustHTTPClient)
    mock_http.get = AsyncMock(
        return_value=HTTPResult(
            url="https://example.com/api/orders/1002",
            status=200,
            headers={"content-type": "application/json"},
            cookies={},
            body=b'{"order_id": 1002, "email": "victim@example.com", "total": 450.00}',
            raw_set_cookies=[],
            redirect_chain=[],
            response_time_ms=30,
            content_type="application/json",
        )
    )

    detector = IDORDetector(http=mock_http)
    findings = await detector.run(
        base_url="https://example.com",
        observations=[
            {"name": "discovered_api_routes", "value": ["/api/orders/1001"]}
        ],
    )
    assert len(findings) >= 1
    assert findings[0]["id"] == "IDOR-BOLA"


if __name__ == "__main__":
    unittest.main()
