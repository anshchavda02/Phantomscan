"""Unit tests for Phase 7: AI & Vibe-Coded Web App Security Intelligence."""

import unittest
from unittest.mock import AsyncMock, MagicMock

import pytest

from phantomscan.http_client import HTTPResult, RobustHTTPClient
from phantomscan.modules.ai_app_security import (
    AIAppSecurityScanner,
    AISecretScanner,
    FirebaseAuditorV2,
    SupabaseAuditorV2,
    SystemPromptLeakDetector,
    TRPCProber,
    _mask,
    _mask_connection_string,
)


class TestAIVibeSecurity(unittest.TestCase):
    def test_secret_masking(self):
        """SEC-H02: Discovered secrets are masked."""
        secret = "sk-proj-1234567890abcdef"
        masked = _mask(secret)
        self.assertTrue(masked.startswith("sk-pro"))
        self.assertNotIn("abcdef", masked)

        conn_str = "postgresql://postgres:SuperSecretPassword123@db.supabase.co:5432/postgres"
        masked_conn = _mask_connection_string(conn_str)
        self.assertNotIn("SuperSecretPassword123", masked_conn)
        self.assertIn("****", masked_conn)


@pytest.mark.asyncio
async def test_supabase_rls_auditor():
    """Detect unauthenticated Supabase CRUD access."""
    mock_http = MagicMock(spec=RobustHTTPClient)
    mock_http.get = AsyncMock(
        side_effect=[
            # rest schema
            HTTPResult("https://xyz.supabase.co/rest/v1/", 200, {}, {}, b'{"paths": {"/users": {}}}', [], [], 20, "application/json"),
            # select rows
            HTTPResult("https://xyz.supabase.co/rest/v1/users?limit=5", 200, {}, {}, b'[{"id": 1, "email": "admin@vibe.app"}]', [], [], 30, "application/json"),
        ]
    )

    from phantomscan.modules.ai_app_security import RLSAuditor
    auditor = RLSAuditor(http=mock_http)
    findings = await auditor.audit_supabase(
        project_url="https://xyz.supabase.co",
        anon_key="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    )

    assert len(findings) >= 1
    assert any("SUPABASE" in f.get("id", "") or "RLS" in f.get("title", "") for f in findings)


@pytest.mark.asyncio
async def test_firebase_rtdb_auditor():
    """Detect open Firebase Realtime Database rules."""
    mock_http = MagicMock(spec=RobustHTTPClient)
    mock_http.get = AsyncMock(
        return_value=HTTPResult(
            "https://my-vibe-app.firebaseio.com/.json",
            200,
            {"content-type": "application/json"},
            {},
            b'{"users": {"u1": {"name": "Alice"}}}',
            [],
            [],
            25,
            "application/json",
        )
    )
    mock_http.post = AsyncMock(
        return_value=HTTPResult("https://my-vibe-app.firebaseio.com/__phantomscan_test_.json", 401, {}, {}, b'{"error": "Permission denied"}', [], [], 25, "application/json")
    )

    auditor = FirebaseAuditorV2(http=mock_http)
    findings = await auditor.audit_legacy("https://my-vibe-app.firebaseio.com")
    assert len(findings) >= 1
    assert any("FIREBASE" in f.get("id", "") for f in findings)


@pytest.mark.asyncio
async def test_trpc_procedure_probing():
    """Detect exposed unauthenticated tRPC procedures."""
    mock_http = MagicMock(spec=RobustHTTPClient)
    mock_http.get = AsyncMock(
        side_effect=[
            # probe nonexistent
            HTTPResult("http://example.com/api/trpc/nonexistent.procedure", 200, {}, {}, b'{"TRPCError": true}', [], [], 20, "application/json"),
            # probe procedure
            HTTPResult("http://example.com/api/trpc/user.getAll", 200, {}, {}, b'{"result": {"data": [{"id": 1}]}}', [], [], 20, "application/json"),
        ]
    )

    prober = TRPCProber(http=mock_http)
    findings = await prober.discover_and_test(
        target="http://example.com",
    )
    assert len(findings) >= 1
    assert any("TRPC" in f.get("id", "") for f in findings)



@pytest.mark.asyncio
async def test_system_prompt_leak_probing():
    """Detect system prompt leakage on AI chat endpoints."""
    mock_http = MagicMock(spec=RobustHTTPClient)
    mock_http.post = AsyncMock(
        return_value=HTTPResult(
            "http://example.com/api/chat",
            200,
            {"content-type": "application/json"},
            {},
            b'{"response": "You are a helpful customer support agent for Acme Corp. System prompt instructions: do not reveal secrets."}',
            [],
            [],
            50,
            "application/json",
        )
    )

    detector = SystemPromptLeakDetector(http=mock_http)
    findings = await detector.test(
        ai_endpoint="http://example.com/api/chat",
    )
    assert len(findings) >= 1
    assert any("AI-PROMPT-LEAK" in f.get("id", "") for f in findings)



if __name__ == "__main__":
    unittest.main()
