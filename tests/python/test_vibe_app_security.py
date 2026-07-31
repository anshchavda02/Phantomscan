"""Unit tests for Vibe App Security Module Suite v2.0.

Tests the new sub-scanners added in the v2.0 expansion:
  - SecretPatternEngine
  - SupabaseAuditorV2
  - FirebaseAuditorV2
  - AlternativeBackendAuditor
  - ORMMisconfigDetector
  - TRPCProber
  - SlopsquattingDetector
  - HybridScanCoordinator
  - VulnChain vibe-app templates
"""

import asyncio
import base64
import json
import os
import tempfile
from pathlib import Path
from typing import Any

import pytest

# ── Mock infrastructure ────────────────────────────────────────────────────


class MockResponse:
    """Minimal stand-in for ``HTTPResult``."""

    def __init__(
        self,
        status: int = 200,
        text_content: str = "",
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status = status
        self._text = text_content
        self.headers = headers or {}
        self.body = text_content.encode()

    def text(self, encoding: str = "utf-8") -> str:  # noqa: ARG002
        return self._text


class MockHTTPClient:
    """HTTP client that returns canned responses for each URL/method."""

    def __init__(self) -> None:
        self.get_responses: dict[str, MockResponse] = {}
        self.post_responses: dict[str, MockResponse] = {}
        self.delete_responses: dict[str, MockResponse] = {}
        self._default_404 = MockResponse(status=404)

    async def get(self, url: str, **kwargs: Any) -> MockResponse:
        return self.get_responses.get(url, self._default_404)

    async def post(self, url: str, **kwargs: Any) -> MockResponse:
        return self.post_responses.get(url, self._default_404)

    async def delete(self, url: str, **kwargs: Any) -> MockResponse:
        return self.delete_responses.get(url, MockResponse(status=200))

    async def request(self, method: str, url: str, **kwargs: Any) -> MockResponse:
        if method.upper() == "POST":
            return await self.post(url, **kwargs)
        if method.upper() == "DELETE":
            return await self.delete(url, **kwargs)
        if method.upper() in ("PATCH", "PUT"):
            return self.post_responses.get(url, self._default_404)
        return await self.get(url, **kwargs)


# ── Helpers ────────────────────────────────────────────────────────────────


def _build_jwt(payload: dict[str, Any]) -> str:
    """Create a realistic-length unsigned JWT string from a payload dict."""
    full_payload = {
        "aud": "authenticated",
        "exp": 9999999999,
        "iat": 1700000000,
        "sub": "00000000-0000-0000-0000-000000000000",
        **payload,
    }
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(
        json.dumps(full_payload, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    signature = base64.urlsafe_b64encode(b"x" * 32).rstrip(b"=").decode()
    return f"{header}.{body}.{signature}"


# ═══════════════════════════════════════════════════════════════════════════
# Test: SecretPatternEngine
# ═══════════════════════════════════════════════════════════════════════════


class TestSecretPatternEngine:
    """Tests for the JSON-driven secret pattern scanner."""

    def _get_engine(self):
        from phantomscan.modules.ai_app_security import SecretPatternEngine
        return SecretPatternEngine()

    def test_patterns_loaded(self):
        """Pattern DB should load 60+ patterns from JSON."""
        engine = self._get_engine()
        assert len(engine.patterns) >= 60, f"Only {len(engine.patterns)} patterns loaded"

    @pytest.mark.asyncio
    async def test_detects_openai_key(self):
        engine = self._get_engine()
        content = "const apiKey = 'sk-proj-abc123def456ghi789jkl012mno345';"
        findings = await engine.scan_content(content, "test.js")
        ids = [f["id"] for f in findings]
        assert any("OPENAI" in fid.upper() for fid in ids), f"Expected OpenAI detection, got {ids}"

    @pytest.mark.asyncio
    async def test_detects_aws_key(self):
        engine = self._get_engine()
        content = "const awsKey = 'AKIAIOSFODNN7WXYZ123';"
        findings = await engine.scan_content(content, "config.js")
        ids = [f["id"] for f in findings]
        assert any("AWS" in fid.upper() for fid in ids), f"Expected AWS detection, got {ids}"

    @pytest.mark.asyncio
    async def test_ignores_placeholder(self):
        engine = self._get_engine()
        content = "const key = 'sk-your_api_key_here';"
        findings = await engine.scan_content(content, "test.js")
        # Should NOT find real secrets — it's a placeholder
        real = [f for f in findings if f["severity"] != "info"]
        assert len(real) == 0, f"False positive on placeholder: {real}"

    @pytest.mark.asyncio
    async def test_detects_mongodb_connection(self):
        engine = self._get_engine()
        content = "const db = 'mongodb+srv://admin:secret123@cluster0.abc123.mongodb.net/mydb';"
        findings = await engine.scan_content(content, "server.js")
        ids = [f["id"] for f in findings]
        assert any("MONGO" in fid.upper() for fid in ids)

    @pytest.mark.asyncio
    async def test_detects_private_key(self):
        engine = self._get_engine()
        content = '-----BEGIN RSA PRIVATE KEY-----\nMIIBog...'
        findings = await engine.scan_content(content, "deploy.js")
        ids = [f["id"] for f in findings]
        assert any("PRIVATE" in fid.upper() for fid in ids)


# ═══════════════════════════════════════════════════════════════════════════
# Test: SupabaseAuditorV2
# ═══════════════════════════════════════════════════════════════════════════


class TestSupabaseAuditorV2:
    """Tests for full Supabase CRUD RLS auditing."""

    @pytest.mark.asyncio
    async def test_detects_rls_missing_select(self):
        from phantomscan.modules.ai_app_security import SupabaseAuditorV2

        mock = MockHTTPClient()
        project_url = "https://abcde12345abcde12345.supabase.co"
        anon_key = _build_jwt({"role": "anon"})
        rest_url = project_url + "/rest/v1/"

        # Schema discovery
        mock.get_responses[rest_url] = MockResponse(
            200, json.dumps({"paths": {"/users": {}, "/orders": {}}}))

        # SELECT test — returns rows
        mock.get_responses[f"{rest_url}users?limit=1"] = MockResponse(
            200, json.dumps([{"id": 1, "email": "test@test.com"}]))
        mock.get_responses[f"{rest_url}users?limit=3"] = MockResponse(
            200, json.dumps([{"id": 1, "email": "test@test.com"}]))
        mock.get_responses[f"{rest_url}orders?limit=1"] = MockResponse(200, "[]")
        mock.get_responses[f"{rest_url}orders?limit=3"] = MockResponse(200, "[]")

        # Storage/auth endpoints not found
        mock.get_responses[f"{project_url}/storage/v1/bucket"] = MockResponse(404)
        mock.get_responses[f"{project_url}/auth/v1/settings"] = MockResponse(404)

        auditor = SupabaseAuditorV2(mock)
        findings = await auditor.full_audit(project_url, anon_key)

        rls_ids = [f["id"] for f in findings if "RLS" in f["id"]]
        assert len(rls_ids) > 0, "Should detect RLS missing on 'users' table"

    @pytest.mark.asyncio
    async def test_detects_sensitive_columns(self):
        from phantomscan.modules.ai_app_security import SupabaseAuditorV2

        mock = MockHTTPClient()
        project_url = "https://abcde12345abcde12345.supabase.co"
        anon_key = _build_jwt({"role": "anon"})
        rest_url = project_url + "/rest/v1/"

        mock.get_responses[rest_url] = MockResponse(
            200, json.dumps({"paths": {"/profiles": {}}}))
        mock.get_responses[f"{rest_url}profiles?limit=1"] = MockResponse(
            200, json.dumps([{"id": 1, "email": "a@b.com", "password_hash": "xxx"}]))
        mock.get_responses[f"{rest_url}profiles?limit=3"] = MockResponse(
            200, json.dumps([{"id": 1, "email": "a@b.com", "password_hash": "xxx"}]))
        mock.get_responses[f"{project_url}/storage/v1/bucket"] = MockResponse(404)
        mock.get_responses[f"{project_url}/auth/v1/settings"] = MockResponse(404)

        auditor = SupabaseAuditorV2(mock)
        findings = await auditor.full_audit(project_url, anon_key)

        sensitive_ids = [f["id"] for f in findings if "SENSITIVE" in f["id"]]
        assert len(sensitive_ids) > 0, "Should detect sensitive columns"

    @pytest.mark.asyncio
    async def test_key_format_sb_secret(self):
        from phantomscan.modules.ai_app_security import SupabaseAuditorV2

        mock = MockHTTPClient()
        auditor = SupabaseAuditorV2(mock)
        content = "const key = 'sb_secret_abcde12345abcde12345_realkey';"
        findings = await auditor.check_key_format(content)
        assert any("SECRET-KEY-NEW" in f["id"] for f in findings)

    @pytest.mark.asyncio
    async def test_detects_storage_public_bucket(self):
        from phantomscan.modules.ai_app_security import SupabaseAuditorV2

        mock = MockHTTPClient()
        project_url = "https://abcde12345abcde12345.supabase.co"
        anon_key = _build_jwt({"role": "anon"})
        rest_url = project_url + "/rest/v1/"

        mock.get_responses[rest_url] = MockResponse(200, json.dumps({"paths": {}}))
        mock.get_responses[f"{project_url}/storage/v1/bucket"] = MockResponse(
            200, json.dumps([{"name": "uploads", "public": True}]))
        mock.get_responses[f"{project_url}/auth/v1/settings"] = MockResponse(404)

        auditor = SupabaseAuditorV2(mock)
        findings = await auditor.full_audit(project_url, anon_key)

        storage_ids = [f["id"] for f in findings if "STORAGE" in f["id"]]
        assert len(storage_ids) > 0, "Should detect public storage bucket"


# ═══════════════════════════════════════════════════════════════════════════
# Test: FirebaseAuditorV2
# ═══════════════════════════════════════════════════════════════════════════


class TestFirebaseAuditorV2:
    """Tests for Firebase RTDB, Firestore, and Storage audit."""

    @pytest.mark.asyncio
    async def test_rtdb_public_read(self):
        from phantomscan.modules.ai_app_security import FirebaseAuditorV2

        mock = MockHTTPClient()
        url = "https://myapp-default.firebaseio.com"
        mock.get_responses[f"{url}/.json"] = MockResponse(
            200, '{"users": {"user1": {"name": "Alice"}}}')
        # Write test will 404
        mock.post_responses[f"{url}/__phantomscan_test_"] = MockResponse(404)

        auditor = FirebaseAuditorV2(mock)
        findings = await auditor.audit_legacy(url)
        assert any("FIREBASE-NO-AUTH" in f["id"] for f in findings)

    @pytest.mark.asyncio
    async def test_firestore_public_read(self):
        from phantomscan.modules.ai_app_security import FirebaseAuditorV2

        mock = MockHTTPClient()
        project_id = "my-cool-app"
        fs_url = (f"https://firestore.googleapis.com/v1/"
                  f"projects/{project_id}/databases/(default)/documents")
        mock.get_responses[fs_url] = MockResponse(
            200, '{"documents": [{"name": "doc1"}]}')

        auditor = FirebaseAuditorV2(mock)
        findings = await auditor.audit({"projectId": project_id})
        assert any("FIRESTORE-PUBLIC" in f["id"] for f in findings)

    @pytest.mark.asyncio
    async def test_storage_public_listing(self):
        from phantomscan.modules.ai_app_security import FirebaseAuditorV2

        mock = MockHTTPClient()
        bucket = "my-cool-app.appspot.com"
        storage_url = f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o"
        mock.get_responses[storage_url] = MockResponse(
            200, '{"items": [{"name": "file1.txt"}]}')

        auditor = FirebaseAuditorV2(mock)
        findings = await auditor.audit({"storageBucket": bucket})
        assert any("STORAGE-PUBLIC" in f["id"] for f in findings)


# ═══════════════════════════════════════════════════════════════════════════
# Test: AlternativeBackendAuditor
# ═══════════════════════════════════════════════════════════════════════════


class TestAlternativeBackendAuditor:
    """Tests for MongoDB and Postgres exposure detection."""

    @pytest.mark.asyncio
    async def test_detects_mongodb_connection_string(self):
        from phantomscan.modules.ai_app_security import AlternativeBackendAuditor

        mock = MockHTTPClient()
        auditor = AlternativeBackendAuditor(mock)
        content = "const uri = 'mongodb+srv://admin:password123@cluster0.abc.mongodb.net';"
        findings = await auditor.check_mongodb_exposure(content)
        assert len(findings) > 0
        assert findings[0]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_detects_postgres_connection_string(self):
        from phantomscan.modules.ai_app_security import AlternativeBackendAuditor

        mock = MockHTTPClient()
        auditor = AlternativeBackendAuditor(mock)
        content = "DATABASE_URL = 'postgresql://user:pass@db.neon.tech/neondb';"
        findings = await auditor.check_raw_postgres_exposure(content)
        assert len(findings) > 0
        assert findings[0]["severity"] == "critical"


# ═══════════════════════════════════════════════════════════════════════════
# Test: ORMMisconfigDetector
# ═══════════════════════════════════════════════════════════════════════════


class TestORMMisconfigDetector:
    """Tests for Prisma / Drizzle ORM misconfig detection."""

    @pytest.mark.asyncio
    async def test_detects_prisma_error_leak(self):
        from phantomscan.modules.ai_app_security import ORMMisconfigDetector

        detector = ORMMisconfigDetector()
        js_content = (
            'if (error) return res.json({error: "PrismaClientKnownRequestError: '
            'Unique constraint failed on the fields"})'
        )
        findings = await detector.check_prisma(None, js_content)
        assert any("PRISMA-ERROR-LEAK" in f["id"] for f in findings)

    @pytest.mark.asyncio
    async def test_prisma_schema_no_owner(self):
        from phantomscan.modules.ai_app_security import ORMMisconfigDetector

        detector = ORMMisconfigDetector()
        with tempfile.TemporaryDirectory() as tmpdir:
            prisma_dir = Path(tmpdir) / "prisma"
            prisma_dir.mkdir()
            schema = prisma_dir / "schema.prisma"
            schema.write_text(
                'model Post {\n  id Int @id\n  title String\n  body String\n}\n'
                'model User {\n  id Int @id\n  name String\n}\n'
            )
            findings = await detector.analyze_prisma_schema(tmpdir)
            # 'Post' has no userId/owner field
            assert any("PRISMA-NO-OWNER" in f["id"] for f in findings)

    @pytest.mark.asyncio
    async def test_drizzle_sql_injection(self):
        from phantomscan.modules.ai_app_security import ORMMisconfigDetector

        detector = ORMMisconfigDetector()
        with tempfile.TemporaryDirectory() as tmpdir:
            ts_file = Path(tmpdir) / "routes.ts"
            ts_file.write_text(
                'const result = await db.execute(sql`SELECT * FROM users WHERE id = ${req.params.id}`);\n'
            )
            findings = await detector.check_drizzle(tmpdir)
            assert any("DRIZZLE-SQL-INJECTION" in f["id"] for f in findings)


# ═══════════════════════════════════════════════════════════════════════════
# Test: TRPCProber
# ═══════════════════════════════════════════════════════════════════════════


class TestTRPCProber:
    """Tests for tRPC endpoint discovery and testing."""

    @pytest.mark.asyncio
    async def test_discovers_trpc_endpoint(self):
        from phantomscan.modules.ai_app_security import TRPCProber

        mock = MockHTTPClient()
        target = "https://example.com"
        # tRPC endpoint responds with TRPCError
        mock.get_responses[f"{target}/api/trpc/nonexistent.procedure"] = MockResponse(
            200, '{"error": {"message": "No query found", "code": "NOT_FOUND"}, "TRPCError": true}')

        prober = TRPCProber(mock)
        findings = await prober.discover_and_test(target)
        assert any("TRPC-ENDPOINT" in f["id"] for f in findings)

    @pytest.mark.asyncio
    async def test_detects_unauth_procedure(self):
        from phantomscan.modules.ai_app_security import TRPCProber

        mock = MockHTTPClient()
        target = "https://example.com"

        # Endpoint discovery
        mock.get_responses[f"{target}/api/trpc/nonexistent.procedure"] = MockResponse(
            200, '{"TRPCError": true}')
        # Unauth procedure returns data
        mock.get_responses[f"{target}/api/trpc/user.getAll"] = MockResponse(
            200, '{"result": {"data": [{"id": 1}]}}')

        prober = TRPCProber(mock)
        findings = await prober.discover_and_test(target)
        assert any("TRPC-UNAUTH-PROC" in f["id"] for f in findings)


# ═══════════════════════════════════════════════════════════════════════════
# Test: SlopsquattingDetector
# ═══════════════════════════════════════════════════════════════════════════


class TestSlopsquattingDetector:
    """Tests for AI-hallucinated dependency detection."""

    @pytest.mark.asyncio
    async def test_detects_missing_npm_package(self):
        from phantomscan.modules.ai_app_security import SlopsquattingDetector

        mock = MockHTTPClient()
        # Package that 404s on npm (hallucinated name)
        mock.get_responses["https://registry.npmjs.org/react-hallu-nonexistent-pkg"] = MockResponse(404)

        detector = SlopsquattingDetector(http=mock)

        with tempfile.TemporaryDirectory() as tmpdir:
            pkg_json = Path(tmpdir) / "package.json"
            pkg_json.write_text(json.dumps({
                "dependencies": {
                    "react-hallu-nonexistent-pkg": "^1.0.0"
                }
            }))
            findings = await detector.scan_project(tmpdir)
            assert any("SLOPSQUATTING-NPM" in f["id"] for f in findings)

    @pytest.mark.asyncio
    async def test_detects_missing_pypi_package(self):
        from phantomscan.modules.ai_app_security import SlopsquattingDetector

        mock = MockHTTPClient()
        mock.get_responses["https://pypi.org/pypi/hallu-nonexistent-ai-lib/json"] = MockResponse(404)

        detector = SlopsquattingDetector(http=mock)

        with tempfile.TemporaryDirectory() as tmpdir:
            req_txt = Path(tmpdir) / "requirements.txt"
            req_txt.write_text("hallu-nonexistent-ai-lib==1.0.0\n")
            findings = await detector.scan_project(tmpdir)
            assert any("SLOPSQUATTING-PYPI" in f["id"] for f in findings)

    @pytest.mark.asyncio
    async def test_suspicious_metadata_single_version(self):
        from phantomscan.modules.ai_app_security import SlopsquattingDetector

        mock = MockHTTPClient()
        mock.get_responses["https://registry.npmjs.org/sketchy-pkg"] = MockResponse(
            200, json.dumps({
                "time": {"created": "2024-06-01"},
                "versions": {"1.0.0": {}}
            }))

        detector = SlopsquattingDetector(http=mock)
        result = await detector.verify_package("sketchy-pkg", "npm")
        assert result.suspicious


# ═══════════════════════════════════════════════════════════════════════════
# Test: HybridScanCoordinator
# ═══════════════════════════════════════════════════════════════════════════


class TestHybridScanCoordinator:
    """Tests for source-aware hybrid scanning."""

    @pytest.mark.asyncio
    async def test_source_secret_scan(self):
        from phantomscan.modules.ai_app_security import HybridScanCoordinator

        coordinator = HybridScanCoordinator()
        with tempfile.TemporaryDirectory() as tmpdir:
            src_file = Path(tmpdir) / "config.js"
            src_file.write_text(
                "const key = 'sk-proj-abc123def456ghi789jkl012mno345';\n"
            )
            findings = await coordinator.run_source_checks(tmpdir)
            assert len(findings) > 0, "Should find secret in source file"

    def test_merge_and_boost_confidence(self):
        from phantomscan.modules.ai_app_security import HybridScanCoordinator

        bb = [{"title": "Exposed Secret: OpenAI API Key", "confidence": "high"}]
        src = [{"title": "Exposed Secret: OpenAI API Key", "confidence": "high", "evidence": "Found in src"}]
        HybridScanCoordinator.merge_and_boost_confidence(bb, src)
        assert src[0]["confidence"] == "confirmed"


# ═══════════════════════════════════════════════════════════════════════════
# Test: VulnChain Vibe App Templates
# ═══════════════════════════════════════════════════════════════════════════


class TestVulnChainVibeApp:
    """Tests for the new vibe-app attack chain definitions."""

    def test_supabase_chain_fires(self):
        from phantomscan.modules.vuln_chain import VulnChainEngine

        engine = VulnChainEngine()
        findings = [
            {"id": "AI-SUPABASE-RLS-MISSING", "title": "Supabase Table 'users': RLS Missing for SELECT"},
            {"id": "AI-SUPABASE-SERVICE-ROLE-JWT", "title": "Supabase SERVICE ROLE KEY exposed service_role"},
        ]
        chains = engine.analyze_chains(findings)
        chain_names = [c["title"] for c in chains]
        assert any("Supabase RLS" in name for name in chain_names), f"Expected Supabase chain, got {chain_names}"

    def test_slopsquatting_chain_fires(self):
        from phantomscan.modules.vuln_chain import VulnChainEngine

        engine = VulnChainEngine()
        findings = [
            {"id": "AI-SLOPSQUATTING-NPM", "title": "Slopsquatting: 'react-hallu' Does Not Exist on npm"},
        ]
        chains = engine.analyze_chains(findings)
        chain_names = [c["title"] for c in chains]
        assert any("Slopsquatting" in name for name in chain_names), f"Expected slopsquatting chain, got {chain_names}"

    def test_firebase_chain_fires(self):
        from phantomscan.modules.vuln_chain import VulnChainEngine

        engine = VulnChainEngine()
        findings = [
            {"id": "AI-FIREBASE-RTDB-PUBLIC-READ", "title": "Firebase Publicly Readable No Auth"},
            {"id": "AI-FIREBASE-RTDB-PUBLIC-WRITE", "title": "Firebase Publicly Writable"},
        ]
        chains = engine.analyze_chains(findings)
        chain_names = [c["title"] for c in chains]
        assert any("Firebase" in name for name in chain_names), f"Expected Firebase chain, got {chain_names}"

    def test_ai_proxy_chain_fires(self):
        from phantomscan.modules.vuln_chain import VulnChainEngine

        engine = VulnChainEngine()
        findings = [
            {"id": "AI-PROXY-UNAUTH", "title": "Unauthenticated AI Proxy Endpoint"},
            {"id": "RATE-LIMIT-MISSING", "title": "No Rate Limit on endpoint"},
        ]
        chains = engine.analyze_chains(findings)
        chain_names = [c["title"] for c in chains]
        assert any("AI Proxy" in name for name in chain_names), f"Expected AI proxy chain, got {chain_names}"

    def test_env_cloud_chain_fires(self):
        from phantomscan.modules.vuln_chain import VulnChainEngine

        engine = VulnChainEngine()
        findings = [
            {"id": "AI-ENV-FILE-EXPOSED", "title": ".env File Publicly Accessible"},
            {"id": "AI-KEY-EXPOSED", "title": "Exposed AI-KEY-EXPOSED AWS Access Key"},
        ]
        chains = engine.analyze_chains(findings)
        chain_names = [c["title"] for c in chains]
        assert any(".env Leak" in name for name in chain_names), f"Expected .env chain, got {chain_names}"

    def test_trpc_default_creds_chain_fires(self):
        from phantomscan.modules.vuln_chain import VulnChainEngine

        engine = VulnChainEngine()
        findings = [
            {"id": "AI-TRPC-UNAUTH-PROC", "title": "tRPC Procedure 'admin.getAll' Accessible Without Auth"},
            {"id": "AI-DEFAULT-CREDS", "title": "Default Credentials Accepted: admin/admin"},
        ]
        chains = engine.analyze_chains(findings)
        chain_names = [c["title"] for c in chains]
        assert any("tRPC" in name for name in chain_names), f"Expected tRPC chain, got {chain_names}"


# ═══════════════════════════════════════════════════════════════════════════
# Test: Helper Functions
# ═══════════════════════════════════════════════════════════════════════════


class TestHelpers:
    """Test utility functions."""

    def test_mask(self):
        from phantomscan.modules.ai_app_security import _mask
        assert _mask("sk-1234567890abcdef") == "sk-123*************"

    def test_mask_short(self):
        from phantomscan.modules.ai_app_security import _mask
        assert _mask("abc") == "abc"

    def test_mask_connection_string(self):
        from phantomscan.modules.ai_app_security import _mask_connection_string
        result = _mask_connection_string("mongodb://admin:secretpass@host.com")
        assert "secretpass" not in result
        assert "****" in result

    def test_is_placeholder(self):
        from phantomscan.modules.ai_app_security import _is_placeholder
        assert _is_placeholder("your_api_key_here")
        assert _is_placeholder("sk-XXXXXXXXXXXXXXXX")
        assert _is_placeholder("test_test_test")
        assert not _is_placeholder("sk-proj-abc123def456ghi789jkl012")

    def test_shannon_entropy(self):
        from phantomscan.modules.ai_app_security import _shannon_entropy
        assert _shannon_entropy("aaaa") < 1.0
        assert _shannon_entropy("abcdefghij") > 3.0

    def test_is_comment_context(self):
        from phantomscan.modules.ai_app_security import _is_comment_context
        content = '// example key: sk-abc123def456\nconst key = "real_key"'
        assert _is_comment_context(content, content.index("sk-abc"))
        assert not _is_comment_context(content, content.index("real_key"))
