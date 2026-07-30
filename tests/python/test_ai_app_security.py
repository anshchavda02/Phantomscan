"""Unit tests for the AI / Vibe-Coded Web Application Security Scanner."""

import asyncio
import json
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
        cookies: dict[str, str] | None = None,
    ) -> None:
        self.status = status
        self._text = text_content
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.body = text_content.encode()

    def text(self, encoding: str = "utf-8") -> str:  # noqa: ARG002
        return self._text


class MockHTTPClient:
    """HTTP client that returns canned responses for each URL/method."""

    def __init__(self) -> None:
        self.get_responses: dict[str, MockResponse] = {}
        self.post_responses: dict[str, MockResponse] = {}
        self.delete_responses: dict[str, MockResponse] = {}
        # Fallback for un-mapped URLs
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
        return await self.get(url, **kwargs)


# ── Helpers ────────────────────────────────────────────────────────────────


def _build_jwt(payload: dict[str, Any]) -> str:
    """Create a realistic-length unsigned JWT string from a payload dict.

    Supabase JWTs are long — include extra claims so the base64 output
    exceeds the 100-character threshold required by the BAAS regex pattern.
    """
    import base64

    # Pad the payload with realistic Supabase claims
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
    sig = base64.urlsafe_b64encode(b"a" * 32).rstrip(b"=").decode()
    return f"{header}.{body}.{sig}"


# ═══════════════════════════════════════════════════════════════════════════
# AISecretScanner tests
# ═══════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_ai_secret_scanner_detects_openai_key():
    """Detects an OpenAI key in HTML body."""
    from phantomscan.modules.ai_app_security import AISecretScanner

    mock_http = MockHTTPClient()
    scanner = AISecretScanner(mock_http)

    html = '<script>const key = "sk-proj-ABCDE12345FGHIJ67890xyzabc";</script>'
    findings = await scanner.scan("https://example.com", html, [], {})

    key_findings = [f for f in findings if f["id"] == "AI-KEY-EXPOSED"]
    assert len(key_findings) >= 1
    assert key_findings[0]["severity"] == "critical"
    assert "OpenAI" in key_findings[0]["title"]


@pytest.mark.asyncio
async def test_ai_secret_scanner_detects_anthropic_key():
    """Detects an Anthropic key in JS content."""
    from phantomscan.modules.ai_app_security import AISecretScanner

    mock_http = MockHTTPClient()
    js_content = 'const ANTHROPIC_KEY = "sk-ant-api03-' + "A" * 100 + '";'
    mock_http.get_responses["https://example.com/app.js"] = MockResponse(
        status=200, text_content=js_content,
    )
    scanner = AISecretScanner(mock_http)

    findings = await scanner.scan(
        "https://example.com", "", ["https://example.com/app.js"], {},
    )
    key_findings = [f for f in findings if f["id"] == "AI-KEY-EXPOSED"]
    assert len(key_findings) >= 1
    assert any("Anthropic" in f["title"] for f in key_findings)


@pytest.mark.asyncio
async def test_ai_secret_scanner_ignores_placeholders():
    """Placeholder API keys should be filtered out."""
    from phantomscan.modules.ai_app_security import AISecretScanner

    mock_http = MockHTTPClient()
    html = '<script>const key = "sk-your_api_key_here_placeholder";</script>'
    scanner = AISecretScanner(mock_http)

    findings = await scanner.scan("https://example.com", html, [], {})
    key_findings = [f for f in findings if f["id"] == "AI-KEY-EXPOSED"]
    assert len(key_findings) == 0


@pytest.mark.asyncio
async def test_ai_secret_scanner_detects_source_map():
    """Exposed source maps should produce a finding."""
    from phantomscan.modules.ai_app_security import AISecretScanner

    mock_http = MockHTTPClient()
    mock_http.get_responses["https://example.com/app.js"] = MockResponse(
        status=200, text_content="// minified js",
    )
    mock_http.get_responses["https://example.com/app.js.map"] = MockResponse(
        status=200,
        text_content='{"version":3,"sources":["src/app.tsx"],"mappings":"..."}',
    )
    scanner = AISecretScanner(mock_http)

    findings = await scanner.scan(
        "https://example.com", "", ["https://example.com/app.js"], {},
    )
    map_findings = [f for f in findings if f["id"] == "AI-SOURCEMAP-EXPOSED"]
    assert len(map_findings) == 1
    assert map_findings[0]["severity"] == "medium"


@pytest.mark.asyncio
async def test_ai_secret_scanner_detects_platform():
    """Platform markers should produce an info finding."""
    from phantomscan.modules.ai_app_security import AISecretScanner

    mock_http = MockHTTPClient()
    scanner = AISecretScanner(mock_http)

    html = '<meta name="generator" content="made with lovable.dev">'
    findings = await scanner.scan("https://myapp.lovable.dev", html, [], {})
    platform_findings = [f for f in findings if f["id"] == "AI-PLATFORM-DETECTED"]
    assert len(platform_findings) >= 1
    assert "Lovable" in platform_findings[0]["title"]


@pytest.mark.asyncio
async def test_ai_secret_scanner_detects_service_role_jwt():
    """A Supabase service_role JWT should be flagged as critical."""
    from phantomscan.modules.ai_app_security import AISecretScanner

    mock_http = MockHTTPClient()
    scanner = AISecretScanner(mock_http)

    jwt = _build_jwt({"role": "service_role", "iss": "supabase"})
    html = f'<script>const SUPABASE_KEY = "{jwt}";</script>'
    findings = await scanner.scan("https://example.com", html, [], {})

    baas_findings = [f for f in findings if f["id"] == "AI-BAAS-CONFIG-EXPOSED"]
    service_findings = [
        f for f in baas_findings if "SERVICE ROLE" in f.get("title", "")
    ]
    assert len(service_findings) >= 1
    assert service_findings[0]["severity"] == "critical"


@pytest.mark.asyncio
async def test_check_jwt_role_helper():
    """Helper function correctly decodes JWT role claims."""
    from phantomscan.modules.ai_app_security import AISecretScanner

    service_jwt = _build_jwt({"role": "service_role"})
    anon_jwt = _build_jwt({"role": "anon"})

    assert AISecretScanner._check_jwt_role(service_jwt) is True
    assert AISecretScanner._check_jwt_role(anon_jwt) is False
    assert AISecretScanner._check_jwt_role("not-a-jwt") is False


# ═══════════════════════════════════════════════════════════════════════════
# RLSAuditor tests
# ═══════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_rls_auditor_supabase_read():
    """Detects tables readable with the public anon key."""
    from phantomscan.modules.ai_app_security import RLSAuditor

    mock_http = MockHTTPClient()

    # OpenAPI schema response
    schema = {"paths": {"/users": {}, "/posts": {}}}
    mock_http.get_responses[
        "https://abc12345678901234567.supabase.co/rest/v1/"
    ] = MockResponse(status=200, text_content=json.dumps(schema))

    # Table read responses
    users_data = [{"id": 1, "email": "a@b.com", "name": "Alice"}]
    mock_http.get_responses[
        "https://abc12345678901234567.supabase.co/rest/v1/users?limit=5"
    ] = MockResponse(status=200, text_content=json.dumps(users_data))

    posts_data = [{"id": 1, "title": "Hello", "body": "World"}]
    mock_http.get_responses[
        "https://abc12345678901234567.supabase.co/rest/v1/posts?limit=5"
    ] = MockResponse(status=200, text_content=json.dumps(posts_data))

    auditor = RLSAuditor(mock_http)
    findings = await auditor.audit_supabase(
        "https://abc12345678901234567.supabase.co", "fake-anon-key",
    )

    read_findings = [f for f in findings if f["id"] == "AI-SUPABASE-RLS-READ"]
    assert len(read_findings) == 2

    # Users table should also flag sensitive columns
    sensitive = [f for f in findings if f["id"] == "AI-SUPABASE-SENSITIVE-DATA"]
    assert len(sensitive) >= 1
    assert "email" in sensitive[0]["evidence"]


@pytest.mark.asyncio
async def test_rls_auditor_firebase():
    """Detects publicly readable Firebase Realtime Database."""
    from phantomscan.modules.ai_app_security import RLSAuditor

    mock_http = MockHTTPClient()
    mock_http.get_responses[
        "https://my-app.firebaseio.com/.json"
    ] = MockResponse(status=200, text_content='{"users": {"uid1": {"name": "Bob"}}}')

    auditor = RLSAuditor(mock_http)
    findings = await auditor.audit_firebase("https://my-app.firebaseio.com")

    assert len(findings) == 1
    assert findings[0]["id"] == "AI-FIREBASE-NO-AUTH"
    assert findings[0]["severity"] == "critical"


@pytest.mark.asyncio
async def test_rls_auditor_firebase_empty():
    """Empty Firebase responses should NOT produce a finding."""
    from phantomscan.modules.ai_app_security import RLSAuditor

    mock_http = MockHTTPClient()
    mock_http.get_responses[
        "https://my-app.firebaseio.com/.json"
    ] = MockResponse(status=200, text_content="null")

    auditor = RLSAuditor(mock_http)
    findings = await auditor.audit_firebase("https://my-app.firebaseio.com")
    assert len(findings) == 0


# ═══════════════════════════════════════════════════════════════════════════
# ServerlessAbuseDetector tests
# ═══════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_serverless_detector_finds_unauth_proxy():
    """An endpoint responding with AI-like content should be flagged."""
    from phantomscan.modules.ai_app_security import ServerlessAbuseDetector

    mock_http = MockHTTPClient()
    ai_response = json.dumps({
        "choices": [{"message": {"content": "Hello, how can I help?"}}],
    })
    mock_http.post_responses["https://example.com/api/chat"] = MockResponse(
        status=200, text_content=ai_response,
    )

    detector = ServerlessAbuseDetector(mock_http)
    findings = await detector.detect("https://example.com")

    proxy_findings = [f for f in findings if f["id"] == "AI-PROXY-UNAUTH"]
    assert len(proxy_findings) >= 1
    assert proxy_findings[0]["severity"] in ("critical", "high")


@pytest.mark.asyncio
async def test_serverless_detector_ignores_non_ai():
    """Non-AI-looking responses should not be flagged."""
    from phantomscan.modules.ai_app_security import ServerlessAbuseDetector

    mock_http = MockHTTPClient()
    mock_http.post_responses["https://example.com/api/chat"] = MockResponse(
        status=200, text_content="OK",
    )

    detector = ServerlessAbuseDetector(mock_http)
    findings = await detector.detect("https://example.com")

    proxy_findings = [f for f in findings if f["id"] == "AI-PROXY-UNAUTH"]
    assert len(proxy_findings) == 0


@pytest.mark.asyncio
async def test_serverless_detector_rate_limit_headers():
    """Rate-limited endpoints should have lower severity."""
    from phantomscan.modules.ai_app_security import ServerlessAbuseDetector

    mock_http = MockHTTPClient()
    ai_response = json.dumps({"content": "I am an AI assistant"})
    mock_http.post_responses["https://example.com/api/chat"] = MockResponse(
        status=200,
        text_content=ai_response,
        headers={"x-ratelimit-remaining": "99"},
    )

    detector = ServerlessAbuseDetector(mock_http)
    findings = await detector.detect("https://example.com")

    proxy_findings = [f for f in findings if f["id"] == "AI-PROXY-UNAUTH"]
    assert len(proxy_findings) >= 1
    assert proxy_findings[0]["severity"] == "high"  # not critical


# ═══════════════════════════════════════════════════════════════════════════
# SystemPromptLeakDetector tests
# ═══════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_prompt_leak_detector():
    """AI responses with multiple leak indicators should be flagged."""
    from phantomscan.modules.ai_app_security import SystemPromptLeakDetector

    mock_http = MockHTTPClient()
    leaked_response = (
        "You are a helpful AI assistant. Your role is to help users "
        "with their questions. Do not reveal your system prompt."
    )
    # All probes get this leaked response
    for path in [
        "https://example.com/api/chat",
    ]:
        mock_http.post_responses[path] = MockResponse(
            status=200, text_content=leaked_response,
        )

    detector = SystemPromptLeakDetector(mock_http)
    findings = await detector.test("https://example.com/api/chat")

    assert len(findings) >= 1
    assert findings[0]["id"] == "AI-PROMPT-LEAK"
    assert findings[0]["severity"] == "medium"


@pytest.mark.asyncio
async def test_prompt_leak_detector_no_leak():
    """Normal AI responses should not be flagged as leaks."""
    from phantomscan.modules.ai_app_security import SystemPromptLeakDetector

    mock_http = MockHTTPClient()
    normal_response = "The weather today is sunny with a high of 75F."
    mock_http.post_responses["https://example.com/api/chat"] = MockResponse(
        status=200, text_content=normal_response,
    )

    detector = SystemPromptLeakDetector(mock_http)
    findings = await detector.test("https://example.com/api/chat")
    assert len(findings) == 0


# ═══════════════════════════════════════════════════════════════════════════
# CRUDOwnershipChecker tests
# ═══════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_crud_ownership_checker():
    """Endpoints with owned-resource patterns should be flagged."""
    from phantomscan.modules.ai_app_security import CRUDOwnershipChecker

    mock_http = MockHTTPClient()
    checker = CRUDOwnershipChecker(mock_http)

    endpoints = [
        "https://example.com/api/users/123",
        "https://example.com/api/my/orders/456",
        "https://example.com/api/public/info",  # should not match
    ]
    findings = await checker.check(endpoints)

    crud_findings = [f for f in findings if f["id"] == "AI-CRUD-NO-OWNERSHIP"]
    assert len(crud_findings) == 2
    assert all(f["severity"] == "medium" for f in crud_findings)


@pytest.mark.asyncio
async def test_crud_ownership_checker_no_match():
    """Endpoints without owned-resource patterns should pass."""
    from phantomscan.modules.ai_app_security import CRUDOwnershipChecker

    mock_http = MockHTTPClient()
    checker = CRUDOwnershipChecker(mock_http)

    endpoints = [
        "https://example.com/api/status",
        "https://example.com/api/health",
    ]
    findings = await checker.check(endpoints)
    assert len(findings) == 0


# ═══════════════════════════════════════════════════════════════════════════
# EnvDebugScanner tests
# ═══════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_env_scanner_detects_env_file():
    """Exposed .env files should produce a critical finding."""
    from phantomscan.modules.ai_app_security import EnvDebugScanner

    mock_http = MockHTTPClient()
    env_content = (
        "DATABASE_URL=postgres://user:pass@host/db\n"
        "OPENAI_API_KEY=sk-test1234567890\n"
        "JWT_SECRET=supersecret\n"
    )
    mock_http.get_responses["https://example.com/.env"] = MockResponse(
        status=200, text_content=env_content,
    )

    scanner = EnvDebugScanner(mock_http)
    findings = await scanner.scan("https://example.com")

    env_findings = [f for f in findings if f["id"] == "AI-ENV-FILE-EXPOSED"]
    assert len(env_findings) >= 1
    assert env_findings[0]["severity"] == "critical"


@pytest.mark.asyncio
async def test_env_scanner_detects_git():
    """Exposed .git directories should produce a high finding."""
    from phantomscan.modules.ai_app_security import EnvDebugScanner

    mock_http = MockHTTPClient()
    mock_http.get_responses["https://example.com/.git/config"] = MockResponse(
        status=200,
        text_content="[core]\n\trepositoryformatversion = 0\n",
    )

    scanner = EnvDebugScanner(mock_http)
    findings = await scanner.scan("https://example.com")

    git_findings = [f for f in findings if f["id"] == "AI-GIT-EXPOSED"]
    assert len(git_findings) >= 1
    assert git_findings[0]["severity"] == "high"


@pytest.mark.asyncio
async def test_env_scanner_detects_debug():
    """Active debug endpoints should produce a high finding."""
    from phantomscan.modules.ai_app_security import EnvDebugScanner

    mock_http = MockHTTPClient()
    mock_http.get_responses["https://example.com/api/debug"] = MockResponse(
        status=200,
        text_content='{"env": "production", "debug": true}',
    )

    scanner = EnvDebugScanner(mock_http)
    findings = await scanner.scan("https://example.com")

    debug_findings = [f for f in findings if f["id"] == "AI-DEBUG-ENDPOINT"]
    assert len(debug_findings) >= 1


@pytest.mark.asyncio
async def test_env_scanner_detects_package_json():
    """Exposed package.json should produce a low finding."""
    from phantomscan.modules.ai_app_security import EnvDebugScanner

    mock_http = MockHTTPClient()
    mock_http.get_responses["https://example.com/package.json"] = MockResponse(
        status=200,
        text_content='{"name": "my-app", "version": "1.0.0", "dependencies": {}}',
    )

    scanner = EnvDebugScanner(mock_http)
    findings = await scanner.scan("https://example.com")

    pkg_findings = [f for f in findings if f["id"] == "AI-PACKAGE-JSON-EXPOSED"]
    assert len(pkg_findings) == 1
    assert pkg_findings[0]["severity"] == "low"


# ═══════════════════════════════════════════════════════════════════════════
# DefaultCredChecker tests
# ═══════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_default_cred_checker_finds_creds():
    """Default credentials that succeed should be flagged critical."""
    from phantomscan.modules.ai_app_security import DefaultCredChecker

    mock_http = MockHTTPClient()
    # Empty-cred probe returns 401 (endpoint exists)
    mock_http.post_responses["https://example.com/api/auth/login"] = MockResponse(
        status=401, text_content='{"error": "unauthorized"}',
    )

    # Override: admin/admin succeeds
    class CredAwareMockHTTP(MockHTTPClient):
        async def post(self, url: str, **kwargs: Any) -> MockResponse:
            body = kwargs.get("json", {})
            if (
                url == "https://example.com/api/auth/login"
                and body.get("username") == "admin"
                and body.get("password") == "admin"
            ):
                return MockResponse(
                    status=200,
                    text_content='{"token": "eyJhbG...", "logged_in": true}',
                )
            if url == "https://example.com/api/auth/login":
                return MockResponse(
                    status=401, text_content='{"error": "invalid credentials"}',
                )
            return MockResponse(status=404)

    checker = DefaultCredChecker(CredAwareMockHTTP())
    findings = await checker.check("https://example.com")

    cred_findings = [f for f in findings if f["id"] == "AI-DEFAULT-CREDS"]
    assert len(cred_findings) >= 1
    assert cred_findings[0]["severity"] == "critical"
    assert "admin/admin" in cred_findings[0]["evidence"]


@pytest.mark.asyncio
async def test_default_cred_checker_no_login_endpoint():
    """If no login endpoint exists, no findings should be produced."""
    from phantomscan.modules.ai_app_security import DefaultCredChecker

    mock_http = MockHTTPClient()
    # All paths return 404 by default
    checker = DefaultCredChecker(mock_http)
    findings = await checker.check("https://example.com")
    assert len(findings) == 0


# ═══════════════════════════════════════════════════════════════════════════
# AIAppSecurityScanner orchestrator test
# ═══════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_orchestrator_runs_without_crash():
    """The main orchestrator should complete without exceptions."""
    from phantomscan.modules.ai_app_security import AIAppSecurityScanner

    mock_http = MockHTTPClient()
    scanner = AIAppSecurityScanner(mock_http)

    observations = [
        {"name": "homepage_body", "value": "<html><body>Hello</body></html>"},
        {"name": "js_urls", "value": []},
        {"name": "response_headers", "value": {}},
    ]

    findings = await scanner.run(
        base_url="https://example.com",
        observations=observations,
    )

    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_orchestrator_integration_with_baas_discovery():
    """The orchestrator should chain secret scanning into RLS auditing."""
    from phantomscan.modules.ai_app_security import AIAppSecurityScanner

    mock_http = MockHTTPClient()

    # Supabase PostgREST schema
    schema = {"paths": {"/profiles": {}}}
    mock_http.get_responses[
        "https://abc12345678901234567.supabase.co/rest/v1/"
    ] = MockResponse(status=200, text_content=json.dumps(schema))

    profiles_data = [{"id": 1, "email": "user@test.com"}]
    mock_http.get_responses[
        "https://abc12345678901234567.supabase.co/rest/v1/profiles?limit=5"
    ] = MockResponse(status=200, text_content=json.dumps(profiles_data))

    anon_jwt = _build_jwt({"role": "anon", "iss": "supabase"})
    html_body = (
        f'<script>'
        f'const SUPABASE_URL = "https://abc12345678901234567.supabase.co";'
        f'const SUPABASE_ANON_KEY = "{anon_jwt}";'
        f'</script>'
    )

    observations = [
        {"name": "homepage_body", "value": html_body},
        {"name": "js_urls", "value": []},
        {"name": "response_headers", "value": {}},
    ]

    scanner = AIAppSecurityScanner(mock_http)
    findings = await scanner.run(
        base_url="https://myapp.com",
        observations=observations,
    )

    # Should have BaaS config findings AND RLS findings
    baas = [f for f in findings if f["id"] == "AI-BAAS-CONFIG-EXPOSED"]
    rls = [f for f in findings if f["id"] == "AI-SUPABASE-RLS-READ"]
    assert len(baas) >= 1
    assert len(rls) >= 1


# ═══════════════════════════════════════════════════════════════════════════
# Shared helpers tests
# ═══════════════════════════════════════════════════════════════════════════


def test_mask_helper():
    """_mask should hide all but the first N characters."""
    from phantomscan.modules.ai_app_security import _mask

    assert _mask("sk-proj-ABCDE12345FGHIJ67890xyzabc", 6) == "sk-pro" + "*" * 20
    assert _mask("short", 6) == "short"
    assert _mask("ab", 6) == "ab"


def test_is_placeholder_helper():
    """_is_placeholder should detect common placeholder patterns."""
    from phantomscan.modules.ai_app_security import _is_placeholder

    assert _is_placeholder("sk-your_api_key_here") is True
    assert _is_placeholder("sk-test_placeholder_value") is True
    assert _is_placeholder("XXXXXXXXXXXXXXX") is True
    assert _is_placeholder("sk-proj-Abc123RealKeyValue99") is False
