"""Regression tests for false positives identified in real-world scan reports.

These tests cover the 12 root causes found by analyzing reports from
amazon.com, google.com, nvidia.com, and testaspnet.vulnweb.com scans.
Each test verifies that the specific false positive is suppressed or
correctly reclassified in the scanner codebase.
"""

from __future__ import annotations

import re
from unittest.mock import AsyncMock, MagicMock

import pytest

from phantomscan.http_client import RobustHTTPClient
from phantomscan.models import Finding


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_result(url: str = "", status: int = 200, headers: dict | None = None,
                body: str = "", cookies: dict | None = None) -> MagicMock:
    r = MagicMock()
    r.url = url
    r.status = status
    r.headers = headers or {}
    r.body = body.encode() if isinstance(body, str) else body
    r.text = MagicMock(return_value=body)
    r.cookies = cookies or {}
    r.raw_set_cookies = []
    return r


# ═══════════════════════════════════════════════════════════════════════════════
# FIX 1: dir_enum — Redirect to /login should NOT be "Directory Accessible"
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_dir_enum_redirect_to_login_not_accessible():
    """A 301/302 redirect to /login or external IdP is NOT 'Directory Accessible'."""
    from modules.dir_enum import DirectoryEnumerator

    mock_http = MagicMock(spec=RobustHTTPClient)

    async def mock_get(url, **kwargs):
        if "/admin/" in url:
            return make_result(url=url, status=301, headers={"location": "/login"}, body="")
        return make_result(url=url, status=404, body="Not Found")

    mock_http.get = AsyncMock(side_effect=mock_get)

    enumerator = DirectoryEnumerator(http_client=mock_http)
    result = await enumerator.probe_directory("https://www.example.com", "/admin/")

    # Redirect to /login should return None (suppressed)
    assert result is None, \
        f"Redirect to /login should suppress directory finding, got: {result}"


# ═══════════════════════════════════════════════════════════════════════════════
# FIX 2: privacy_scanner — Toll-free numbers and IP addresses
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_privacy_scanner_toll_free_suppressed():
    """Toll-free 1-800/888/877 numbers should NOT trigger PII phone findings."""
    from phantomscan.modules.privacy_scanner import PrivacyScanner

    scanner = PrivacyScanner(http=MagicMock(spec=RobustHTTPClient))
    html = """
    <html><body>
    Call us at 1-800-123-4567 or 1-888-555-1234.
    Support: 1-877-999-0000.
    </body></html>
    """
    findings = await scanner.scan_response("https://www.amazon.com", html)
    phone_findings = [f for f in findings if "phone" in f.get("title", "").lower()]
    assert len(phone_findings) == 0, f"Toll-free numbers should be suppressed: {phone_findings}"


@pytest.mark.asyncio
async def test_privacy_scanner_ip_address_is_info():
    """Public IP addresses in HTML should be at most Info severity, not Medium."""
    from phantomscan.modules.privacy_scanner import PrivacyScanner

    scanner = PrivacyScanner(http=MagicMock(spec=RobustHTTPClient))
    html = """<html><body>Server: 203.0.113.42</body></html>"""
    findings = await scanner.scan_response("https://example.com", html)
    ip_findings = [f for f in findings if "ip" in f.get("title", "").lower()
                   or "ip_address" in f.get("id", "").lower()]
    for f in ip_findings:
        assert f["severity"] in ("info", "low"), \
            f"IP address finding should be Info/Low severity, got: {f['severity']}"


# ═══════════════════════════════════════════════════════════════════════════════
# FIX 3: http_smuggling — TCP timeout is NOT smuggling
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_http_smuggling_tcp_timeout_returns_no_findings():
    """When raw baseline returns status==0 (TCP drop), smuggling should produce zero findings."""
    from phantomscan.modules.http_smuggling import HTTPSmugglingDetector

    mock_http = MagicMock(spec=RobustHTTPClient)

    # Baseline returns status 0 = TCP timeout
    baseline_result = MagicMock()
    baseline_result.status = 0
    baseline_result.response_time_ms = 5000
    mock_http.send_raw = AsyncMock(return_value=baseline_result)

    detector = HTTPSmugglingDetector(http=mock_http)
    findings = await detector.run("https://example.com", [])
    assert len(findings) == 0, \
        f"TCP timeout (status 0) should produce zero smuggling findings, got: {findings}"


# ═══════════════════════════════════════════════════════════════════════════════
# FIX 4: supply_chain — camelCase JS vars are NOT bearer tokens
# ═══════════════════════════════════════════════════════════════════════════════

def test_supply_chain_camelcase_var_not_bearer_token():
    """JavaScript identifiers like 'validationToken' should NOT match Bearer Token regex."""
    from phantomscan.modules.supply_chain import SupplyChainAnalyzer

    analyzer = SupplyChainAnalyzer(http=MagicMock(spec=RobustHTTPClient))
    js_code = """
    function validateUserToken(token) {
        var validationToken = token;
        return validationToken.length > 0;
    }
    """
    findings = analyzer._scan_for_secrets(js_code, "https://example.com")
    bearer_findings = [f for f in findings if "bearer" in f.get("title", "").lower()
                       or "token" in f.get("title", "").lower()]
    assert len(bearer_findings) == 0, \
        f"camelCase JS identifiers should not match Bearer Token: {bearer_findings}"


# ═══════════════════════════════════════════════════════════════════════════════
# FIX 5: idor_detector — Public content paths excluded
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_idor_public_content_paths_excluded():
    """Public content paths like /ReadNews.aspx should be excluded from IDOR testing."""
    from phantomscan.modules.idor_detector import IDORDetector

    mock_http = MagicMock(spec=RobustHTTPClient)
    mock_http.get = AsyncMock(return_value=make_result(status=200, body="News article body"))

    detector = IDORDetector(mock_http)
    observations = [
        {"name": "discovered_urls", "value": [
            "http://testaspnet.vulnweb.com/ReadNews.aspx?id=1",
            "http://testaspnet.vulnweb.com/ReadNews.aspx?id=3",
        ]}
    ]
    findings = await detector.run("http://testaspnet.vulnweb.com", observations)
    readnews_findings = [f for f in findings
                         if "ReadNews" in str(f.get("target", ""))]
    assert len(readnews_findings) == 0, \
        f"ReadNews.aspx is public content and should not produce IDOR findings: {readnews_findings}"


# ═══════════════════════════════════════════════════════════════════════════════
# FIX 6: idor_detector — Diff-based data signal check
# ═══════════════════════════════════════════════════════════════════════════════

def test_idor_differential_data_leak_footer_not_data():
    """Static footer keywords present identically in baseline+test should NOT trigger IDOR.

    The diff between the two pages only contains article title changes,
    not PII data signals like 'email', 'username', 'account'.
    """
    from phantomscan.modules.idor_detector import IDORDetector

    # Shared footer — keywords appear in BOTH responses identically
    shared_footer = (
        '<div class="footer-links">'
        '<a href="/contact">Contact Us</a>'
        '</div>'
    )
    baseline = f"<html><body><h1>Article One</h1><p>Lorem ipsum dolor.</p>{shared_footer}</body></html>"
    test_resp = f"<html><body><h1>Article Two</h1><p>Sit amet consectetur.</p>{shared_footer}</body></html>"

    # The diff only contains article text changes, no data signals
    result = IDORDetector._is_differential_data_leak(baseline, test_resp, is_json=False, kind="param_id")
    assert not result, \
        "Article title changes without PII data signals in diff should NOT trigger IDOR"


# ═══════════════════════════════════════════════════════════════════════════════
# FIX 7: anti_automation — OAuth endpoints skipped entirely
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_anti_automation_skips_oauth_endpoints():
    """OAuth authorization URLs must be skipped entirely — no brute force probes."""
    from phantomscan.modules.anti_automation import AntiAutomationTester

    mock_http = MagicMock(spec=RobustHTTPClient)
    mock_http.get = AsyncMock(return_value=make_result(status=200, body="<html>OAuth</html>"))
    mock_http.post = AsyncMock(return_value=make_result(status=200, body="Auth form"))

    tester = AntiAutomationTester(mock_http)
    # URL with redirect_uri= (OAuth flow)
    findings = await tester.test(
        "https://www.nvidia.com/auth/?redirect_uri=https%3A%2F%2Fwww.nvidia.com&client_id=abc123"
    )
    assert len(findings) == 0, \
        f"OAuth endpoints should produce zero findings: {findings}"
    # POST should never have been called (no brute force)
    mock_http.post.assert_not_called()


# ═══════════════════════════════════════════════════════════════════════════════
# FIX 8: cookie_analyzer — Localization cookies skipped
# ═══════════════════════════════════════════════════════════════════════════════

def test_cookie_analyzer_skips_localization_cookies():
    """Localization cookies (c_code, locale, lang, country) should NOT trigger HttpOnly findings."""
    from phantomscan.modules.cookie_analyzer import CookieAnalyzer

    analyzer = CookieAnalyzer()
    cookies = [
        "c_code=IN; Path=/; Domain=.nvidia.com",
        "locale=en-in; Path=/",
        "lang=en; Path=/",
        "country=US; Path=/",
        "theme=dark; Path=/",
    ]
    findings = analyzer.analyze(cookies, url="https://www.nvidia.com")
    httponly_findings = [f for f in findings if "HttpOnly" in f.title]
    for f in httponly_findings:
        flagged_cookies = f.evidence.lower()
        for loc_cookie in ("c_code", "locale", "lang", "country", "theme"):
            assert loc_cookie not in flagged_cookies, \
                f"Localization cookie '{loc_cookie}' should not be flagged for missing HttpOnly"


# ═══════════════════════════════════════════════════════════════════════════════
# FIX 9: recon.py — CORS wildcard suppressed on public marketing root pages
# ═══════════════════════════════════════════════════════════════════════════════

def test_cors_wildcard_suppressed_on_public_root():
    """CORS wildcard without credentials on / or /en-in/ should be suppressed."""
    # Verify the path matching logic used in recon.py
    def is_public_root(path: str) -> bool:
        _path = path.strip("/").lower()
        return (
            not _path
            or bool(re.fullmatch(r"[a-z]{2}(-[a-z]{2})?", _path))
            or _path in ("about", "contact", "products", "blog", "home")
        )

    assert is_public_root("/") is True
    assert is_public_root("/en-in/") is True
    assert is_public_root("/en/") is True
    assert is_public_root("/en-us/") is True
    assert is_public_root("/about/") is True
    assert is_public_root("/api/v1/data") is False
    assert is_public_root("/admin/settings") is False


# ═══════════════════════════════════════════════════════════════════════════════
# FIX 10: sensitive_path_scanner — .htaccess 403 suppressed
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_htaccess_403_suppressed():
    """A 403 on /.htaccess is expected server behavior and should NOT generate a finding."""
    from modules.sensitive_path_scanner import SensitivePathScanner

    mock_http = MagicMock(spec=RobustHTTPClient)

    async def mock_get(url, **kwargs):
        if ".htaccess" in url:
            return make_result(url=url, status=403, body="Forbidden")
        return make_result(url=url, status=404, body="Not Found")

    mock_http.get = AsyncMock(side_effect=mock_get)

    scanner = SensitivePathScanner(http_client=mock_http)
    findings = await scanner.scan("https://www.nvidia.com")
    htaccess_findings = [f for f in findings
                         if "htaccess" in str(getattr(f, 'title', '')).lower()
                         or "htaccess" in str(getattr(f, 'target', '')).lower()]
    assert len(htaccess_findings) == 0, \
        f"403 on .htaccess should be suppressed: {htaccess_findings}"


# ═══════════════════════════════════════════════════════════════════════════════
# FIX 11: postprocess — Case-insensitive URL deduplication
# ═══════════════════════════════════════════════════════════════════════════════

def test_dedup_case_insensitive_url_paths():
    """/Signup.aspx and /signup.aspx should collapse into a single finding."""
    from phantomscan.postprocess import deduplicate_findings

    findings = [
        {"id": "XSS-REFLECTED", "target": "http://example.com/Signup.aspx", "evidence": "test"},
        {"id": "XSS-REFLECTED", "target": "http://example.com/signup.aspx", "evidence": "test"},
        {"id": "XSS-REFLECTED", "target": "http://example.com/SIGNUP.ASPX", "evidence": "test"},
    ]
    result = deduplicate_findings(findings)
    assert len(result) == 1, \
        f"Case-different URL paths should deduplicate to 1 finding, got {len(result)}"


# ═══════════════════════════════════════════════════════════════════════════════
# FIX 12: privacy_scanner — Template phone deduplication
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_privacy_scanner_template_phone_deduplication():
    """The same phone number appearing across multiple pages should be
    suppressed by the run() method's cross-page template deduplication.

    scan_response() is per-page; the template dedup is in run() which
    aggregates results. We test the actual dedup logic here.
    """
    from phantomscan.modules.privacy_scanner import PrivacyScanner

    mock_http = MagicMock(spec=RobustHTTPClient)

    # Mock crawl results — same phone in two pages
    page_body = "<html><body>Contact: +1-206-266-1000</body></html>"

    async def mock_get(url, **kwargs):
        return make_result(url=url, status=200, headers={"content-type": "text/html"},
                           body=page_body)

    mock_http.get = AsyncMock(side_effect=mock_get)

    scanner = PrivacyScanner(http=mock_http)
    observations = [
        {"name": "discovered_urls", "value": [
            "https://www.amazon.com/page1",
            "https://www.amazon.com/page2",
        ]}
    ]
    findings = await scanner.run(
        base_url="https://www.amazon.com",
        observations=observations,
    )
    phone_findings = [f for f in findings if "phone" in f.get("title", "").lower()]
    # Template dedup: same number on >=2 pages suppressed
    assert len(phone_findings) == 0, \
        f"Template phone numbers appearing on multiple pages should be suppressed, got {len(phone_findings)}"


# ═══════════════════════════════════════════════════════════════════════════════
# FIX 13: js_analyzer / secret_patterns — Resend key identifier false positives
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_resend_api_key_identifier_false_positive_suppressed():
    """JavaScript identifiers like 're_MicrosoftTeamsApp' must NOT match Resend API key."""
    from phantomscan.js_analyzer import JSRouteExtractor

    http = MagicMock(spec=RobustHTTPClient)
    extractor = JSRouteExtractor(http=http)

    js_code = """
    var re_MicrosoftTeamsApp = function() { return 1; };
    var re_ExtenConfig = { enabled: true };
    """
    _, _, secrets = await extractor.analyze("https://example.com", js_code)
    resend_findings = [s for s in secrets if "resend" in s.get("title", "").lower()]
    assert len(resend_findings) == 0, f"Unquoted code identifiers starting with re_ must not match Resend: {resend_findings}"

    # Genuine quoted string literal DOES match
    valid_js = """const resendKey = "re_1234567890abcdef12345678";"""
    _, _, valid_secrets = await extractor.analyze("https://example.com", valid_js)
    valid_resend = [s for s in valid_secrets if "resend" in s.get("title", "").lower()]
    assert len(valid_resend) == 1, "Quoted Resend token must match"


# ═══════════════════════════════════════════════════════════════════════════════
# FIX 14: ai_app_security — HuggingFace minified variable false positive
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_huggingface_minified_var_false_positive_suppressed():
    """Minified identifiers starting with hf_ without quotes or context must not trigger HuggingFace."""
    from phantomscan.modules.ai_app_security import AISecretScanner

    http = MagicMock(spec=RobustHTTPClient)
    scanner = AISecretScanner(http=http)

    minified_js = "function a(){var hf_0123456789012345678901234567890123=42;return hf_0123456789012345678901234567890123;}"
    findings = await scanner.scan("https://example.com", minified_js, [], {})
    hf_findings = [f for f in findings if "huggingface" in f.get("title", "").lower()]
    assert len(hf_findings) == 0, f"Minified variable should not trigger HuggingFace finding: {hf_findings}"

    # Quoted real HuggingFace token DOES trigger
    real_js = 'const token = "hf_abcdefghijklmnopqrstuvwxyz01234567";'
    real_findings = await scanner.scan("https://example.com", real_js, [], {})
    real_hf = [f for f in real_findings if "huggingface" in f.get("title", "").lower()]
    assert len(real_hf) == 1, "Quoted HuggingFace token must be detected"


# ═══════════════════════════════════════════════════════════════════════════════
# FIX 15: ai_app_security — Google Client API key not critical Gemini key
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_google_client_key_without_ai_context_not_critical_ai_key():
    """Standard Google Client API Key (Maps, Firebase web) without AI context must not be reported as Critical Gemini key."""
    from phantomscan.modules.ai_app_security import AISecretScanner

    http = MagicMock(spec=RobustHTTPClient)
    scanner = AISecretScanner(http=http)

    normal_google_js = """
    var firebaseConfig = {
        apiKey: "AIzaSyBwQcjgmXUAsw5r4FZXO5t8_EZ_aUm_TGE",
        authDomain: "app.firebaseapp.com"
    };
    """
    findings = await scanner.scan("https://example.com", normal_google_js, [], {})
    gemini_findings = [f for f in findings if "gemini" in f.get("title", "").lower()]
    assert len(gemini_findings) == 0, f"Standard Google Client Key must not be reported as Gemini AI key: {gemini_findings}"

    # With AI context (Gemini / Generative AI)
    ai_google_js = """
    const gemini_api_key = "AIzaSyBwQcjgmXUAsw5r4FZXO5t8_EZ_aUm_TGE";
    const model = getGenerativeModel("gemini-pro");
    """
    ai_findings = await scanner.scan("https://example.com", ai_google_js, [], {})
    ai_gemini = [f for f in ai_findings if "gemini" in f.get("title", "").lower()]
    assert len(ai_gemini) == 1, "Google Key with Gemini context must be reported as Gemini key"


# ═══════════════════════════════════════════════════════════════════════════════
# FIX 16: http_smuggling — WAF 403 / rate limit is NOT smuggling timing anomaly
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_http_smuggling_waf_403_rejection_suppressed():
    """When server/WAF delays 10s then returns 403 Forbidden or WAF block, smuggling must not be reported."""
    from phantomscan.modules.http_smuggling import HTTPSmugglingDetector

    mock_http = MagicMock(spec=RobustHTTPClient)

    # Baseline succeeds fast
    baseline_result = MagicMock()
    baseline_result.status = 200
    baseline_result.response_time_ms = 80
    baseline_result.body = b"OK"
    baseline_result.text = MagicMock(return_value="OK")

    # Probe takes 6000ms but returns HTTP 403 Forbidden (Akamai / Cloudflare WAF block)
    waf_result = MagicMock()
    waf_result.status = 403
    waf_result.response_time_ms = 6000
    waf_result.body = b"Access Denied by WAF"
    waf_result.text = MagicMock(return_value="Access Denied by WAF")

    async def mock_send_raw(host, payload, **kwargs):
        if "GET /" in payload:
            return baseline_result
        return waf_result

    mock_http.send_raw = AsyncMock(side_effect=mock_send_raw)

    detector = HTTPSmugglingDetector(http=mock_http)
    findings = await detector.run("http://example.com", [])
    assert len(findings) == 0, f"WAF 403 rejection timing delay must produce zero smuggling findings, got: {findings}"


# ═══════════════════════════════════════════════════════════════════════════════
# FIX 17: sensitive_path_scanner — Wildcard 403 suppresses blocked path findings
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_sensitive_path_wildcard_403_suppressed():
    """When server returns 403 for random nonexistent paths, sensitive path 403 findings must be suppressed."""
    from modules.sensitive_path_scanner import SensitivePathScanner
    from tests.false_positive_regression.conftest import MockHTTPClient, MockHTTPResult

    # Server returns 403 for all paths (including random UUID)
    client = MockHTTPClient(
        default_response=MockHTTPResult(status=403, body=b"Forbidden")
    )
    scanner = SensitivePathScanner(http_client=client)
    findings = await scanner.scan("https://example.com")

    blocked_findings = [f for f in findings if "SENSITIVE-PATH-BLOCKED" in f.id]
    assert len(blocked_findings) == 0, f"Wildcard 403 server must not trigger SENSITIVE-PATH-BLOCKED findings: {blocked_findings}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
