"""Regression tests validating fixes for identified bugs in PhantomScan."""

from __future__ import annotations

import pytest
from typing import Any

from modules.matcher_engine import SafeDSLEvaluator
from modules.scan_cache import ScanCache
from modules.scheduler import ModuleScheduler
from modules.dir_enum import DirectoryEnumerator
from phantomscan.http_client import HTTPResult
from phantomscan.modules.business_logic import BusinessLogicAnalyzer
from phantomscan.modules.jwt_oauth import JWTOAuthTester, _b64url_encode


def test_matcher_engine_rejects_dunder_traversal():
    """Verify that SafeDSLEvaluator blocks sandbox escape via dunder attributes."""
    evaluator = SafeDSLEvaluator()

    # Normal safe expression should work
    assert evaluator.evaluate("status == 200", {"status": 200}) is True
    assert evaluator.evaluate("status == 404", {"status": 200}) is False

    # Dunder attribute traversal must be blocked
    malicious_exprs = [
        "().__class__.__bases__[0].__subclasses__()",
        "body.__class__.__name__ == 'str'",
        "headers.__class__",
        "len.__globals__",
    ]
    for expr in malicious_exprs:
        assert evaluator.evaluate(expr, {"status": 200, "body": "test"}) is False


@pytest.mark.asyncio
async def test_scan_cache_supports_sync_fetch_fn(tmp_path):
    """Verify ScanCache.get_or_fetch handles both sync and async fetch_fn."""
    cache = ScanCache(db_path=tmp_path / "cache.db")

    # 1. Test with synchronous callable
    sync_call_count = 0

    def sync_fetcher():
        nonlocal sync_call_count
        sync_call_count += 1
        return {"data": "sync_result"}

    val1 = await cache.get_or_fetch("sync_key", sync_fetcher, ttl_category="dns")
    assert val1 == {"data": "sync_result"}
    assert sync_call_count == 1

    # Second call should hit cache
    val2 = await cache.get_or_fetch("sync_key", sync_fetcher, ttl_category="dns")
    assert val2 == {"data": "sync_result"}
    assert sync_call_count == 1  # Not called again

    # 2. Test with async callable
    async_call_count = 0

    async def async_fetcher():
        nonlocal async_call_count
        async_call_count += 1
        return {"data": "async_result"}

    val3 = await cache.get_or_fetch("async_key", async_fetcher, ttl_category="dns")
    assert val3 == {"data": "async_result"}
    assert async_call_count == 1


def test_scheduler_tier_ordering_invariant():
    """Verify finding_gate runs before fp_postprocessor, and fp_postprocessor runs before scoring."""
    tiers = ModuleScheduler.TIERS

    finding_gate_tier = None
    fp_postprocessor_tier = None
    score_engine_tier = None

    for tier_num, modules in tiers.items():
        if "finding_gate" in modules:
            finding_gate_tier = tier_num
        if "fp_postprocessor" in modules:
            fp_postprocessor_tier = tier_num
        if "score_engine" in modules:
            score_engine_tier = tier_num

    assert finding_gate_tier is not None, "finding_gate must be in TIERS"
    assert fp_postprocessor_tier is not None, "fp_postprocessor must be in TIERS"
    assert score_engine_tier is not None, "score_engine must be in TIERS"

    # Non-negotiable order: finding_gate < fp_postprocessor < score_engine
    assert finding_gate_tier < fp_postprocessor_tier, (
        f"finding_gate (tier {finding_gate_tier}) must run before fp_postprocessor (tier {fp_postprocessor_tier})"
    )
    assert fp_postprocessor_tier < score_engine_tier, (
        f"fp_postprocessor (tier {fp_postprocessor_tier}) must run before score_engine (tier {score_engine_tier})"
    )


def test_http_result_dict_compatibility():
    """Verify HTTPResult provides dict-like get() and __getitem__ methods."""
    result = HTTPResult(
        url="http://example.com",
        status=200,
        headers={"content-type": "text/html"},
        cookies={"session": "abc"},
        body=b"Hello World",
        raw_set_cookies=[],
        redirect_chain=[],
        response_time_ms=50,
        content_type="text/html",
    )

    # Direct attribute access
    assert result.status == 200
    assert result.body == b"Hello World"

    # Dictionary compatibility access
    assert result.get("status") == 200
    assert result.get("body") == b"Hello World"
    assert result.get("nonexistent", "default") == "default"
    assert result["status"] == 200
    assert result["url"] == "http://example.com"


@pytest.mark.asyncio
async def test_dir_enum_403_reported_as_blocked_info():
    """Verify DirectoryEnumerator reports HTTP 403 as 'info' severity with blocked title."""
    class Mock403Client:
        async def get(self, url: str, **kwargs: Any):
            return HTTPResult(
                url=url,
                status=403,
                headers={"content-type": "text/html"},
                cookies={},
                body=b"Access Denied",
                raw_set_cookies=[],
                redirect_chain=[],
                response_time_ms=30,
                content_type="text/html",
            )

    client = Mock403Client()
    enumerator = DirectoryEnumerator(http_client=client)

    finding = await enumerator.probe_directory("http://example.com", "admin")
    assert finding is not None
    assert finding.severity.lower() == "info"
    assert "Blocked" in finding.title or "403" in finding.evidence


@pytest.mark.asyncio
async def test_business_logic_method_tampering_has_verification_method():
    """Verify BL-METHOD-TAMPER includes verification_method field."""
    class MockMethodClient:
        async def get(self, url: str, **kwargs: Any):
            return await self.request("GET", url, **kwargs)

        async def request(self, method: str, url: str, **kwargs: Any):
            if method == "GET":
                return HTTPResult(
                    url=url, status=200, headers={}, cookies={}, body=b"Original GET body",
                    raw_set_cookies=[], redirect_chain=[], response_time_ms=10, content_type="text/html",
                )
            elif method == "PUT":
                return HTTPResult(
                    url=url, status=200, headers={}, cookies={},
                    body=b"Different body with more than 50 bytes of text here for testing method tampering",
                    raw_set_cookies=[], redirect_chain=[], response_time_ms=10, content_type="text/html",
                )
            return HTTPResult(
                url=url, status=405, headers={}, cookies={}, body=b"Method Not Allowed",
                raw_set_cookies=[], redirect_chain=[], response_time_ms=10, content_type="text/html",
            )

    client = MockMethodClient()
    analyzer = BusinessLogicAnalyzer(http=client)
    findings = await analyzer._test_method_tampering("http://example.com", ["http://example.com/api/item"])
    assert len(findings) >= 1
    tamper_finding = findings[0]
    assert tamper_finding.get("verification_method") == "baseline_differential"


def test_jwt_weak_secret_has_target():
    """Verify _test_weak_secret sets target from endpoint."""
    import hmac
    import hashlib
    import json

    tester = JWTOAuthTester(http=None)
    header = {"alg": "HS256", "typ": "JWT"}
    h_b64 = _b64url_encode(json.dumps(header).encode())
    p_b64 = _b64url_encode(json.dumps({"sub": "user123"}).encode())
    sig = hmac.new(b"secret", f"{h_b64}.{p_b64}".encode(), hashlib.sha256).digest()
    sig_b64 = _b64url_encode(sig)
    token = f"{h_b64}.{p_b64}.{sig_b64}"

    findings = tester._test_weak_secret(token, header, target="http://example.com/api/user")
    assert len(findings) == 1
    assert findings[0]["target"] == "http://example.com/api/user"
    assert findings[0]["confidence"] == "high"


def test_extract_injection_targets_supports_dataclass_observations():
    """Verify extract_injection_targets handles both dict and dataclass observations and forms."""
    from phantomscan.models import Observation
    from phantomscan.web_crawler import DiscoveredForm, FormField
    from phantomscan.injection_target import extract_injection_targets

    forms = [
        DiscoveredForm(
            action="http://example.com/login.aspx",
            method="POST",
            fields=[
                FormField(name="__VIEWSTATE", field_type="hidden", default_value="dummy_vs"),
                FormField(name="tbUsername", field_type="text", default_value=""),
                FormField(name="tbPassword", field_type="password", default_value=""),
                FormField(name="btnLogin", field_type="submit", default_value="Login"),
            ],
        )
    ]
    observations = [
        Observation("parameterized_urls", ["http://example.com/item.php?id=10"], "crawler"),
        Observation("discovered_forms", forms, "crawler"),
    ]

    targets = extract_injection_targets(observations, "http://example.com")
    assert len(targets) >= 2

    # Query param target
    q_target = next((t for t in targets if t.param_name == "id"), None)
    assert q_target is not None
    assert q_target.method == "GET"

    # Form target
    f_target = next((t for t in targets if t.param_name == "tbUsername"), None)
    assert f_target is not None
    assert f_target.method == "POST"
    assert f_target.hidden_fields.get("__VIEWSTATE") == "dummy_vs"
    assert "btnLogin" in f_target.all_params


@pytest.mark.asyncio
async def test_sqli_auth_bypass_detection_on_login_form():
    """Verify SQLi detector identifies login form auth bypass with negative control verification."""
    from phantomscan.modules.sqli_detector import SQLiDetector
    from phantomscan.injection_target import InjectionTarget

    class MockLoginClient:
        async def post(self, url: str, data: dict, allow_redirects: bool = True, **kwargs: Any) -> HTTPResult:
            username = data.get("tbUsername", "")
            # Baseline or negative control: invalid login
            if "OR 1=1" in username:
                return HTTPResult(
                    url=url, status=302, headers={"location": "/Default.aspx", "set-cookie": "frmLogin=admin; path=/"},
                    cookies={"frmLogin": "admin"}, body=b"Redirecting...", raw_set_cookies=[],
                    redirect_chain=[], response_time_ms=15, content_type="text/html",
                )
            return HTTPResult(
                url=url, status=200, headers={}, cookies={},
                body=b"<html><body>Invalid username or password</body></html>",
                raw_set_cookies=[], redirect_chain=[], response_time_ms=15, content_type="text/html",
            )

    client = MockLoginClient()
    detector = SQLiDetector(http=client)
    target = InjectionTarget(
        url="http://example.com/login.aspx",
        method="POST",
        param_name="tbUsername",
        original_value="test",
        all_params={"tbUsername": "test", "tbPassword": "password", "btnLogin": "Login"},
        hidden_fields={"__VIEWSTATE": "abc"},
        target_type="form",
    )

    finding = await detector._test_auth_bypass(target, "tbUsername")
    assert finding is not None
    assert "Authentication Bypass" in finding["title"]
    assert finding["severity"] == "critical"
    assert finding["confidence"] == "high"
    assert finding["verification_method"] == "baseline_differential"


@pytest.mark.asyncio
async def test_path_traversal_windows_and_sink_detection():
    """Verify path traversal scanner detects Windows win.ini and config indicators."""
    from phantomscan.modules.path_traversal import PathTraversalScanner
    from phantomscan.injection_target import InjectionTarget

    class MockTraversalClient:
        async def get(self, url: str, **kwargs: Any) -> HTTPResult:
            if "win.ini" in url:
                return HTTPResult(
                    url=url, status=200, headers={}, cookies={},
                    body=b"[fonts]\nari=arial.ttf\n[extensions]\n",
                    raw_set_cookies=[], redirect_chain=[], response_time_ms=20, content_type="text/plain",
                )
            return HTTPResult(
                url=url, status=200, headers={}, cookies={},
                body=b"<html>Normal page</html>",
                raw_set_cookies=[], redirect_chain=[], response_time_ms=20, content_type="text/html",
            )

    client = MockTraversalClient()
    scanner = PathTraversalScanner(http=client)
    target = InjectionTarget(
        url="http://example.com/view.aspx",
        method="GET",
        param_name="file",
        original_value="document.txt",
        all_params={"file": "document.txt"},
        target_type="query",
    )

    assert PathTraversalScanner._is_file_like(target) is True

    non_file_target = InjectionTarget(
        url="http://example.com/login.aspx",
        method="POST",
        param_name="tbUsername",
        original_value="",
        all_params={"tbUsername": ""},
        target_type="form",
    )
    assert PathTraversalScanner._is_file_like(non_file_target) is False

    finding = await scanner._test_traversal(target, "file")
    assert finding is not None
    assert "Traversal" in finding["title"]
    assert finding["severity"] in ("high", "critical")


@pytest.mark.asyncio
async def test_xss_scanner_uri_sink_and_stored_form_detection():
    """Verify XSS scanner identifies URI attribute sinks and stored comment forms."""
    from phantomscan.modules.xss_scanner import XSSScanner
    from phantomscan.injection_target import InjectionTarget

    class MockXSSClient:
        async def get(self, url: str, **kwargs: Any) -> HTTPResult:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            ad_val = qs.get("NewsAd", [""])[0]
            body = f'<html><iframe id="adsFrame" src="{ad_val}"></iframe></html>'.encode()
            return HTTPResult(
                url=url, status=200, headers={}, cookies={},
                body=body, raw_set_cookies=[], redirect_chain=[], response_time_ms=10, content_type="text/html",
            )

    client = MockXSSClient()
    scanner = XSSScanner(http=client)
    target = InjectionTarget(
        url="http://example.com/ReadNews.aspx",
        method="GET",
        param_name="NewsAd",
        original_value="ads/def.html",
        all_params={"id": "0", "NewsAd": "ads/def.html"},
        target_type="query",
    )

    finding = await scanner._test_reflection(target, "NewsAd")
    assert finding is not None
    assert "Reflected XSS" in finding["title"]
    assert finding["severity"] == "high"
    assert "NewsAd" in finding["evidence"]


@pytest.mark.asyncio
async def test_csrf_detector_safe_methods_and_navigation_forms_not_flagged():
    """Verify CSRF detector does not flag GET navigation/telemetry forms, and FindingGate rejects them."""
    from unittest.mock import MagicMock
    from phantomscan.modules.csrf_detector import CSRFDetector
    from phantomscan.modules.finding_gate import gate_finding

    mock_http = MagicMock()
    detector = CSRFDetector(mock_http)

    # Replicate navigation/telemetry forms from amazon.com
    observations = [
        {"name": "discovered_forms", "value": [
            {"action": "https://www.amazon.com/gp/cart/get", "method": "GET", "fields": [{"name": "ue_back", "type": "hidden"}]},
            {"action": "https://www.amazon.com/business/register/org/get", "method": "GET", "fields": [{"name": "ue_back", "type": "hidden"}]},
            {"action": "https://www.amazon.com/gp/help/customer/account-issues/get", "method": "GET", "fields": [{"name": "ue_back", "type": "hidden"}]},
            {"action": "https://www.amazon.com/ap/signin/get", "method": "GET", "fields": [{"name": "ue_back", "type": "hidden"}]},
            {"action": "https://www.amazon.com/gp/subscribe-and-save/manager/get", "method": "GET", "fields": [{"name": "ue_back", "type": "hidden"}]},
            # Search form using POST
            {"action": "https://www.amazon.com/s", "method": "POST", "fields": [{"name": "field-keywords", "type": "text"}]},
            # Valid state-modifying POST form lacking CSRF token
            {"action": "https://example.com/api/user/update-email", "method": "POST", "fields": [{"name": "email", "type": "text"}]},
        ]}
    ]

    findings = await detector.run("https://www.amazon.com", observations)

    # Ensure none of the GET navigation forms are flagged
    for f in findings:
        assert "amazon.com" not in f["target"]
        assert "HTTP Method: GET" not in f["evidence"]

    # Ensure the real POST update form IS flagged
    assert len(findings) == 1
    assert findings[0]["target"] == "https://example.com/api/user/update-email"
    assert findings[0]["id"] == "CSRF-TOKEN-MISSING"

    # Test FindingGate rejection of GET CSRF candidate
    fp_log = []
    rejected = gate_finding({
        "id": "CSRF-TOKEN-MISSING",
        "title": "Absence of Anti-CSRF Tokens: Form at 'https://example.com/get'",
        "severity": "medium",
        "confidence": "high",
        "evidence": "Form Action: https://example.com/get\nHTTP Method: GET\nForm Fields: id",
        "method": "GET",
    }, fp_log=fp_log)
    assert rejected is None
    assert len(fp_log) == 1
    assert "safe per RFC 7231" in fp_log[0]["gate_rejection_reason"]



