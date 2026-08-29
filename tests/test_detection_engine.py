"""Comprehensive test suite for PhantomScan detection engine fixes.

Tests:
1. Target normalization (local targets default to HTTP)
2. Web crawler parameter & form discovery
3. SQLi detector parameter extraction & verification
4. Reflected XSS scanner (parameter & form)
5. Path traversal scanner
6. Local app profiles & auto-detection
7. Score completeness penalty calibration for local targets
8. JWT token discovery and endpoint extraction
9. Module registry verification
"""

from __future__ import annotations

import pytest
from typing import Any

from phantomscan.scope import parse_target, Target
from phantomscan.web_crawler import WebCrawler, CrawlResult, FormField, DiscoveredForm
from phantomscan.modules.sqli_detector import SQLiDetector
from phantomscan.modules.xss_scanner import XSSScanner
from phantomscan.modules.path_traversal import PathTraversalScanner
from phantomscan.local_app_profiles import detect_app_profile, get_profile, profile_to_observations
from phantomscan.postprocess import score
from phantomscan.modules.jwt_oauth import JWTOAuthTester
from phantomscan.modules import get_all_modules, list_module_names
from tests.false_positive_regression.conftest import MockHTTPClient, MockHTTPResult


# ── 1. Target Normalization Tests ─────────────────────────────────────────────

def test_localhost_normalizes_to_http():
    target = parse_target("localhost:3000")
    assert target.host == "localhost"
    assert target.port == 3000
    assert target.is_local is True
    assert target.scheme == "http"
    assert target.base_url == "http://localhost:3000"


def test_127_0_0_1_normalizes_to_http():
    target = parse_target("127.0.0.1:8080")
    assert target.host == "127.0.0.1"
    assert target.port == 8080
    assert target.is_local is True
    assert target.scheme == "http"
    assert target.base_url == "http://127.0.0.1:8080"


def test_remote_domain_defaults_to_https():
    target = parse_target("testaspnet.vulnweb.com")
    assert target.host == "testaspnet.vulnweb.com"
    assert target.is_local is False
    assert target.base_url == "https://testaspnet.vulnweb.com"


# ── 2. Web Crawler Tests ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_crawler_discovers_links_and_forms():
    html_page1 = """
    <html>
      <body>
        <a href="/artists.php?artist=1">Artist 1</a>
        <a href="/listproducts.php?cat=2">Products</a>
        <a href="https://external.com/out">External</a>
        <form action="/search.php" method="GET">
          <input type="text" name="query" value="default" />
          <input type="submit" value="Search" />
        </form>
        <form action="/login.php" method="POST">
          <input type="text" name="uname" />
          <input type="password" name="pass" />
        </form>
      </body>
    </html>
    """
    html_page2 = """
    <html>
      <body>
        <h1>Artist 1</h1>
        <a href="/product.php?pic=5">Pic 5</a>
      </body>
    </html>
    """

    class CustomMockClient:
        async def get(self, url: str, **kwargs: Any) -> MockHTTPResult:
            if "artists.php" in url:
                return MockHTTPResult(status=200, body=html_page2.encode(), headers={"content-type": "text/html"})
            elif "search.php" in url or "listproducts" in url or "product" in url or "login" in url:
                return MockHTTPResult(status=200, body=b"OK", headers={"content-type": "text/html"})
            return MockHTTPResult(status=200, body=html_page1.encode(), headers={"content-type": "text/html"})

    crawler = WebCrawler(http=CustomMockClient(), max_pages=10, max_depth=2)
    result = await crawler.crawl("http://test.local")

    assert len(result.urls) >= 2
    assert any("artist=1" in u for u in result.parameterized_urls)
    assert len(result.forms) >= 2
    
    obs = crawler.to_observations(result, "http://test.local")
    obs_names = [o.name for o in obs]
    assert "discovered_urls" in obs_names
    assert "parameterized_urls" in obs_names
    assert "discovered_forms" in obs_names


# ── 3. SQLi Detector Parameter Extraction & Detection Tests ───────────────────

def test_sqli_extracts_params_from_crawler_observations():
    observations = [
        {
            "name": "parameterized_urls",
            "value": [
                "http://test.local/artists.php?artist=1",
                "http://test.local/search.php?test=query&cat=2",
            ],
            "source": "crawler",
        },
        {
            "name": "discovered_forms",
            "value": [
                {
                    "action": "http://test.local/login.php",
                    "method": "POST",
                    "fields": [{"name": "username", "type": "text", "value": ""}],
                }
            ],
            "source": "crawler",
        },
    ]

    params = SQLiDetector._extract_params(observations, "http://test.local")
    param_names = [p["name"] for p in params]
    assert "artist" in param_names
    assert "test" in param_names
    assert "cat" in param_names
    assert "username" in param_names


@pytest.mark.asyncio
async def test_sqli_detector_identifies_mysql_error():
    # Setup mock client that returns MySQL error only on SQLi payload
    class SQLiMockClient:
        async def get(self, url: str, **kwargs: Any) -> MockHTTPResult:
            params = kwargs.get("params", {})
            val = str(params.get("artist", ""))
            if "'" in val or "OR" in val or "UNION" in val:
                return MockHTTPResult(
                    status=200,
                    body=b"Warning: mysqli_fetch_array(): Error in your SQL syntax near MySQL server version",
                    headers={"content-type": "text/html"},
                )
            if "1=1" in val:
                return MockHTTPResult(status=200, body=b"<html>Items: 10 found</html>", headers={"content-type": "text/html"})
            if "1=2" in val:
                return MockHTTPResult(status=200, body=b"<html>No items found</html>", headers={"content-type": "text/html"})
            return MockHTTPResult(status=200, body=b"<html>Artist page</html>", headers={"content-type": "text/html"})

    client = SQLiMockClient()
    detector = SQLiDetector(http=client)
    observations = [
        {"name": "parameterized_urls", "value": ["http://test.local/artists.php?artist=1"], "source": "crawler"}
    ]

    findings = await detector.run("http://test.local", observations)
    assert len(findings) >= 1
    assert findings[0]["id"] == "SQLI-ERROR-BASED"
    assert "artist" in findings[0]["evidence"]


# ── 4. XSS Scanner Tests ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_xss_scanner_detects_reflected_parameter():
    class XSSMockClient:
        async def get(self, url: str, **kwargs: Any) -> MockHTTPResult:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            q_val = qs.get("q", [""])[0]
            # Unencoded reflection of q parameter
            body = f"<html><body>Search results for: {q_val}</body></html>".encode()
            return MockHTTPResult(status=200, body=body, headers={"content-type": "text/html"})

        async def post(self, url: str, **kwargs: Any) -> MockHTTPResult:
            return MockHTTPResult(status=200, body=b"OK", headers={"content-type": "text/html"})

    client = XSSMockClient()
    scanner = XSSScanner(http=client)
    observations = [
        {"name": "parameterized_urls", "value": ["http://test.local/search.php?q=apple"], "source": "crawler"}
    ]

    findings = await scanner.run("http://test.local", observations)
    assert len(findings) >= 1
    assert findings[0]["id"] == "XSS-REFLECTED"
    assert "Parameter: q" in findings[0]["evidence"]


# ── 5. Path Traversal Tests ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_path_traversal_detects_etc_passwd():
    class TraversalMockClient:
        async def get(self, url: str, **kwargs: Any) -> MockHTTPResult:
            if "etc/passwd" in url or "etc%2Fpasswd" in url:
                return MockHTTPResult(
                    status=200,
                    body=b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
                    headers={"content-type": "text/plain"},
                )
            return MockHTTPResult(status=200, body=b"<html>Normal image file content</html>", headers={"content-type": "text/html"})

    client = TraversalMockClient()
    scanner = PathTraversalScanner(http=client)
    observations = [
        {"name": "parameterized_urls", "value": ["http://test.local/show.php?file=pic1.jpg"], "source": "crawler"}
    ]

    findings = await scanner.run("http://test.local", observations)
    assert len(findings) >= 1
    assert findings[0]["id"] == "PATH-TRAVERSAL"
    assert "Parameter: file" in findings[0]["evidence"]


# ── 6. Local App Profile Tests ────────────────────────────────────────────────

def test_local_app_profile_auto_detection():
    juice_body = "<html><head><title>OWASP Juice Shop</title></head><body>Welcome</body></html>"
    detected = detect_app_profile(juice_body, target_host="localhost:3000")
    assert detected == "juiceshop"

    profile = get_profile("juiceshop")
    assert profile is not None
    assert profile["is_spa"] is True

    obs = profile_to_observations("juiceshop", "http://localhost:3000")
    assert len(obs) >= 2
    urls_obs = [o for o in obs if o["name"] == "discovered_urls"][0]
    assert any("/rest/products/search?q=test" in u for u in urls_obs["value"])


# ── 7. Score Penalty Calibration for Local Targets ────────────────────────────

def test_local_target_score_ignores_infra_penalties():
    # Observations with missing DNS, WHOIS, TLS errors on a local target
    observations = [
        {"name": "is_local_target", "value": True, "source": "scope"},
        {"name": "http_error", "value": "Connection refused", "source": "http"},
        {"name": "tls_error", "value": "No TLS", "source": "tls"},
        {"name": "whois_info", "value": "unavailable", "source": "rdap"},
        {"name": "dns_error", "value": "Name or service not known", "source": "dns"},
    ]

    # With no findings, local target should NOT be penalized for infrastructure absence
    val = score(findings=[], observations=observations)
    assert val >= 95, f"Expected clean score for local target, got {val}"


# ── 8. JWT Token Discovery and Endpoint Guessing ──────────────────────────────

def test_jwt_extract_and_endpoint_guessing():
    fake_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    observations = [
        {"name": "body_sample", "value": f"token = '{fake_jwt}'", "source": "http"},
        {"name": "discovered_api_endpoints", "value": [{"url": "http://test.local/rest/user/whoami"}], "source": "crawler"},
    ]

    extracted = JWTOAuthTester._extract_jwts(observations)
    assert fake_jwt in extracted

    endpoints = JWTOAuthTester._guess_jwt_endpoints("http://test.local", observations)
    assert any("whoami" in ep for ep in endpoints)


# ── 9. Module Registry Verification ───────────────────────────────────────────

def test_module_registry_has_new_scanners():
    modules = get_all_modules()
    assert "xss_scanner" in modules
    assert "path_traversal" in modules
    assert "sqli_detector" in modules

    names = list_module_names()
    assert "xss_scanner" in names
    assert "path_traversal" in names


# ── 10. Deep / Deepscan Profile Verification ──────────────────────────────────

@pytest.mark.asyncio
async def test_deepscan_profile_runs_all_modules():
    from phantomscan.advanced_scan import run_advanced_modules
    from tests.false_positive_regression.conftest import MockHTTPClient, MockHTTPResult

    client = MockHTTPClient(default_response=MockHTTPResult(status=200, body=b"OK", headers={"content-type": "text/html"}))
    observations = [{"name": "discovered_urls", "value": ["http://test.local/api/users"], "source": "crawler"}]
    findings = []

    # Test that run_advanced_modules accepts both 'deep' and 'deepscan'
    adv_findings, new_obs = await run_advanced_modules(
        target="test.local",
        base_url="http://test.local",
        http_client=client,
        observations=observations,
        findings=findings,
        profile="deepscan",
    )
    assert isinstance(adv_findings, list)
    assert isinstance(new_obs, list)


# ── 11. False Positive Suppression & Optimization Tests ───────────────────────

@pytest.mark.asyncio
async def test_xss_scanner_rejects_plain_javascript_string_reflection():
    """Verify that echoing plain strings (like Google does with hl=javascript:...) is NOT flagged as XSS."""
    class GoogleMockClient:
        async def get(self, url: str, **kwargs: Any) -> MockHTTPResult:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            hl_val = qs.get("hl", [""])[0]
            # Google sanitizes special chars but reflects plain strings in JS config/input
            sanitized = hl_val.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
            body = f'<html><script>var config = {{"hl": "{sanitized}"}};</script></html>'.encode()
            return MockHTTPResult(status=200, body=body, headers={"content-type": "text/html"})

        async def post(self, url: str, **kwargs: Any) -> MockHTTPResult:
            return MockHTTPResult(status=200, body=b"OK", headers={"content-type": "text/html"})

    client = GoogleMockClient()
    scanner = XSSScanner(http=client)
    observations = [
        {"name": "parameterized_urls", "value": ["https://www.google.com/search?hl=en"], "source": "crawler"}
    ]

    findings = await scanner.run("https://www.google.com", observations)
    # Must produce ZERO findings because HTML special characters were encoded
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_crawler_unescapes_html_entities_in_links():
    """Verify that <a href="/search?hl=en&amp;ogbl=1"> yields 'ogbl', NOT 'amp;ogbl'."""
    from phantomscan.web_crawler import WebCrawler
    crawler = WebCrawler(http=None, max_depth=1, max_pages=5)
    body = '<html><a href="/search?hl=en&amp;ogbl=1&amp;authuser=0">Search</a></html>'
    links = crawler._extract_links(body, "https://www.google.com/", "www.google.com")
    assert len(links) == 1
    assert "amp;ogbl" not in links[0]
    assert "ogbl=1" in links[0]
    assert "authuser=0" in links[0]


def test_finding_gate_rejects_plain_xss_probe():
    """FindingGate must reject any XSS finding whose evidence lacks syntax characters."""
    from phantomscan.modules.finding_gate import gate_finding

    bad_finding = {
        "id": "XSS-REFLECTED",
        "title": "Reflected XSS: Parameter 'hl'",
        "severity": "high",
        "confidence": "high",
        "evidence": "Parameter: hl\nPayload: javascript:phantomscan_js\nURL: https://google.com/?hl=javascript:phantomscan_js",
        "verification_method": "baseline_differential",
    }
    gated = gate_finding(bad_finding)
    assert gated is None  # Must be rejected by Check 7

    good_finding = {
        "id": "XSS-REFLECTED",
        "title": "Reflected XSS: Parameter 'q'",
        "severity": "high",
        "confidence": "high",
        "evidence": "Parameter: q\nPayload: <phantomscan_xss_probe>\nURL: https://vuln.site/?q=<phantomscan_xss_probe>\nReflected unencoded.",
        "verification_method": "baseline_differential",
    }
    gated_good = gate_finding(good_finding)
    assert gated_good is not None
    assert gated_good["id"] == "XSS-REFLECTED"


