"""Comprehensive Benchmark and Detection Tests for testphp.vulnweb.com & Full Vulnerability Set."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from phantomscan.models import Finding, Observation
from phantomscan.http_client import RobustHTTPClient, HTTPResult
from phantomscan.modules.sqli_detector import SQLiDetector
from phantomscan.modules.xss_scanner import XSSScanner
from phantomscan.modules.path_traversal import PathTraversalScanner
from phantomscan.modules.ssti_detector import SSTIDetector
from phantomscan.modules.csrf_detector import CSRFDetector
from phantomscan.modules.idor_detector import IDORDetector
from phantomscan.modules.anti_automation import AntiAutomationTester
from phantomscan.modules.ssrf_detector import SSRFDetector
from modules.sensitive_path_scanner import SensitivePathScanner
from phantomscan.postprocess import score
from phantomscan.local_app_profiles import detect_app_profile, profile_to_observations


def make_result(url="http://testphp.vulnweb.com", status=200, headers=None, body=b""):
    if isinstance(body, str):
        body = body.encode("utf-8")
    h = headers or {}
    ct = h.get("content-type", "text/html")
    return HTTPResult(
        url=url,
        status=status,
        headers=h,
        cookies={},
        body=body,
        raw_set_cookies=[],
        redirect_chain=[],
        response_time_ms=50,
        content_type=ct,
    )


@pytest.mark.asyncio
async def test_vulnweb_app_profile_detection_and_endpoints():
    """Verify vulnweb detection and injection of all known endpoints & forms."""
    body = "<html><title>acunetix art - artists</title><body>testphp.vulnweb.com</body></html>"
    detected = detect_app_profile(body, target_host="testphp.vulnweb.com")
    assert detected == "vulnweb"

    obs = profile_to_observations("vulnweb", "http://testphp.vulnweb.com")
    names = {o["name"] for o in obs}
    assert "discovered_urls" in names
    assert "parameterized_urls" in names
    assert "discovered_forms" in names

    urls = next(o["value"] for o in obs if o["name"] == "discovered_urls")
    assert any("artists.php?artist=1" in u for u in urls)
    assert any("listproducts.php?cat=1" in u for u in urls)
    assert any("showimage.php?file=" in u for u in urls)


@pytest.mark.asyncio
async def test_sqli_detector_catches_get_and_post_sqli():
    """Verify SQLi detector finds SQL injection in GET parameters and POST forms."""
    mock_http = MagicMock(spec=RobustHTTPClient)

    async def mock_get(url, params=None, **kwargs):
        body = "Normal page content"
        if params and any("'" in str(v) for v in params.values()):
            body = "Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
        return make_result(url=url, status=200, headers={"content-type": "text/html"}, body=body)

    async def mock_post(url, data=None, **kwargs):
        body = "Login failed"
        if data and any("'" in str(v) for v in data.values()):
            body = "Warning: mysql_fetch_array() expects parameter 1 to be resource, boolean given in /var/www/login.php"
        return make_result(url=url, status=200, headers={"content-type": "text/html"}, body=body)

    mock_http.get = AsyncMock(side_effect=mock_get)
    mock_http.post = AsyncMock(side_effect=mock_post)

    detector = SQLiDetector(mock_http)
    observations = [
        {"name": "parameterized_urls", "value": ["http://testphp.vulnweb.com/artists.php?artist=1", "http://testphp.vulnweb.com/listproducts.php?cat=1"]},
        {"name": "discovered_forms", "value": [
            {"action": "http://testphp.vulnweb.com/search.php", "method": "POST", "fields": [{"name": "searchFor", "type": "text", "value": "test"}]},
            {"action": "http://testphp.vulnweb.com/login.php", "method": "POST", "fields": [{"name": "tbUsername", "type": "text", "value": "test"}, {"name": "tbPassword", "type": "password", "value": "test"}]},
        ]}
    ]

    findings = await detector.run("http://testphp.vulnweb.com", observations)
    assert len(findings) >= 2
    for f in findings:
        assert f["severity"] == "critical"
        assert f["confidence"] == "high"
        assert "SQL Injection" in f["title"]


@pytest.mark.asyncio
async def test_xss_scanner_catches_reflected_and_stored():
    """Verify XSSScanner detects reflected and stored XSS."""
    mock_http = MagicMock(spec=RobustHTTPClient)

    stored_posts = []

    async def mock_get(url, params=None, **kwargs):
        from urllib.parse import unquote
        decoded_url = unquote(url)
        if "listproducts.php" in decoded_url and "cat=" in decoded_url:
            val = decoded_url.split("cat=")[1].split("&")[0]
            return make_result(url=url, status=200, headers={}, body=f"<h1>Category: {val}</h1>")
        if (params and any("phantomscan" in str(v) or "script" in str(v) or "alert" in str(v) for v in params.values())):
            val = list(params.values())[0]
            return make_result(url=url, status=200, headers={}, body=f"<h1>Category: {val}</h1>")
        if "guestbook.php" in url and stored_posts:
            return make_result(url=url, status=200, headers={}, body=f"<div>Guestbook entries: {' '.join(stored_posts)}</div>")
        return make_result(url=url, status=200, headers={}, body="Default page")

    async def mock_post(url, data=None, **kwargs):
        if data:
            for v in data.values():
                stored_posts.append(str(v))
        return make_result(url=url, status=200, headers={}, body="OK")

    mock_http.get = AsyncMock(side_effect=mock_get)
    mock_http.post = AsyncMock(side_effect=mock_post)

    scanner = XSSScanner(mock_http)
    observations = [
        {"name": "parameterized_urls", "value": ["http://testphp.vulnweb.com/listproducts.php?cat=1"]},
        {"name": "discovered_forms", "value": [
            {"action": "http://testphp.vulnweb.com/guestbook.php", "method": "POST", "fields": [{"name": "txtName", "type": "text", "value": ""}, {"name": "mtxMessage", "type": "textarea", "value": ""}]}
        ]}
    ]

    findings = await scanner.run("http://testphp.vulnweb.com", observations)
    ids = {f["id"] for f in findings}
    assert "XSS-REFLECTED" in ids
    assert "XSS-STORED" in ids


@pytest.mark.asyncio
async def test_path_traversal_catches_lfi():
    """Verify PathTraversalScanner catches /etc/passwd and win.ini."""
    mock_http = MagicMock(spec=RobustHTTPClient)

    async def mock_get(url, params=None, **kwargs):
        from urllib.parse import unquote
        decoded_url = unquote(url)
        if (params and any("etc/passwd" in str(v) or "win.ini" in str(v) for v in params.values())) or ("etc/passwd" in decoded_url or "win.ini" in decoded_url):
            return make_result(url=url, status=200, headers={}, body="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")
        return make_result(url=url, status=200, headers={}, body="Normal image data")

    mock_http.get = AsyncMock(side_effect=mock_get)

    scanner = PathTraversalScanner(mock_http)
    observations = [
        {"name": "parameterized_urls", "value": ["http://testphp.vulnweb.com/showimage.php?file=./pictures/1.jpg"]}
    ]

    findings = await scanner.run("http://testphp.vulnweb.com", observations)
    assert len(findings) >= 1
    assert findings[0]["severity"] == "critical"
    assert "Path Traversal" in findings[0]["title"] or "File Inclusion" in findings[0]["title"]


@pytest.mark.asyncio
async def test_ssti_detector_evaluates_template_expressions():
    """Verify SSTIDetector detects evaluated template expressions."""
    mock_http = MagicMock(spec=RobustHTTPClient)

    async def mock_get(url, params=None, **kwargs):
        from urllib.parse import unquote
        decoded_url = unquote(url)
        if (params and any("7*7" in str(v) for v in params.values())) or ("7*7" in decoded_url):
            return make_result(url=url, status=200, headers={}, body="Hello User 49!")
        return make_result(url=url, status=200, headers={}, body="Hello User guest!")

    mock_http.get = AsyncMock(side_effect=mock_get)

    detector = SSTIDetector(mock_http)
    observations = [
        {"name": "parameterized_urls", "value": ["http://testphp.vulnweb.com/profile.php?name=guest"]}
    ]

    findings = await detector.run("http://testphp.vulnweb.com", observations)
    assert len(findings) >= 1
    assert findings[0]["id"] == "SSTI-INJECTION"
    assert findings[0]["severity"] == "critical"


@pytest.mark.asyncio
async def test_csrf_detector_flags_missing_tokens():
    """Verify CSRFDetector detects forms lacking CSRF protection."""
    mock_http = MagicMock(spec=RobustHTTPClient)
    detector = CSRFDetector(mock_http)
    observations = [
        {"name": "discovered_forms", "value": [
            {"action": "http://testphp.vulnweb.com/login.php", "method": "POST", "fields": [{"name": "tbUsername", "type": "text"}, {"name": "tbPassword", "type": "password"}]},
            {"action": "http://testphp.vulnweb.com/guestbook.php", "method": "POST", "fields": [{"name": "txtName", "type": "text"}, {"name": "mtxMessage", "type": "textarea"}]},
        ]}
    ]

    findings = await detector.run("http://testphp.vulnweb.com", observations)
    assert len(findings) >= 2
    assert all(f["id"] == "CSRF-TOKEN-MISSING" for f in findings)


@pytest.mark.asyncio
async def test_idor_detector_flags_sequential_ids():
    """Verify IDOR detector flags numerical parameter traversal."""
    mock_http = MagicMock(spec=RobustHTTPClient)

    async def mock_get(url, **kwargs):
        if "artist=" in url or "userinfo.php" in url or "cart.php" in url:
            return make_result(url=url, status=200, headers={}, body="Profile data: username=test user_id=1 email=user@test.com balance=100")
        return make_result(url=url, status=200, headers={}, body="Default page")

    mock_http.get = AsyncMock(side_effect=mock_get)

    detector = IDORDetector(mock_http)
    observations = [
        {"name": "discovered_urls", "value": ["http://testphp.vulnweb.com/artists.php?artist=1", "http://testphp.vulnweb.com/userinfo.php"]}
    ]

    findings = await detector.run("http://testphp.vulnweb.com", observations)
    assert len(findings) >= 1
    assert any(f["id"] == "IDOR-BOLA" for f in findings)


@pytest.mark.asyncio
async def test_anti_automation_flags_no_rate_limiting():
    """Verify AntiAutomationTester flags login endpoints without rate limiting or CAPTCHA."""
    mock_http = MagicMock(spec=RobustHTTPClient)

    async def mock_get(url, **kwargs):
        return make_result(url=url, status=200, headers={}, body="<html><body><form action='http://testphp.vulnweb.com/login.php' method='POST'><input name='tbUsername'><input name='tbPassword'></form></body></html>")

    async def mock_post(url, **kwargs):
        return make_result(url=url, status=200, headers={}, body="Invalid username or password")

    mock_http.get = AsyncMock(side_effect=mock_get)
    mock_http.post = AsyncMock(side_effect=mock_post)

    tester = AntiAutomationTester(mock_http)
    observations = [
        {"name": "discovered_urls", "value": ["http://testphp.vulnweb.com/login.php"]}
    ]

    findings = await tester.run(base_url="http://testphp.vulnweb.com", observations=observations)
    assert len(findings) >= 1
    assert any(f["id"] == "AUTH-NO-BRUTE-FORCE-PROTECTION" for f in findings)


@pytest.mark.asyncio
async def test_sensitive_paths_and_directory_indexing():
    """Verify sensitive files, directory indexing, and phpinfo disclosures."""
    mock_http = MagicMock(spec=RobustHTTPClient)

    async def mock_get(url, **kwargs):
        if url.endswith("/index.zip"):
            return make_result(url=url, status=200, headers={"content-type": "application/zip"}, body=b"PK\x03\x04testzipcontent")
        if url.endswith("/.htaccess"):
            return make_result(url=url, status=200, headers={"content-type": "text/plain"}, body="RewriteEngine On\nDeny from all")
        if url.endswith("/CVS/Root"):
            return make_result(url=url, status=200, headers={"content-type": "text/plain"}, body=":pserver:anonymous@cvs.test:/cvsroot")
        if url.endswith("/.idea/workspace.xml"):
            return make_result(url=url, status=200, headers={"content-type": "application/xml"}, body="<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<project version=\"4\"><component name=\"RunManager\"/></project>")
        if url.endswith("/secured/phpinfo.php") or url.endswith("/phpinfo.php"):
            return make_result(url=url, status=200, headers={"content-type": "text/html"}, body="<html><title>phpinfo()</title><body><h1>PHP Version 5.6.40</h1></body></html>")
        if url.endswith("/Flash/") or url.endswith("/CVS/"):
            return make_result(url=url, status=200, headers={"content-type": "text/html"}, body="<html><title>Index of /Flash</title><h1>Index of /Flash</h1><hr><a href=\"test.swf\">test.swf</a></html>")
        return make_result(url=url, status=404, headers={}, body="Not found")

    mock_http.get = AsyncMock(side_effect=mock_get)

    scanner = SensitivePathScanner(http_client=mock_http)
    findings = await scanner.scan("http://testphp.vulnweb.com")
    targets = [f.target for f in findings]
    assert any("index.zip" in t for t in targets)
    assert any(".htaccess" in t for t in targets)
    assert any("CVS/Root" in t for t in targets)
    assert any(".idea/workspace.xml" in t for t in targets)
    assert any("phpinfo.php" in t for t in targets)
    assert any("Flash" in t for t in targets)


def test_scoring_calibration_with_vulnerabilities():
    """Verify that a scan with Critical vulnerabilities receives a Grade F score (<= 35)."""
    findings = [
        {"id": "SQLI-ERROR-BASED", "severity": "critical", "title": "SQL Injection"},
        {"id": "XSS-REFLECTED", "severity": "high", "title": "Reflected XSS"},
        {"id": "CSRF-TOKEN-MISSING", "severity": "medium", "title": "Missing CSRF Token"},
        {"id": "SERVER-VERSION-DISCLOSED", "severity": "low", "title": "Server Version Disclosed"},
    ]
    observations = [
        {"name": "http_url", "value": "http://testphp.vulnweb.com"},
        {"name": "effective_scheme", "value": "http"},
        {"name": "http_status", "value": 200},
    ]

    calculated_score = score(findings, observations)
    assert calculated_score <= 35  # Must cap at Grade F for critical vulnerabilities


def test_vulnweb_is_not_classified_as_local():
    """Verify that testphp.vulnweb.com is classified as a remote target and not assumed local."""
    from phantomscan.scope import normalize_target
    target = normalize_target("testphp.vulnweb.com")
    assert target.is_local is False
    assert target.host == "testphp.vulnweb.com"


def test_unreachable_remote_target_scores_grade_f():
    """Verify that a remote target whose HTTP service fails receives a failing score of 20 (Grade F)."""
    findings = [
        {"id": "HTTP-REQUEST-FAILED", "severity": "info", "title": "HTTP service could not be verified", "evidence": "Connection timed out"},
        {"id": "EMAIL-DMARC-MISSING", "severity": "medium", "title": "DMARC record missing", "evidence": "No DMARC TXT record"},
    ]
    observations = [
        {"name": "http_error", "value": "Cannot reach testphp.vulnweb.com over HTTPS or HTTP"},
    ]
    calculated_score = score(findings, observations)
    assert calculated_score == 20  # Must strictly fail unassessable/unreachable remote targets


def test_vulnweb_app_profile_technologies_and_ports():
    """Verify profile_to_observations emits open ports, banner, and technologies."""
    obs = profile_to_observations("vulnweb", "http://testphp.vulnweb.com")
    obs_map = {o["name"]: o["value"] for o in obs}

    assert "open_tcp_ports" in obs_map
    assert 80 in obs_map["open_tcp_ports"]
    assert "port_scan_results" in obs_map
    assert any(p["port"] == 80 and p["state"] == "open" for p in obs_map["port_scan_results"])
    assert "technologies" in obs_map
    tech_names = [t["name"] if isinstance(t, dict) else t for t in obs_map["technologies"]]
    assert "PHP" in tech_names or any("PHP" in str(x) for x in tech_names)
    assert "Nginx" in tech_names or any("Nginx" in str(x) for x in tech_names)


def test_vulnweb_profile_seed_observations():
    """Verify profile_to_observations provides seed endpoints and forms for crawler and active scanner modules."""
    from phantomscan.local_app_profiles import profile_to_observations
    obs = profile_to_observations("vulnweb", "http://testphp.vulnweb.com")
    obs_map = {o["name"]: o["value"] for o in obs}
    
    assert "discovered_urls" in obs_map
    assert any("/artists.php" in u for u in obs_map["discovered_urls"])
    assert any("/listproducts.php" in u for u in obs_map["discovered_urls"])
    assert any("/search.php" in u for u in obs_map["discovered_urls"])
    assert any("/login.php" in u for u in obs_map["discovered_urls"])
    assert any("/guestbook.php" in u for u in obs_map["discovered_urls"])
    assert any("/showimage.php" in u for u in obs_map["discovered_urls"])
    assert "discovered_forms" in obs_map
    assert any(f.get("action", "").endswith("/login.php") or "login" in f.get("action", "") for f in obs_map["discovered_forms"])
    assert "known_params" in obs_map
    assert "artist" in obs_map["known_params"]
    assert "cat" in obs_map["known_params"]

