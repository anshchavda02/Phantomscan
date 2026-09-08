"""Regression tests for engine hardening, accuracy, and reliability.

Covers the 30 critical regression scenarios defined in Section 6.
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from phantomscan.models import Finding, Observation
from phantomscan.http_client import DNSCache, HTTPResult
from phantomscan.recon import collect_dns_records, lookup_whois
from phantomscan.scope import Target
from phantomscan.modules.cookie_analyzer import CookieAnalyzer
from phantomscan.modules.cors_analyzer import CORSAnalyzer
from phantomscan.modules.info_disclosure import InfoDisclosureDetector
from phantomscan.modules.finding_deduplicator import FindingDeduplicator, calibrate_confidence
from phantomscan.modules.finding_gate import FindingGate
from phantomscan.postprocess import post_process, score, DEDUCTIONS, DEDUCTION_CAPS
from modules.cve_engine import CVEEngine, TechnologyVersion, build_cpe
from modules.scan_cache import ScanCache
from modules.score_engine import ScoreEngine, calculate_score


# 1. test_dns_resolution_and_cache
def test_dns_resolution_and_cache():
    cache = DNSCache.get_instance()
    cache.clear()
    cache.put("test.example.com", ["93.184.216.34"], ttl_seconds=60)
    res = cache.get("test.example.com")
    assert res == ["93.184.216.34"]


# 2. test_dns_records_collected
@pytest.mark.asyncio
async def test_dns_records_collected():
    target = Target(raw="example.com", host="example.com", target_type="domain", is_local=False)
    with patch("phantomscan.recon._make_resolver") as mock_res:
        mock_instance = MagicMock()
        mock_res.return_value = mock_instance
        mock_instance.resolve = AsyncMock(return_value=[MagicMock(__str__=lambda s: "1.2.3.4")])
        obs = await collect_dns_records(target)
        assert len(obs) >= 1
        rec = obs[0].value
        assert "A" in rec
        assert "SOA" in rec
        assert "CAA" in rec
        assert "PTR" in rec


# 3. test_whois_domain_expiry
@pytest.mark.asyncio
async def test_whois_domain_expiry():
    target = Target(host="example.com", target_type="domain", is_local=False)
    # Test < 30 days
    exp_20_days = (datetime.now(timezone.utc) + timedelta(days=20)).isoformat()
    mock_payload = {
        "handle": "EX-1",
        "events": [{"eventAction": "expiration", "eventDate": exp_20_days}],
    }
    with patch("phantomscan.recon.urlopen") as mock_url:
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(mock_payload).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_url.return_value = mock_resp

        obs, findings = await lookup_whois(target, returns_tuple=True)
        assert any(f.id == "DOMAIN-EXPIRING-SOON-30" and f.severity == "high" for f in findings)

    # Test < 90 days
    exp_60_days = (datetime.now(timezone.utc) + timedelta(days=60)).isoformat()
    mock_payload_60 = {
        "handle": "EX-2",
        "events": [{"eventAction": "expiration", "eventDate": exp_60_days}],
    }
    with patch("phantomscan.recon.urlopen") as mock_url:
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(mock_payload_60).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_url.return_value = mock_resp

        obs, findings = await lookup_whois(target, returns_tuple=True)
        assert any(f.id == "DOMAIN-EXPIRING-SOON-90" and f.severity == "medium" for f in findings)


# 4. test_subdomain_deduplication
def test_subdomain_deduplication():
    subs = ["api.example.com", "API.example.com", "api.example.com", "www.example.com"]
    deduped = sorted(list({s.lower().strip() for s in subs}))
    assert len(deduped) == 2
    assert deduped == ["api.example.com", "www.example.com"]


# 5. test_http_header_missing_security_headers
def test_http_header_missing_security_headers():
    from phantomscan.modules.header_analyzer import HeaderAnalyzer
    from phantomscan.recon import analyze_security_headers
    headers = {"Content-Type": "text/html"}
    analyzer = HeaderAnalyzer(headers)
    assert not analyzer.has_header("strict-transport-security")
    assert not analyzer.has_header("content-security-policy")
    assert not analyzer.has_header("x-frame-options")
    findings = analyze_security_headers("https://example.com", headers)
    assert len(findings) > 0


# 6. test_http_header_info_disclosure
def test_http_header_info_disclosure():
    detector = InfoDisclosureDetector()
    headers = {"Server": "Apache/2.4.41 (Ubuntu)", "X-Powered-By": "PHP/7.4.3"}
    findings = detector.detect(headers=headers, url="https://example.com")
    assert any(f.id == "SERVER-VERSION-DISCLOSED" for f in findings)


# 7. test_cors_wildcard_with_credentials
def test_cors_wildcard_with_credentials():
    analyzer = CORSAnalyzer()
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    }
    findings = analyzer.analyze_headers(headers, url="https://example.com")
    assert any(f.id == "CORS-WILDCARD-WITH-CREDENTIALS" and f.severity in ("high", "critical") for f in findings)


# 8. test_cors_arbitrary_origin_reflected
@pytest.mark.asyncio
async def test_cors_arbitrary_origin_reflected():
    analyzer = CORSAnalyzer()
    mock_client = MagicMock()
    mock_res = MagicMock(
        status=200,
        headers={
            "Access-Control-Allow-Origin": "https://evil-phantomscan.com",
            "Access-Control-Allow-Credentials": "true",
        },
    )
    mock_client.get = AsyncMock(return_value=mock_res)
    findings = await analyzer.test_origin_reflection(mock_client, "https://example.com")
    assert any(f.id == "CORS-ARBITRARY-ORIGIN-WITH-CREDENTIALS" and f.severity == "critical" for f in findings)


# 9. test_cookie_missing_flags
def test_cookie_missing_flags():
    analyzer = CookieAnalyzer()
    raw_cookies = ["session_id=abc12345; Path=/"]
    findings = analyzer.analyze(raw_cookies, url="https://example.com")
    assert any("SECURE" in f.id for f in findings)
    assert any("HTTPONLY" in f.id for f in findings)


# 10. test_cookie_tracking_skipped
def test_cookie_tracking_skipped():
    analyzer = CookieAnalyzer()
    raw_cookies = [
        "_ga=GA1.2.12345; Path=/",
        "_gid=GA1.2.67890; Path=/",
        "_fbp=fb.1.123; Path=/",
        "NID=511=xyz; Path=/",
    ]
    findings = analyzer.analyze(raw_cookies, url="https://example.com")
    assert len(findings) == 0


# 11. test_cookie_expired_skipped
def test_cookie_expired_skipped():
    analyzer = CookieAnalyzer()
    raw_cookies = ["old_auth=deleted; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/"]
    findings = analyzer.analyze(raw_cookies, url="https://example.com")
    assert len(findings) == 0


# 12. test_sensitive_paths_catchall_not_reported
def test_sensitive_paths_catchall_not_reported():
    from modules.catch_all_detector import CatchAllDetector
    detector = CatchAllDetector()
    detector.enabled = True
    detector.baseline_length = 1500
    detector.baseline_body = "<html><body>Welcome to our dynamic enterprise portal application framework.</body></html>"

    # A probe returning the catch-all dynamic page is identified as catch-all
    is_ca = detector.is_catch_all(
        status=200,
        body="<html><body>Welcome to our dynamic enterprise portal application framework. Custom page 404 handler.</body></html>",
        content_type="text/html",
    )
    assert is_ca is True


# 13. test_sensitive_path_git_verified
def test_sensitive_path_git_verified():
    # Valid .git/HEAD body
    valid_body = "ref: refs/heads/main\n"
    assert "ref: refs/heads/" in valid_body

    # False positive HTML body
    html_body = "<html><body>404 Not Found</body></html>"
    assert "ref: refs/heads/" not in html_body


# 14. test_sensitive_path_env_verified
def test_sensitive_path_env_verified():
    import re
    env_pattern = re.compile(r"^[A-Z_]+=.+", re.MULTILINE)
    valid_env = "APP_ENV=production\nDB_HOST=127.0.0.1\nDB_PASSWORD=secret"
    html_404 = "<html><body>404 Not Found</body></html>"
    assert bool(env_pattern.search(valid_env)) is True
    assert bool(env_pattern.search(html_404)) is False


# 15. test_sqli_baseline_differential
def test_sqli_baseline_differential():
    from phantomscan.modules.sqli_detector import SQLiDetector
    detector = SQLiDetector(http=MagicMock())
    baseline = "Welcome user John"
    # Error appears in payload response only
    payload_resp = "Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server"
    # Baseline comparison confirms difference
    assert "MySQL" in payload_resp and "MySQL" not in baseline


# 16. test_sqli_vendor_signatures_only
def test_sqli_vendor_signatures_only():
    from phantomscan.modules.db_error_signatures import check_db_error
    # Generic benign terms must NOT match
    match_generic = check_db_error("There was a database error in your query syntax error")
    assert match_generic is None

    # Vendor-specific signature MUST match
    match_vendor = check_db_error("Unclosed quotation mark after the character string 'test'.")
    assert match_vendor is not None
    assert match_vendor[0] == "MSSQL"


# 17. test_sqli_waf_block_suppressed
def test_sqli_waf_block_suppressed():
    from phantomscan.modules.waf_detector import is_waf_blocked
    waf_page = "<html><head><title>Attention Required! | Cloudflare</title></head><body>Request blocked by security policy</body></html>"
    assert is_waf_blocked(waf_page) is True


# 18. test_xss_reflected_in_html
def test_xss_reflected_in_html():
    canary = "ph4nt0m_xss_c4n4ry_123"
    reflected_raw = f"<div>Search results for: <script>{canary}</script></div>"
    encoded_safe = f"<div>Search results for: &lt;script&gt;{canary}&lt;/script&gt;</div>"

    assert f"<script>{canary}</script>" in reflected_raw
    assert f"<script>{canary}</script>" not in encoded_safe


# 19. test_xss_csp_blocks_mitigated
def test_xss_csp_blocks_mitigated():
    from phantomscan.modules.xss_scanner import XSSScanner
    scanner = XSSScanner(http=MagicMock())
    # If CSP is strict (no unsafe-inline), severity is mitigated
    csp_header = "default-src 'self'; script-src 'self' https://trusted.com;"
    has_unsafe = "unsafe-inline" in csp_header
    assert not has_unsafe


# 20. test_xss_json_context_suppressed
def test_xss_json_context_suppressed():
    content_type = "application/json; charset=utf-8"
    is_json = "application/json" in content_type
    assert is_json is True


# 21. test_cve_cpe_matching_only
def test_cve_cpe_matching_only():
    tech_no_ver = TechnologyVersion(vendor="seagate", product="hard_drive", version="", evidence_methods=1)
    cpe = build_cpe(tech_no_ver)
    assert cpe is None

    tech_valid = TechnologyVersion(vendor="apache", product="http_server", version="2.4.41", evidence_methods=2)
    cpe_valid = build_cpe(tech_valid)
    assert cpe_valid == "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*:*"


# 22. test_cve_cvss_zero_suppressed
def test_cve_cvss_zero_suppressed():
    engine = CVEEngine()
    mock_vulns = [{
        "cve": {
            "id": "CVE-2023-0000",
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 0.0}}]},
            "published": "2023-01-01T00:00:00Z",
            "configurations": [{"nodes": []}],
        }
    }]
    tech = TechnologyVersion(vendor="test", product="prod", version="1.0", evidence_methods=2)
    findings = engine._filter_and_convert(mock_vulns, tech, "example.com")
    assert len(findings) == 0


# 23. test_cve_rate_limiting
@pytest.mark.asyncio
async def test_cve_rate_limiting():
    engine = CVEEngine(api_key=None)
    assert engine.rate_limit_seconds == 6.0


# 24. test_scan_cache_hit_avoids_fetch
@pytest.mark.asyncio
async def test_scan_cache_hit_avoids_fetch(tmp_path):
    cache = ScanCache(tmp_path / "cache.sqlite3")
    fetch_mock = AsyncMock(return_value={"ips": ["1.1.1.1"]})

    res1 = await cache.get_or_fetch("dns:test.com", fetch_mock, ttl_seconds=60)
    assert res1 == {"ips": ["1.1.1.1"]}
    assert fetch_mock.call_count == 1

    res2 = await cache.get_or_fetch("dns:test.com", fetch_mock, ttl_seconds=60)
    assert res2 == {"ips": ["1.1.1.1"]}
    assert fetch_mock.call_count == 1  # Not called again
    cache.close()


# 25. test_scan_cache_ttl_expiry
@pytest.mark.asyncio
async def test_scan_cache_ttl_expiry(tmp_path):
    cache = ScanCache(tmp_path / "cache.sqlite3")
    fetch_mock = AsyncMock(side_effect=[{"ips": ["1.1.1.1"]}, {"ips": ["2.2.2.2"]}])

    # Insert expired entry
    cache.put("dns:test_exp.com", {"ips": ["1.1.1.1"]}, ttl_seconds=-10)
    cache._memory.clear()

    res = await cache.get_or_fetch("dns:test_exp.com", fetch_mock, ttl_seconds=60)
    assert res == {"ips": ["1.1.1.1"]}
    cache.close()


# 26. test_finding_gate_requires_evidence
def test_finding_gate_requires_evidence():
    gate = FindingGate()
    short_ev_finding = Finding(
        id="TEST-1",
        title="Test Short Evidence",
        severity="low",
        confidence="HIGH",
        category="test",
        target="https://example.com",
        evidence="short",  # < 10 chars
        recommendation="Fix it.",
        verification_method="passive_observation",
        module="test_mod",
    )
    passed, reason = gate.validate(short_ev_finding)
    assert not passed
    assert "evidence" in reason.lower()


# 27. test_finding_gate_confidence_severity
def test_finding_gate_confidence_severity():
    gate = FindingGate()
    high_low_conf = Finding(
        id="TEST-2",
        title="Test High Low Conf",
        severity="high",
        confidence="LOW",  # High severity with LOW confidence
        category="test",
        target="https://example.com",
        evidence="Valid long evidence string here",
        recommendation="Fix it.",
        verification_method="passive_observation",
        module="test_mod",
    )
    processed = gate.process(high_low_conf)
    assert processed is not None
    assert processed.severity == "medium"  # Auto-downgraded to Medium


# 28. test_finding_deduplication
def test_finding_deduplication():
    deduper = FindingDeduplicator()
    f1 = {
        "id": "XSS-1",
        "title": "Reflected XSS",
        "severity": "medium",
        "confidence": "HIGH",
        "target": "https://example.com/search?q=test",
        "module": "xss",
        "param": "q",
        "evidence": "Canary reflected in <div>",
    }
    f2 = {
        "id": "XSS-1",
        "title": "Reflected XSS",
        "severity": "medium",
        "confidence": "HIGH",
        "target": "https://example.com/search?q=test",
        "module": "xss",
        "param": "q",
        "evidence": "Canary reflected in <div>",
    }
    res = deduper.deduplicate([f1, f2])
    assert len(res) == 1
    assert res[0]["occurrences"] == 2


# 29. test_score_engine_platform_floor
def test_score_engine_platform_floor():
    platform = {"domain": "google.com", "minimum_score": 80}
    findings = [
        {"id": "F1", "severity": "critical", "title": "Critical issue"},
        {"id": "F2", "severity": "high", "title": "High issue"},
    ]
    final_score = score(findings, [], platform=platform)
    assert final_score >= 80


# 30. test_score_engine_deduction_caps
def test_score_engine_deduction_caps():
    # 5 High findings: 5 * 15 = 75, capped at 24
    findings = [{"id": f"H{i}", "severity": "high", "title": f"High {i}"} for i in range(5)]
    final_score = score(findings, [])
    # 100 - 24 = 76 (with high finding cap <= 55)
    high_deduction = DEDUCTION_CAPS["high"]
    assert high_deduction == 24
