"""Security tests for HTML report escaping and XSS prevention."""
from __future__ import annotations

from pathlib import Path
import tempfile
import pytest

from phantomscan.reporting import write_html_report


def test_report_escapes_malicious_title():
    """Create report payload with target page title containing <script>alert(1)</script>.
    Assert: <script>alert(1)</script> appears HTML-encoded in the report, not as a live script tag.
    """
    malicious_target = "http://example.com/<script>alert(1)</script>"
    malicious_title = "<img src=x onerror=document.title='XSS'>"
    malicious_evidence = (
        "GET /search?q=<script>alert(1)</script> HTTP/1.1\n"
        "Host: example.com\n\n"
        "HTTP/1.1 200 OK\n\n"
        "<script>alert(1)</script>"
    )

    payload = {
        "target": malicious_target,
        "score": 75,
        "grade": "B",
        "findings": [
            {
                "id": "FIND-XSS-1",
                "title": malicious_title,
                "severity": "high",
                "confidence": "high",
                "category": "injection",
                "target": "http://example.com/search?q=<script>alert(1)</script>",
                "evidence": malicious_evidence,
                "recommendation": "Encode output.",
                "references": ["CWE-79"],
            }
        ],
        "observations": [
            {"name": "server_banner", "value": "Apache/2.4 <script>alert('server')</script>"}
        ],
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        report_file = Path(tmpdir) / "report.html"
        write_html_report(report_file, payload)

        content = report_file.read_text(encoding="utf-8")

        # Must NOT contain live unescaped script tag with alert(1) from target
        assert "<title>PhantomScan Security Report — http://example.com/<script>alert(1)</script></title>" not in content
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in content

        # Finding title must be HTML encoded, never live <img>
        assert "<img src=x onerror=document.title='XSS'>" not in content
        assert "&lt;img src=x onerror=" in content

        # Evidence must be in <pre class="evidence"> and HTML-escaped
        assert '<pre class="evidence"' in content


def test_report_json_bridge_escapes_script_breakout():
    """Verify that chart and D3 JSON script tags do not allow </script> tag breakout."""
    malicious_domain = "http://evil.com</script><script>alert('breakout')</script>"
    payload = {
        "target": malicious_domain,
        "score": 90,
        "grade": "A+",
        "findings": [],
        "observations": [],
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        report_file = Path(tmpdir) / "report.html"
        write_html_report(report_file, payload)
        content = report_file.read_text(encoding="utf-8")

        # Must not contain unescaped script breakout
        assert "</script><script>alert('breakout')</script>" not in content
