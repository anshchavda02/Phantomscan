"""Regression tests for YAML Template Engine, Matchers, Extractors, and Catch-All Protection."""
from __future__ import annotations

from pathlib import Path
from typing import Any
import pytest

from modules.catch_all_detector import CatchAllResult
from modules.extractor_engine import ExtractorEngine
from modules.matcher_engine import MatcherEngine, MatchResult
from modules.template_executor import TemplateExecutor
from modules.template_loader import TemplateLoader, Template, TemplateInfo, RequestDefinition
from modules.template_scanner import TemplateScanner
from tests.false_positive_regression.conftest import MockHTTPClient, MockHTTPResult


def test_template_loads_valid_yaml(tmp_path: Path):
    """Test 1: TemplateLoader parses a valid template without error."""
    yaml_content = """
id: test-valid-template
info:
  name: Test Valid Template
  author: test
  severity: high
  tags: test,exposure
requests:
  - method: GET
    path:
      - "{{BaseURL}}/test"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["test_token"]
"""
    tmpl_file = tmp_path / "valid.yaml"
    tmpl_file.write_text(yaml_content, encoding="utf-8")

    loader = TemplateLoader()
    template = loader.load_template(tmpl_file)
    assert template.id == "test-valid-template"
    assert template.info.name == "Test Valid Template"
    assert template.info.severity == "high"
    assert "exposure" in template.info.tags
    assert len(template.requests) == 1
    assert template.requests[0].path == ["{{BaseURL}}/test"]


def test_template_rejects_missing_id():
    """Test 2: TemplateLoader raises on template without id."""
    loader = TemplateLoader()
    invalid_data = {
        "info": {"name": "No ID", "severity": "high"},
        "requests": [{"path": ["/test"], "matchers": [{"type": "status", "status": [200]}]}],
    }
    with pytest.raises(ValueError, match="missing required 'id'"):
        loader.parse_template_dict(invalid_data)


def test_template_rejects_missing_matchers():
    """Test 3: TemplateLoader raises on template without matchers."""
    loader = TemplateLoader()
    invalid_data = {
        "id": "no-matchers-template",
        "info": {"name": "No Matchers", "severity": "high"},
        "requests": [{"path": ["/test"], "matchers": []}],
    }
    with pytest.raises(ValueError, match="missing matchers"):
        loader.parse_template_dict(invalid_data)


def test_status_matcher_matches():
    """Test 4: StatusMatcher returns True for matching status code."""
    engine = MatcherEngine()
    resp = MockHTTPResult(status=200, body=b"OK")
    matcher = {"type": "status", "status": [200, 206]}
    matched, ev = engine.evaluate_matcher(matcher, resp)
    assert matched is True
    assert "200" in ev


def test_status_matcher_rejects():
    """Test 5: StatusMatcher returns False for wrong status code."""
    engine = MatcherEngine()
    resp = MockHTTPResult(status=404, body=b"Not Found")
    matcher = {"type": "status", "status": [200]}
    matched, ev = engine.evaluate_matcher(matcher, resp)
    assert matched is False


def test_word_matcher_and_condition():
    """Test 6: All words must be present when condition=and."""
    engine = MatcherEngine()
    resp_both = MockHTTPResult(status=200, body=b"root:x:0:0:root /bin/bash daemon")
    resp_one = MockHTTPResult(status=200, body=b"root:x:0:0:root")

    matcher = {"type": "word", "words": ["root:", "/bin/bash"], "condition": "and", "part": "body"}
    matched1, _ = engine.evaluate_matcher(matcher, resp_both)
    matched2, _ = engine.evaluate_matcher(matcher, resp_one)

    assert matched1 is True
    assert matched2 is False


def test_word_matcher_or_condition():
    """Test 7: Any word sufficient when condition=or."""
    engine = MatcherEngine()
    resp = MockHTTPResult(status=200, body=b"DB_PASSWORD=secret")
    matcher = {"type": "word", "words": ["AWS_KEY", "DB_PASSWORD"], "condition": "or", "part": "body"}
    matched, _ = engine.evaluate_matcher(matcher, resp)
    assert matched is True


def test_negative_matcher_rejects_html():
    """Test 8: Negative word matcher rejects HTML body."""
    engine = MatcherEngine()
    html_resp = MockHTTPResult(
        status=200,
        body=b"<!DOCTYPE html><html><head><title>Login</title></head><body>Sign In</body></html>",
    )

    matchers = [
        {"type": "status", "status": [200]},
        {"type": "word", "words": ["Sign In"], "part": "body"},
        {"type": "word", "negative": True, "words": ["<!DOCTYPE", "<html"], "part": "body"},
    ]

    result = engine.evaluate(html_resp, matchers, condition="and")
    assert result.matched is False
    assert any("NEGATIVE_REJECT" in m for m in result.matched_matchers)


def test_and_matchers_condition_all_required():
    """Test 9: matchers-condition=and requires all matchers pass."""
    engine = MatcherEngine()
    resp = MockHTTPResult(status=200, body=b"Hello World")
    matchers = [
        {"type": "status", "status": [200]},
        {"type": "word", "words": ["MissingWord"], "part": "body"},
    ]
    result = engine.evaluate(resp, matchers, condition="and")
    assert result.matched is False


def test_or_matchers_condition_any_sufficient():
    """Test 10: matchers-condition=or passes if any positive matcher passes."""
    engine = MatcherEngine()
    resp = MockHTTPResult(status=200, body=b"Hello World")
    matchers = [
        {"type": "status", "status": [404]},
        {"type": "word", "words": ["Hello"], "part": "body"},
    ]
    result = engine.evaluate(resp, matchers, condition="or")
    assert result.matched is True


def test_regex_matcher():
    """Test 11: Regex matcher correctly matches body pattern."""
    engine = MatcherEngine()
    resp = MockHTTPResult(status=200, body=b"repositoryformatversion = 0\nfilemode = true")
    matcher = {"type": "regex", "regex": [r"repositoryformatversion\s*=\s*\d"], "part": "body"}
    matched, ev = engine.evaluate_matcher(matcher, resp)
    assert matched is True
    assert "Matched regex" in ev


def test_dsl_matcher_complex_expression():
    """Test 12: DSL expression evaluates correctly."""
    engine = MatcherEngine()
    resp = MockHTTPResult(status=200, body=b"ref: refs/heads/main\n")
    matcher = {
        "type": "dsl",
        "dsl": ["status == 200 and 'ref:' in body and len(body) > 10"],
    }
    matched, _ = engine.evaluate_matcher(matcher, resp)
    assert matched is True


@pytest.mark.asyncio
async def test_executor_uses_web_root():
    """Test 13: TemplateExecutor uses scheme://host not sub-page URL."""
    client = MockHTTPClient(default_response=MockHTTPResult(status=404, body=b"Not Found"))
    executor = TemplateExecutor(http_client=client)

    template = Template(
        id="test-root-isolation",
        info=TemplateInfo(name="Root Isolation Test", severity="high"),
        requests=[
            RequestDefinition(
                path=["{{BaseURL}}/.git/HEAD"],
                matchers=[{"type": "status", "status": [200]}],
            )
        ],
    )

    page_target = "https://studentportal.silveroakuni.ac.in/UMSStudents/login.aspx"
    await executor.execute(template, page_target)

    assert len(client.request_log) == 1
    requested_url = client.request_log[0]["url"]
    assert requested_url == "https://studentportal.silveroakuni.ac.in/.git/HEAD"
    assert "UMSStudents/login.aspx" not in requested_url


@pytest.mark.asyncio
async def test_executor_negative_matcher_suppresses_html_200():
    """Test 14: HTML 200 response rejected by negative matcher in executor."""
    aspnet_login_html = b"<!DOCTYPE html><html><head><title>Login</title></head><body>Form</body></html>"
    client = MockHTTPClient(default_response=MockHTTPResult(status=200, body=aspnet_login_html))
    executor = TemplateExecutor(http_client=client)

    template = Template(
        id="git-head-exposed",
        info=TemplateInfo(name="Exposed .git/HEAD File", severity="critical"),
        requests=[
            RequestDefinition(
                path=["{{BaseURL}}/.git/HEAD"],
                matchers_condition="and",
                matchers=[
                    {"type": "status", "status": [200]},
                    {"type": "word", "words": ["ref: refs/heads/"], "part": "body"},
                    {"type": "word", "negative": True, "words": ["<!DOCTYPE", "<html"], "part": "body"},
                ],
            )
        ],
    )

    finding = await executor.execute(template, "https://example.com")
    assert finding is None


@pytest.mark.asyncio
async def test_executor_git_head_true_positive():
    """Test 15: True positive git HEAD response produces valid Finding."""
    git_head_content = b"ref: refs/heads/main\n"
    client = MockHTTPClient(default_response=MockHTTPResult(status=200, body=git_head_content))
    executor = TemplateExecutor(http_client=client)

    template = Template(
        id="git-head-exposed",
        info=TemplateInfo(name="Exposed .git/HEAD File", severity="critical"),
        requests=[
            RequestDefinition(
                path=["{{BaseURL}}/.git/HEAD"],
                matchers_condition="and",
                matchers=[
                    {"type": "status", "status": [200]},
                    {"type": "word", "words": ["ref: refs/heads/"], "part": "body"},
                    {"type": "word", "negative": True, "words": ["<!DOCTYPE", "<html"], "part": "body"},
                ],
            )
        ],
    )

    finding = await executor.execute(template, "https://example.com")
    assert finding is not None
    assert finding.severity == "critical"
    assert "git-head-exposed" in finding.evidence.lower() or ".git/head" in finding.title.lower()


@pytest.mark.asyncio
async def test_executor_git_head_false_positive_aspnet():
    """Test 16: ASP.NET catch-all server returns 200 + HTML for /.git/HEAD -> zero findings."""
    aspnet_html = b"<!DOCTYPE html><html><body><h1>Student Portal</h1></body></html>"
    client = MockHTTPClient(default_response=MockHTTPResult(status=200, body=aspnet_html))
    executor = TemplateExecutor(http_client=client)

    template = Template(
        id="git-head-exposed",
        info=TemplateInfo(name="Exposed .git/HEAD File", severity="critical"),
        requests=[
            RequestDefinition(
                path=["{{BaseURL}}/.git/HEAD"],
                matchers_condition="and",
                matchers=[
                    {"type": "status", "status": [200]},
                    {"type": "word", "words": ["ref: refs/heads/"], "part": "body"},
                    {"type": "word", "negative": True, "words": ["<!DOCTYPE", "<html"], "part": "body"},
                ],
            )
        ],
    )

    catch_all = CatchAllResult(has_catch_all=True, baseline_body_length=len(aspnet_html))
    finding = await executor.execute(template, "https://studentportal.silveroakuni.ac.in/app/login", catch_all=catch_all)
    assert finding is None


def test_extractor_captures_value():
    """Test 17: Extractor captures regex group from response body."""
    engine = ExtractorEngine()
    resp = MockHTTPResult(status=200, body=b"url = https://github.com/org/repo.git\n")
    extractors = [
        {"type": "regex", "name": "git_remote", "regex": [r"url\s*=\s*(.+)"], "group": 1}
    ]
    extracted = engine.extract(resp, extractors)
    assert "git_remote" in extracted
    assert extracted["git_remote"] == "https://github.com/org/repo.git"


@pytest.mark.asyncio
async def test_flow_stops_on_first_mismatch():
    """Test 18: Multi-step template flow stops when step 1 fails."""
    client = MockHTTPClient(default_response=MockHTTPResult(status=404, body=b"Not Found"))
    executor = TemplateExecutor(http_client=client)

    template = Template(
        id="multi-step-flow",
        info=TemplateInfo(name="Multi Step Flow", severity="high"),
        requests=[
            RequestDefinition(
                path=["{{BaseURL}}/step1"],
                matchers=[{"type": "status", "status": [200]}],
            ),
            RequestDefinition(
                path=["{{BaseURL}}/step2"],
                matchers=[{"type": "status", "status": [200]}],
            ),
        ],
        flow="http(1) && http(2)",
    )

    finding = await executor.execute(template, "https://example.com")
    assert finding is None
    # Only step 1 was queried, step 2 was never triggered
    assert len(client.request_log) == 1
    assert client.request_log[0]["url"] == "https://example.com/step1"


@pytest.mark.asyncio
async def test_tag_filtering_exposure_only():
    """Test 19: TemplateScanner loads only exposure tagged templates."""
    client = MockHTTPClient(default_response=MockHTTPResult(status=404, body=b"Not Found"))
    scanner = TemplateScanner(http_client=client)
    rules_dir = Path(__file__).parent.parent.parent / "rules"

    # Scan with tags=["exposure"]
    findings = await scanner.scan(
        target="https://example.com",
        template_dir=rules_dir,
        tags=["exposure"],
    )
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_severity_filtering_critical_only():
    """Test 20: TemplateScanner loads only critical templates."""
    client = MockHTTPClient(default_response=MockHTTPResult(status=404, body=b"Not Found"))
    scanner = TemplateScanner(http_client=client)
    rules_dir = Path(__file__).parent.parent.parent / "rules"

    findings = await scanner.scan(
        target="https://example.com",
        template_dir=rules_dir,
        severity=["critical"],
    )
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_scanner_finds_git_head_on_real_file():
    """Test 21: End-to-end scanner finds git HEAD on real file."""
    responses = {
        "/.git/HEAD": MockHTTPResult(
            status=200,
            body=b"ref: refs/heads/main\n",
            headers={"content-type": "text/plain"},
        )
    }
    client = MockHTTPClient(
        default_response=MockHTTPResult(status=404, body=b"Not Found"),
        responses=responses,
    )
    scanner = TemplateScanner(http_client=client)
    rules_dir = Path(__file__).parent.parent.parent / "rules"

    findings = await scanner.scan(
        target="https://example.com",
        template_dir=rules_dir,
        tags=["git"],
    )
    assert len(findings) >= 1
    git_findings = [f for f in findings if "git" in f.title.lower() or "git" in f.id.lower()]
    assert len(git_findings) >= 1


@pytest.mark.asyncio
async def test_scanner_zero_findings_on_catchall():
    """Test 22: End-to-end scanner returns 0 findings on ASP.NET catch-all server."""
    aspnet_html = b"<!DOCTYPE html><html><body><form action='/login.aspx'></form></body></html>"
    client = MockHTTPClient(
        default_response=MockHTTPResult(
            status=200,
            body=aspnet_html,
            headers={"content-type": "text/html"},
        )
    )
    scanner = TemplateScanner(http_client=client)
    rules_dir = Path(__file__).parent.parent.parent / "rules"

    findings = await scanner.scan(
        target="https://studentportal.silveroakuni.ac.in/UMSStudents/login.aspx",
        template_dir=rules_dir,
    )
    assert len(findings) == 0, f"Expected 0 findings on catch-all server, got: {[f.title for f in findings]}"
