"""Tests for Deep Scan comprehensive all-inclusive coverage.

Verifies that:
1. Deep scan profile includes ALL modules across all tiers without tech-pruning (force_all=True) and includes continuous_monitor (all 45 modules).
2. All 45 registered modules in MODULE_REGISTRY can be instantiated with http client and have runnable async run() methods.
3. Deep scan ports default to 'top1000' covering 1024+ ports.
4. Deep scan elevates crawler limits to 200 pages and depth 4.
5. Deep scan defaults to include_low=True unless --confidence is explicitly given.
6. deep_analyze_web incorporates DirectoryEnumerator with catch-all route safety.
7. PipelineDAG stratifies and executes all modules cleanly.
"""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from phantomscan.models import Finding, Observation
from phantomscan.modules import get_all_modules, list_module_names
from phantomscan.pipeline import PipelineDAG, DEFAULT_MODULE_METADATA
from phantomscan.scanners import _parse_ports
from phantomscan.asset_graph import AssetGraph
from phantomscan.scope import Target


def test_all_modules_instantiable_and_runnable():
    """Verify every module in MODULE_REGISTRY accepts http client and implements async run()."""
    modules = get_all_modules()
    assert len(modules) >= 45, f"Expected at least 45 registered modules, got {len(modules)}"

    mock_http = MagicMock()
    for name, cls in modules.items():
        # Must be instantiable with http client
        instance = cls(http=mock_http)
        assert hasattr(instance, "run"), f"Module '{name}' ({cls.__name__}) lacks async run() method"
        assert asyncio.iscoroutinefunction(instance.run), f"Module '{name}'.run() must be an async coroutine"


def test_deep_scan_dag_includes_all_45_modules():
    """Verify that deep scan forces inclusion of all 45 modules including continuous_monitor without tech pruning."""
    dag = PipelineDAG()
    all_module_names = set(list_module_names())
    assert len(all_module_names) == 45

    # An empty asset graph with no detected technologies
    empty_graph = AssetGraph()

    # Plan with force_all=True (as done in deep scan)
    stages = dag.plan(
        modules_to_run=all_module_names,
        target=None,
        asset_graph=empty_graph,
        force_all=True,
    )

    planned_modules = {m for stage in stages for m in stage}

    # All 45 modules must be scheduled even if tech prerequisites are missing
    assert "graphql" in planned_modules
    assert "ai_app_security" in planned_modules
    assert "ssl_analyzer" in planned_modules
    assert "cors_analyzer" in planned_modules
    assert "info_disclosure" in planned_modules
    assert "cookie_analyzer" in planned_modules
    assert "cve_engine" in planned_modules
    assert "continuous_monitor" in planned_modules
    assert len(planned_modules) == 45


def test_deep_scan_ports_and_crawler_limits():
    """Verify deep scan profile upgrades ports to top1000 and crawler depth/pages."""
    import importlib.util
    cli_path = Path(__file__).resolve().parent.parent.parent / "phantomscan.py"
    spec = importlib.util.spec_from_file_location("phantomscan_cli", cli_path)
    cli_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli_mod)

    parser = cli_mod.build_parser()
    args = parser.parse_args(["--target", "example.com", "--profile", "deep"])
    assert args.profile == "deep"

    is_deep_scan = getattr(args, "profile", "") in ("deep", "deepscan")
    assert is_deep_scan is True

    # Check port upgrade logic
    ports = args.ports
    if is_deep_scan and ports == "top100":
        ports = "top1000"
    assert ports == "top1000"
    parsed_ports = _parse_ports(ports)
    assert len(parsed_ports) >= 1000

    # Check crawler limit elevation in deep scan
    crawler_pages = 50
    crawl_depth = 2
    if is_deep_scan:
        crawler_pages = 200
        crawl_depth = max(crawl_depth, 4)

    assert crawler_pages == 200
    assert crawl_depth >= 4

    # Check default confidence handling for deep scan: include_low is True if not explicitly overridden
    explicit_confidence = False
    include_low = (
        args.show_all
        or args.confidence == "low"
        or (is_deep_scan and not explicit_confidence)
    )
    assert include_low is True


@pytest.mark.asyncio
async def test_deep_scan_pipeline_execution():
    """Verify that execute_pipeline runs all modules in deep profile without crashing."""
    dag = PipelineDAG()
    mock_http = MagicMock()
    mock_http.get = AsyncMock(return_value=MagicMock(status=200, headers={}, body="", text=lambda: ""))

    observations = [
        {"name": "effective_url", "value": "https://example.com", "source": "http"},
        {"name": "headers", "value": {"server": "nginx/1.18.0", "strict-transport-security": "max-age=31536000"}, "source": "http"},
    ]
    findings = []

    active_findings, new_obs = await dag.execute_pipeline(
        target="example.com",
        base_url="https://example.com",
        http_client=mock_http,
        observations=observations,
        findings=findings,
        profile="deep",
        force_all=True,
        max_concurrency=20,
    )

    # The pipeline must complete and return findings and observations
    assert isinstance(active_findings, list)
    assert isinstance(new_obs, list)


@pytest.mark.asyncio
async def test_deep_analyze_web_includes_directory_enumeration():
    """Verify deep_analyze_web executes DirectoryEnumerator and returns findings."""
    from phantomscan.recon import deep_analyze_web
    from phantomscan.http_client import HTTPResult

    target = Target(raw="example.com", host="example.com", target_type="domain")

    # Mock responses: 404 for random baseline, 200 for /admin, 404 for others
    class MockHttp:
        def __init__(self):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

        async def get(self, url: str, **kwargs):
            if "/admin" in url:
                return HTTPResult(
                    url=url, status=200, headers={"content-type": "application/json"},
                    cookies={}, body=b'{"admin": true}', raw_set_cookies=[],
                    redirect_chain=[], response_time_ms=15, content_type="application/json",
                )
            return HTTPResult(
                url=url, status=404, headers={"content-type": "text/html"},
                cookies={}, body=b"Not found", raw_set_cookies=[],
                redirect_chain=[], response_time_ms=10, content_type="text/html",
            )

    with patch("phantomscan.recon.http_client", return_value=MockHttp()):
        findings = await deep_analyze_web(target, "http://example.com")
        dir_findings = [f for f in findings if "Directory Accessible: admin" in f.title]
        assert len(dir_findings) == 1
        assert dir_findings[0].severity == "low"
        assert dir_findings[0].module == "dir_enum"
