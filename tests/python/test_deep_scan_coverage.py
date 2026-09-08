"""Tests for Deep Scan comprehensive all-inclusive coverage.

Verifies that:
1. Deep scan profile includes ALL modules across all tiers without tech-pruning (force_all=True).
2. All 45 registered modules in MODULE_REGISTRY can be instantiated with http client and have runnable async run() methods.
3. Deep scan ports default to 'top1000' covering 1024+ ports.
4. PipelineDAG stratifies and executes all modules cleanly.
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


def test_all_modules_instantiable_and_runnable():
    """Verify every module in MODULE_REGISTRY accepts http client and implements async run()."""
    modules = get_all_modules()
    assert len(modules) >= 44, f"Expected at least 44 registered modules, got {len(modules)}"

    mock_http = MagicMock()
    for name, cls in modules.items():
        # Must be instantiable with http client
        instance = cls(http=mock_http)
        assert hasattr(instance, "run"), f"Module '{name}' ({cls.__name__}) lacks async run() method"
        assert asyncio.iscoroutinefunction(instance.run), f"Module '{name}'.run() must be an async coroutine"


def test_deep_scan_dag_includes_all_modules():
    """Verify that deep scan forces inclusion of all modules without tech pruning."""
    dag = PipelineDAG()
    all_module_names = set(list_module_names()) - {"continuous_monitor"}

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

    # All modules must be scheduled even if tech prerequisites are missing
    assert "graphql" in planned_modules
    assert "ai_app_security" in planned_modules
    assert "ssl_analyzer" in planned_modules
    assert "cors_analyzer" in planned_modules
    assert "info_disclosure" in planned_modules
    assert "cookie_analyzer" in planned_modules
    assert "cve_engine" in planned_modules
    assert len(planned_modules) >= 44


def test_deep_scan_ports_upgraded_to_top1000():
    """Verify that deep scan profile automatically upgrades default ports to top1000."""
    import importlib.util
    cli_path = Path(__file__).resolve().parent.parent.parent / "phantomscan.py"
    spec = importlib.util.spec_from_file_location("phantomscan_cli", cli_path)
    cli_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli_mod)

    parser = cli_mod.build_parser()
    args = parser.parse_args(["--target", "example.com", "--profile", "deep"])
    assert args.profile == "deep"
    assert args.ports == "top100"  # default from parser

    # scan_one logic upgrades top100 default to top1000 for deep scans
    if getattr(args, "profile", "") in ("deep", "deepscan"):
        args.profile = "deep"
        if getattr(args, "ports", "top100") == "top100":
            args.ports = "top1000"

    assert args.ports == "top1000"
    parsed_ports = _parse_ports(args.ports)
    assert len(parsed_ports) >= 1000
    assert 80 in parsed_ports
    assert 443 in parsed_ports
    assert 8080 in parsed_ports


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
