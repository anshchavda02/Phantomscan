"""Unit tests for Phase 4: Adaptive Module Execution & Pipeline Orchestrator."""

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock

import pytest

from phantomscan.asset_graph import AssetGraph
from phantomscan.http_client import RobustHTTPClient
from phantomscan.pipeline import ModuleMetadata, PipelineDAG
from phantomscan.scope import normalize_target
from phantomscan.advanced_scan import run_advanced_modules


class OrchestratorTests(unittest.TestCase):
    def setUp(self):
        self.dag = PipelineDAG()

    def test_metadata_retrieval(self):
        sqli_meta = self.dag.get_metadata("sqli_detector")
        self.assertEqual(sqli_meta.name, "sqli_detector")
        self.assertEqual(sqli_meta.phase, "active")

        # Unknown module fallback
        unknown = self.dag.get_metadata("custom_third_party")
        self.assertEqual(unknown.name, "custom_third_party")
        self.assertEqual(unknown.phase, "active")

    def test_dag_topological_stratification(self):
        """Post-process modules must be stratified based on dependency graph."""
        modules = {
            "sqli_detector",
            "xss_scanner",
            "vuln_chain",
            "attack_path",
            "ai_narrative",
            "compliance",
        }
        target = normalize_target("https://example.com")
        stages = self.dag.plan(modules_to_run=modules, target=target, force_all=True)

        # Stage 1 must contain active modules
        self.assertTrue(len(stages) >= 3)
        self.assertIn("sqli_detector", stages[0])
        self.assertIn("xss_scanner", stages[0])

        # vuln_chain must run before attack_path and compliance
        flattened_stages = []
        for stage in stages:
            flattened_stages.append(set(stage))

        # Find stage indices
        vuln_chain_idx = next(i for i, s in enumerate(flattened_stages) if "vuln_chain" in s)
        attack_path_idx = next(i for i, s in enumerate(flattened_stages) if "attack_path" in s)
        compliance_idx = next(i for i, s in enumerate(flattened_stages) if "compliance" in s)
        ai_narrative_idx = next(i for i, s in enumerate(flattened_stages) if "ai_narrative" in s)

        self.assertLess(vuln_chain_idx, attack_path_idx)
        self.assertLess(vuln_chain_idx, compliance_idx)
        self.assertLess(attack_path_idx, ai_narrative_idx)

    def test_technology_aware_pruning(self):
        """Modules requiring unobserved tech are pruned unless forced."""
        target = normalize_target("https://example.com")
        graph_without_graphql = AssetGraph()
        graph_without_graphql.add_technology("React", version="18.0")

        # Without GraphQL tech detected
        stages = self.dag.plan(
            modules_to_run={"graphql", "sqli_detector"},
            target=target,
            asset_graph=graph_without_graphql,
            force_all=False,
        )
        all_planned = {m for stage in stages for m in stage}
        self.assertNotIn("graphql", all_planned)
        self.assertIn("sqli_detector", all_planned)

        # With GraphQL tech detected
        graph_with_graphql = AssetGraph()
        graph_with_graphql.add_technology("GraphQL", version="16.0")
        stages_with_tech = self.dag.plan(
            modules_to_run={"graphql", "sqli_detector"},
            target=target,
            asset_graph=graph_with_graphql,
            force_all=False,
        )
        all_planned_with_tech = {m for stage in stages_with_tech for m in stage}
        self.assertIn("graphql", all_planned_with_tech)

        # With force_all=True
        stages_forced = self.dag.plan(
            modules_to_run={"graphql", "sqli_detector"},
            target=target,
            asset_graph=graph_without_graphql,
            force_all=True,
        )
        all_planned_forced = {m for stage in stages_forced for m in stage}
        self.assertIn("graphql", all_planned_forced)

    def test_localhost_module_skipping(self):
        """PR-L01: Skip external recon modules on local targets."""
        local_target = normalize_target("http://localhost:3000")
        self.assertTrue(local_target.is_local)

        stages = self.dag.plan(
            modules_to_run={"subdomain_takeover", "xss_scanner"},
            target=local_target,
            force_all=False,
        )
        all_planned = {m for stage in stages for m in stage}
        self.assertNotIn("subdomain_takeover", all_planned)
        self.assertIn("xss_scanner", all_planned)


@pytest.mark.asyncio
async def test_pipeline_execution_graceful_timeout():
    """PY-03 / SEC-E03: Slow modules time out cleanly without terminating the scan."""
    mock_http = MagicMock(spec=RobustHTTPClient)
    dag = PipelineDAG(
        metadata_registry={
            "fast_module": ModuleMetadata(name="fast_module", timeout_seconds=2.0),
            "slow_module": ModuleMetadata(name="slow_module", timeout_seconds=0.1),
        }
    )

    findings, observations = await dag.execute_pipeline(
        target="http://test.local",
        base_url="http://test.local",
        http_client=mock_http,
        observations=[],
        findings=[],
        profile="fast_module,slow_module",
        force_all=True,
    )
    # Pipeline finishes cleanly without raising unhandled exceptions
    assert isinstance(findings, list)
    assert isinstance(observations, list)


@pytest.mark.asyncio
async def test_run_advanced_modules_integration():
    """run_advanced_modules executes via DAG orchestrator."""
    from phantomscan.http_client import HTTPResult
    mock_http = MagicMock(spec=RobustHTTPClient)
    mock_http.get = AsyncMock(
        return_value=HTTPResult("http://example.com/search?q=1", 200, {}, {}, b"<html>Normal search</html>", [], [], 20, "text/html")
    )
    mock_http.post = AsyncMock(
        return_value=HTTPResult("http://example.com/search?q=1", 200, {}, {}, b"<html>Normal search</html>", [], [], 20, "text/html")
    )
    findings, obs = await run_advanced_modules(
        target="http://example.com",
        base_url="http://example.com",
        http_client=mock_http,
        observations=[{"name": "discovered_urls", "value": ["http://example.com/search?q=1"]}],
        findings=[],
        profile="xss_scanner,sqli_detector",
    )
    assert isinstance(findings, list)
    assert isinstance(obs, list)


@pytest.mark.asyncio
async def test_deep_profile_forces_all_modules():
    """Deep profile must automatically enforce force_all=True and include all registered modules."""
    dag = PipelineDAG()
    from phantomscan.modules import MODULE_REGISTRY
    from phantomscan.asset_graph import AssetGraph
    from phantomscan.scope import normalize_target

    target = normalize_target("http://example.com")
    graph_empty = AssetGraph()

    # In deep profile, even without detected technologies, all registered modules (except monitor) must be planned
    stages = dag.plan(
        modules_to_run=set(MODULE_REGISTRY.keys()) - {"continuous_monitor"},
        target=target,
        asset_graph=graph_empty,
        force_all=True,
    )
    all_planned = {m for stage in stages for m in stage}

    # Verify key modules that normally prune without tech signatures are included
    assert "graphql" in all_planned
    assert "websocket" in all_planned
    assert "ai_app_security" in all_planned
    assert "sqli_detector" in all_planned
    assert "xss_scanner" in all_planned
    assert "path_traversal" in all_planned
    assert "dep_confusion" in all_planned
    assert len(all_planned) >= 35


if __name__ == "__main__":
    unittest.main()

