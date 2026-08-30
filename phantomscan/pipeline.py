"""Adaptive Module Execution Pipeline and Dependency DAG Orchestrator for PhantomScan.

Provides:
- ModuleMetadata schema (dependencies, required technologies, local skip rules, timeouts)
- PipelineDAG for dependency resolution, topological stratification, and intelligent pruning
- Async pipeline executor with concurrency bounding (SEC-E03) and failure isolation (PY-03)
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import logging
import time
from typing import Any, Type

from phantomscan.asset_graph import AssetGraph
from phantomscan.http_client import RobustHTTPClient
from phantomscan.models import Finding, Observation
from phantomscan.modules import MODULE_REGISTRY, get_all_modules, get_module_class
from phantomscan.scope import NormalizedTarget, normalize_target

logger = logging.getLogger(__name__)


# ── Module Metadata Schema ───────────────────────────────────────────────────


@dataclass
class ModuleMetadata:
    """Execution metadata and runtime prerequisites for a security module."""

    name: str
    phase: str = "active"  # "recon", "discovery", "active", "post_process"
    depends_on: list[str] = field(default_factory=list)
    requires_tech: list[str] = field(default_factory=list)
    requires_features: list[str] = field(default_factory=list)
    is_local_skip: bool = False
    timeout_seconds: float = 45.0
    description: str = ""


# Default module specifications for all 38+ PhantomScan modules
DEFAULT_MODULE_METADATA: dict[str, ModuleMetadata] = {
    # Active testing modules
    "sqli_detector": ModuleMetadata(
        name="sqli_detector",
        phase="active",
        timeout_seconds=60.0,
        description="Multi-layer SQL injection testing with error and timing verification",
    ),
    "xss_scanner": ModuleMetadata(
        name="xss_scanner",
        phase="active",
        timeout_seconds=50.0,
        description="Reflected and DOM-based XSS verification across injection points",
    ),
    "path_traversal": ModuleMetadata(
        name="path_traversal",
        phase="active",
        timeout_seconds=40.0,
        description="Path traversal and local file inclusion probing with body verification",
    ),
    "ssrf": ModuleMetadata(
        name="ssrf",
        phase="active",
        timeout_seconds=40.0,
        description="Server-Side Request Forgery probing on URL parameters",
    ),
    "business_logic": ModuleMetadata(
        name="business_logic",
        phase="active",
        timeout_seconds=45.0,
        description="Business logic, price tampering, and quantity manipulation testing",
    ),
    "idor": ModuleMetadata(
        name="idor",
        phase="active",
        timeout_seconds=40.0,
        description="Insecure Direct Object Reference and numerical resource traversal",
    ),
    "jwt_oauth": ModuleMetadata(
        name="jwt_oauth",
        phase="active",
        timeout_seconds=30.0,
        description="JWT signature verification, none-algorithm, and OAuth flow checks",
    ),
    "oob_detector": ModuleMetadata(
        name="oob_detector",
        phase="active",
        timeout_seconds=35.0,
        description="Out-of-band injection and callback verification",
    ),
    "race_condition": ModuleMetadata(
        name="race_condition",
        phase="active",
        timeout_seconds=30.0,
        description="Concurrency limit and limit-overrun race condition tester",
    ),
    "http_smuggling": ModuleMetadata(
        name="http_smuggling",
        phase="active",
        timeout_seconds=30.0,
        description="CL.TE and TE.CL HTTP request smuggling probe",
    ),
    "prototype_pollution": ModuleMetadata(
        name="prototype_pollution",
        phase="active",
        timeout_seconds=30.0,
        description="Client-side and server-side JavaScript prototype pollution detection",
    ),
    "graphql": ModuleMetadata(
        name="graphql",
        phase="active",
        requires_tech=["graphql", "apollo", "hasura"],
        timeout_seconds=35.0,
        description="GraphQL introspection, query batching, and field suggestion testing",
    ),
    "websocket": ModuleMetadata(
        name="websocket",
        phase="active",
        timeout_seconds=30.0,
        description="WebSocket origin validation, auth bypass, and cross-site hijacking",
    ),
    "supply_chain": ModuleMetadata(
        name="supply_chain",
        phase="active",
        timeout_seconds=35.0,
        description="Third-party JS dependency CVE lookup and integrity checking",
    ),
    "cloud_metadata": ModuleMetadata(
        name="cloud_metadata",
        phase="active",
        timeout_seconds=25.0,
        description="Cloud provider instance metadata endpoint exposure checks",
    ),
    "second_order": ModuleMetadata(
        name="second_order",
        phase="active",
        timeout_seconds=40.0,
        description="Second-order SQLi and stored reflection verification",
    ),
    "auth_session": ModuleMetadata(
        name="auth_session",
        phase="active",
        timeout_seconds=30.0,
        description="Session fixation, cookie attribute validation, and logout invalidation",
    ),
    "auth_profiles": ModuleMetadata(
        name="auth_profiles",
        phase="active",
        timeout_seconds=40.0,
        description="Multi-role authenticated access control matrix verification",
    ),
    "diff_env": ModuleMetadata(
        name="diff_env",
        phase="active",
        timeout_seconds=30.0,
        description="Differential staging vs production environment scanner",
    ),
    "mobile_api": ModuleMetadata(
        name="mobile_api",
        phase="active",
        timeout_seconds=30.0,
        description="Mobile API endpoint parameter and secret extractor",
    ),
    "dep_confusion": ModuleMetadata(
        name="dep_confusion",
        phase="active",
        timeout_seconds=30.0,
        description="Dependency confusion and package namespace squatter checker",
    ),
    "subdomain_takeover": ModuleMetadata(
        name="subdomain_takeover",
        phase="active",
        is_local_skip=True,
        timeout_seconds=35.0,
        description="Dangling CNAME and cloud provider subdomain takeover detection",
    ),
    "anti_automation": ModuleMetadata(
        name="anti_automation",
        phase="active",
        timeout_seconds=30.0,
        description="Rate limiting, CAPTCHA bypass, and brute-force protection analysis",
    ),
    "privacy_scanner": ModuleMetadata(
        name="privacy_scanner",
        phase="active",
        timeout_seconds=30.0,
        description="PII leak, third-party tracker, and cookie consent compliance checker",
    ),
    "ai_app_security": ModuleMetadata(
        name="ai_app_security",
        phase="active",
        requires_tech=["ai", "llm", "openai", "anthropic", "langchain", "ollama", "vllm", "vibe"],
        timeout_seconds=45.0,
        description="Prompt injection, tool calling tampering, and system prompt leakage",
    ),
    "stateful_scanner": ModuleMetadata(
        name="stateful_scanner",
        phase="active",
        timeout_seconds=40.0,
        description="Multi-step stateful workflow and wizard security verification",
    ),
    # Post-processing modules (Order & DAG dependent)
    "vuln_chain": ModuleMetadata(
        name="vuln_chain",
        phase="post_process",
        depends_on=[],
        timeout_seconds=20.0,
        description="Correlation engine chaining individual findings into compound exploits",
    ),
    "attack_path": ModuleMetadata(
        name="attack_path",
        phase="post_process",
        depends_on=["vuln_chain"],
        timeout_seconds=20.0,
        description="Graph-based visual attack path synthesis",
    ),
    "compliance": ModuleMetadata(
        name="compliance",
        phase="post_process",
        depends_on=["vuln_chain"],
        timeout_seconds=20.0,
        description="Mapping clean findings to SOC2, ISO27001, HIPAA, and PCI-DSS controls",
    ),
    "ai_narrative": ModuleMetadata(
        name="ai_narrative",
        phase="post_process",
        depends_on=["attack_path"],
        timeout_seconds=25.0,
        description="Executive summary and remediation narrative generator",
    ),
    "trend_predictor": ModuleMetadata(
        name="trend_predictor",
        phase="post_process",
        depends_on=[],
        timeout_seconds=15.0,
        description="Historical finding velocity and security posture trend forecast",
    ),
    "expiry_calendar": ModuleMetadata(
        name="expiry_calendar",
        phase="post_process",
        depends_on=[],
        timeout_seconds=15.0,
        description="SSL cert, domain registration, and API key expiration calendar",
    ),
    "scan_merger": ModuleMetadata(
        name="scan_merger",
        phase="post_process",
        depends_on=[],
        timeout_seconds=15.0,
        description="Cross-target team scan result aggregation and diffing",
    ),
    "continuous_monitor": ModuleMetadata(
        name="continuous_monitor",
        phase="post_process",
        timeout_seconds=20.0,
        description="Cron-based recurring scan scheduler and alerting module",
    ),
    "ticketing": ModuleMetadata(
        name="ticketing",
        phase="post_process",
        timeout_seconds=15.0,
        description="Jira and GitHub Issues automated finding dispatcher",
    ),
    "video_summary": ModuleMetadata(
        name="video_summary",
        phase="post_process",
        timeout_seconds=30.0,
        description="Rendered scan walkthrough video generator",
    ),
    "remediation_verifier": ModuleMetadata(
        name="remediation_verifier",
        phase="post_process",
        timeout_seconds=20.0,
        description="Differential re-tester confirming remediated findings",
    ),
    "finding_chat": ModuleMetadata(
        name="finding_chat",
        phase="post_process",
        timeout_seconds=20.0,
        description="Interactive assistant for exploratory finding queries",
    ),
}


# ── Pipeline DAG Engine ───────────────────────────────────────────────────────


class PipelineDAG:
    """Dependency Directed Acyclic Graph orchestrator for modular scan execution."""

    def __init__(self, metadata_registry: dict[str, ModuleMetadata] | None = None) -> None:
        self.registry: dict[str, ModuleMetadata] = dict(metadata_registry or DEFAULT_MODULE_METADATA)

    def get_metadata(self, name: str) -> ModuleMetadata:
        """Retrieve metadata for a module or return a generic active metadata profile."""
        return self.registry.get(
            name,
            ModuleMetadata(name=name, phase="active", timeout_seconds=35.0),
        )

    def plan(
        self,
        modules_to_run: set[str],
        target: NormalizedTarget | None = None,
        asset_graph: AssetGraph | None = None,
        force_all: bool = False,
    ) -> list[list[str]]:
        """Resolve dependencies and stratify modules into executable parallel stages.

        Pruning rules:
        1. Local targets skip external-only modules (PR-L01).
        2. Technology-specific modules are pruned if target lacks prerequisite tech unless force_all is True.
        3. Post-process modules are ordered topologically according to their dependencies.
        """
        pruned_modules: set[str] = set()

        for name in list(modules_to_run):
            meta = self.get_metadata(name)

            # Rule 1: Localhost skip (PR-L01)
            if target and target.is_local and meta.is_local_skip:
                logger.info("Skipping module '%s' on local target %s (PR-L01)", name, target.host)
                continue

            # Rule 2: Technology-aware conditional execution
            if asset_graph and meta.requires_tech and not force_all:
                has_prereq = any(asset_graph.has_technology(tech) for tech in meta.requires_tech)
                if not has_prereq:
                    logger.debug(
                        "Pruning module '%s': required technologies %s not detected in asset graph",
                        name, meta.requires_tech,
                    )
                    continue

            pruned_modules.add(name)

        # Separate active and post-processing modules
        active_set = {m for m in pruned_modules if self.get_metadata(m).phase != "post_process"}
        post_set = {m for m in pruned_modules if self.get_metadata(m).phase == "post_process"}

        stages: list[list[str]] = []

        # Stage 1: Active testing modules (can run concurrently in batch)
        if active_set:
            stages.append(sorted(list(active_set)))

        # Stages 2+: Topological stratification of post-process modules
        remaining_post = set(post_set)
        completed_post: set[str] = set()

        while remaining_post:
            # Find modules whose dependencies are satisfied
            layer = [
                m for m in remaining_post
                if all(dep in completed_post or dep not in post_set for dep in self.get_metadata(m).depends_on)
            ]

            if not layer:
                # Circular dependency or unsatisfied dependency fallback: take remaining
                layer = sorted(list(remaining_post))

            stages.append(sorted(layer))
            for m in layer:
                completed_post.add(m)
                remaining_post.remove(m)

        return stages

    async def execute_pipeline(
        self,
        target: str,
        base_url: str,
        http_client: RobustHTTPClient,
        observations: list[dict[str, Any]],
        findings: list[dict[str, Any]],
        profile: str = "advanced",
        asset_graph: AssetGraph | None = None,
        max_concurrency: int = 15,
        force_all: bool = False,
        **kwargs: Any,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Execute the module pipeline with DAG scheduling, concurrency limits, and failure isolation."""
        all_modules = get_all_modules()
        active_findings: list[dict[str, Any]] = list(findings)
        new_observations: list[dict[str, Any]] = list(observations)

        # Normalize target for scope & local checks
        try:
            norm_target = normalize_target(base_url or target)
        except Exception:
            norm_target = None

        # Build or leverage AssetGraph for tech-aware pruning
        if asset_graph is None:
            asset_graph = AssetGraph.from_observations(new_observations, base_url=base_url)

        # Determine requested module set from profile
        if profile in ("advanced", "deep", "deepscan"):
            modules_to_run = set(all_modules.keys()) - {"continuous_monitor"}
        elif profile == "monitor":
            modules_to_run = {"continuous_monitor"}
        elif "," in profile:
            modules_to_run = {m.strip() for m in profile.split(",") if m.strip() in all_modules}
        else:
            modules_to_run = set(all_modules.keys()) - {"continuous_monitor"}

        # In deep scan mode, include everything by forcing all modules without pruning
        if profile in ("deep", "deepscan"):
            force_all = True

        # Generate execution stages via DAG planner
        stages = self.plan(
            modules_to_run=modules_to_run,
            target=norm_target,
            asset_graph=asset_graph,
            force_all=force_all,
        )

        semaphore = asyncio.Semaphore(max_concurrency)

        async def _run_single_module(name: str, is_post: bool) -> tuple[str, list[dict[str, Any]] | None, dict[str, Any]]:
            if name not in all_modules:
                return name, None, {"name": name, "status": "skipped", "duration": 0.0, "findings": 0, "engine": "python"}

            meta = self.get_metadata(name)
            cls = all_modules[name]

            async with semaphore:
                t0 = time.perf_counter()
                try:
                    instance = cls(http=http_client)
                    if is_post:
                        coro = instance.run(
                            base_url=base_url,
                            observations=new_observations,
                            findings=active_findings,
                            baseline_path=kwargs.get("baseline_path"),
                            webhook_url=kwargs.get("webhook_url"),
                        )
                    else:
                        coro = instance.run(
                            base_url=base_url,
                            observations=new_observations,
                            auth_cookie=kwargs.get("auth_cookie"),
                            auth_token=kwargs.get("auth_token"),
                            source_path=kwargs.get("source_path"),
                            check_slopsquatting=kwargs.get("check_slopsquatting", False),
                        )

                    result = await asyncio.wait_for(coro, timeout=meta.timeout_seconds)
                    elapsed = time.perf_counter() - t0
                    findings_count = len(result) if isinstance(result, list) else 0
                    logger.info("Module %s completed in %.2fs (%d findings)", name, elapsed, findings_count)
                    return name, result if isinstance(result, list) else [], {
                        "name": name,
                        "phase": meta.phase,
                        "status": "completed",
                        "duration": round(elapsed, 2),
                        "findings": findings_count,
                        "engine": "python",
                    }
                except asyncio.TimeoutError:
                    elapsed = time.perf_counter() - t0
                    logger.warning("Module %s timed out after %.1fs (PY-03/SEC-E03)", name, meta.timeout_seconds)
                    return name, None, {
                        "name": name,
                        "phase": meta.phase,
                        "status": "timeout",
                        "duration": round(elapsed, 2),
                        "findings": 0,
                        "engine": "python",
                    }
                except Exception as exc:
                    elapsed = time.perf_counter() - t0
                    logger.exception("Module %s failed gracefully: %s (PY-03)", name, exc)
                    return name, None, {
                        "name": name,
                        "phase": meta.phase,
                        "status": "failed",
                        "duration": round(elapsed, 2),
                        "findings": 0,
                        "engine": "python",
                        "error": str(exc),
                    }

        logger.info("Pipeline DAG scheduled %d execution stages across %d modules", len(stages), sum(len(s) for s in stages))

        for stage_idx, stage_modules in enumerate(stages, start=1):
            logger.debug("Executing DAG Stage %d/%d (%s)", stage_idx, len(stages), ", ".join(stage_modules))
            is_post_stage = any(self.get_metadata(m).phase == "post_process" for m in stage_modules)

            tasks = [_run_single_module(m, is_post=is_post_stage) for m in stage_modules]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for item in results:
                if isinstance(item, tuple) and len(item) == 3:
                    name, findings_result, telemetry = item
                    if findings_result:
                        active_findings.extend(findings_result)
                    new_observations.append({
                        "name": "module_execution",
                        "value": telemetry,
                        "source": "pipeline",
                    })

        return active_findings, new_observations

