"""Dependency-aware parallel module scheduler.

Groups scan modules into execution tiers based on actual data
dependencies. Modules with no dependency on each other run
concurrently within a tier; tiers run sequentially only where
genuinely required.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


# ── Scan context ──────────────────────────────────────────────────────────────


@dataclass
class ScanContext:
    """Shared mutable context passed through all tiers.

    Accumulates observations, findings, and module statuses so each
    tier can read data produced by earlier tiers.
    """

    target: str
    profile: str
    observations: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    module_results: dict[str, Any] = field(default_factory=dict)
    failed_modules: dict[str, str] = field(default_factory=dict)
    skipped_modules: list[str] = field(default_factory=list)
    enabled_modules: set[str] = field(default_factory=set)
    # Timing
    tier_durations: dict[int, float] = field(default_factory=dict)
    module_durations: dict[str, float] = field(default_factory=dict)

    def is_module_enabled(self, module_name: str) -> bool:
        """Return True if *module_name* should run for this scan profile."""
        if not self.enabled_modules:
            return True  # no filter → run everything
        return module_name in self.enabled_modules

    def mark_module_failed(self, module_name: str, exc: Exception) -> None:
        self.failed_modules[module_name] = str(exc)

    def merge_result(self, module_name: str, result: Any) -> None:
        """Merge a module's output into the context."""
        self.module_results[module_name] = result
        if isinstance(result, dict):
            self.observations.extend(result.get("observations", []))
            self.findings.extend(result.get("findings", []))
        elif isinstance(result, (list, tuple)):
            # Convention: (observations, findings) tuple
            if len(result) == 2:
                obs, finds = result
                if isinstance(obs, list):
                    self.observations.extend(obs)
                if isinstance(finds, list):
                    self.findings.extend(finds)

    def finalize(self) -> dict[str, Any]:
        """Return the complete scan result."""
        return {
            "observations": self.observations,
            "findings": self.findings,
            "module_results": self.module_results,
            "failed_modules": self.failed_modules,
            "skipped_modules": self.skipped_modules,
            "tier_durations": self.tier_durations,
            "module_durations": self.module_durations,
        }


# ── Module scheduler ──────────────────────────────────────────────────────────


class ModuleScheduler:
    """Executes scan modules in dependency-ordered tiers.

    Modules within each tier run concurrently via ``asyncio.gather``.
    Tiers run sequentially so later tiers can depend on earlier results.
    """

    # Default tier definitions — can be overridden via config
    TIERS: dict[int, list[str]] = {
        # Tier 0: No dependencies — all parallel
        0: [
            "resolve_target",
            "whois",
            "dns_records",
        ],
        # Tier 1: Needs resolved IPs from tier 0
        1: [
            "port_scan",
            "ip_intel",
            "subdomain_enum",
            "crtsh_lookup",
        ],
        # Tier 2: Needs open ports + HTTP probe
        2: [
            "ssl_inspect",
            "http_probe",
            "tech_detect",
            "waf_detect",
        ],
        # Tier 3: Needs HTTP response + crawl data
        3: [
            "web_crawler",
            "api_discovery",
            "email_security",
            "header_analysis",
            "cookie_analysis",
        ],
        # Tier 4: Needs crawl data — injection tests
        4: [
            "sqli_scanner",
            "xss_scanner",
            "path_traversal",
            "idor_detector",
            "ssrf_detector",
            "cors_analyzer",
        ],
        # Tier 5: Needs tech stack + crawl
        5: [
            "jwt_tester",
            "graphql_tester",
            "websocket_tester",
            "business_logic",
            "cve_lookup",
        ],
        # Tier 6: Needs all findings collected
        6: [
            "finding_gate",
            "fp_postprocessor",
        ],
        # Tier 7: Needs clean findings
        7: [
            "score_engine",
            "chain_engine",
            "compliance_mapper",
        ],
        # Tier 8: Report generation
        8: [
            "reporter",
        ],
    }

    def __init__(
        self,
        module_registry: Optional[dict[str, Callable[..., Any]]] = None,
        tiers: Optional[dict[int, list[str]]] = None,
        max_concurrent_per_tier: int = 10,
    ) -> None:
        self._registry: dict[str, Callable[..., Any]] = module_registry or {}
        self._tiers = tiers or self.TIERS
        self._max_concurrent = max_concurrent_per_tier

    def register_module(self, name: str, fn: Callable[..., Any]) -> None:
        """Register a callable as a named module."""
        self._registry[name] = fn

    async def run_module(
        self,
        name: str,
        target: str,
        context: ScanContext,
    ) -> Any:
        """Execute a single module by name, returning its result."""
        fn = self._registry.get(name)
        if fn is None:
            logger.debug("Module %s not registered — skipping", name)
            context.skipped_modules.append(name)
            return None
        t0 = time.perf_counter()
        try:
            result = await fn(target, context)
            elapsed = time.perf_counter() - t0
            context.module_durations[name] = round(elapsed * 1000, 1)
            return result
        except Exception:
            elapsed = time.perf_counter() - t0
            context.module_durations[name] = round(elapsed * 1000, 1)
            raise

    async def run(self, target: str, context: ScanContext) -> dict[str, Any]:
        """Execute all tiers sequentially, modules within each tier concurrently."""
        for tier_num in sorted(self._tiers.keys()):
            modules = self._tiers[tier_num]
            active = [m for m in modules if context.is_module_enabled(m)]
            if not active:
                continue

            logger.info(
                "Tier %d: running %d modules concurrently (%s)",
                tier_num,
                len(active),
                ", ".join(active),
            )

            t0 = time.perf_counter()
            semaphore = asyncio.Semaphore(self._max_concurrent)

            async def _run_with_sem(module_name: str) -> Any:
                async with semaphore:
                    return await self.run_module(module_name, target, context)

            results = await asyncio.gather(
                *[_run_with_sem(m) for m in active],
                return_exceptions=True,
            )

            for module_name, result in zip(active, results):
                if isinstance(result, Exception):
                    logger.warning(
                        "Module %s failed: %s. Continuing scan with partial results.",
                        module_name,
                        result,
                    )
                    context.mark_module_failed(module_name, result)
                elif result is not None:
                    context.merge_result(module_name, result)

            tier_elapsed = time.perf_counter() - t0
            context.tier_durations[tier_num] = round(tier_elapsed * 1000, 1)
            logger.info(
                "Tier %d complete in %.0fms",
                tier_num,
                tier_elapsed * 1000,
            )

        return context.finalize()
