"""Engine availability health checker.

Run before a scan (when --debug is active) to verify all optional engines
and network prerequisites are in place.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import aiohttp
from rich.console import Console
from rich.table import Table

logger = logging.getLogger(__name__)


@dataclass
class EngineStatus:
    """Availability status for one engine or prerequisite."""

    name: str
    available: bool
    critical: bool = False
    detail: str = ""


@dataclass
class HealthReport:
    """Aggregated health check results."""

    engines: dict[str, EngineStatus] = field(default_factory=dict)

    @property
    def all_critical_available(self) -> bool:
        """Return True if every critical engine is available."""
        return all(s.available for s in self.engines.values() if s.critical)

    @property
    def summary(self) -> dict[str, Any]:
        return {
            name: {
                "name": s.name,
                "available": s.available,
                "critical": s.critical,
                "detail": s.detail,
            }
            for name, s in self.engines.items()
        }


class EngineHealthChecker:
    """Checks optional engines and network connectivity before a scan begins."""

    def __init__(self, repo_root: Path) -> None:
        self._root = repo_root
        self._console = Console()

    async def check_all(self) -> HealthReport:
        """Run all checks concurrently and return a :class:`HealthReport`."""
        results: dict[str, EngineStatus] = {}

        go_bin = self._root / "engines" / "go" / "bin" / "phantomscan-go"
        results["go_scanner"] = EngineStatus(
            name="Go Port Scanner",
            available=go_bin.exists(),
            critical=False,
            detail=str(go_bin) if go_bin.exists() else f"Binary missing: {go_bin}",
        )

        rust_bin = self._root / "engines" / "rust" / "target" / "release" / "phantomscan-rust"
        results["rust_tls"] = EngineStatus(
            name="Rust TLS Inspector",
            available=rust_bin.exists(),
            critical=False,
            detail=str(rust_bin) if rust_bin.exists() else f"Binary missing: {rust_bin}",
        )

        node_result = await self._check_node()
        results["nodejs"] = node_result

        internet_result = await self._check_internet()
        results["internet"] = internet_result

        dns_result = await self._check_dns()
        results["dns"] = dns_result

        self._print_report(results)
        return HealthReport(engines=results)

    async def _check_node(self) -> EngineStatus:
        try:
            proc = await asyncio.create_subprocess_exec(
                "node", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5.0)
            version = stdout.decode().strip()
            return EngineStatus(
                name="Node.js Browser Engine",
                available=True,
                critical=False,
                detail=version,
            )
        except (FileNotFoundError, asyncio.TimeoutError, OSError):
            return EngineStatus(
                name="Node.js Browser Engine",
                available=False,
                critical=False,
                detail="node not found on PATH",
            )

    async def _check_internet(self) -> EngineStatus:
        try:
            resolver = aiohttp.ThreadedResolver()
            connector = aiohttp.TCPConnector(ssl=False, resolver=resolver)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(
                    "https://dns.google/resolve?name=example.com&type=A",
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    ok = resp.status == 200
            return EngineStatus(
                name="Internet Access",
                available=ok,
                critical=True,
                detail="dns.google reachable" if ok else "dns.google not reachable",
            )
        except Exception as exc:
            return EngineStatus(
                name="Internet Access",
                available=False,
                critical=True,
                detail=str(exc),
            )

    async def _check_dns(self) -> EngineStatus:
        try:
            import dns.asyncresolver
            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
            await resolver.resolve("example.com", "A", lifetime=4.0)
            return EngineStatus(
                name="DNS Resolver (dnspython)",
                available=True,
                critical=True,
                detail="8.8.8.8 / 1.1.1.1 reachable",
            )
        except Exception as exc:
            return EngineStatus(
                name="DNS Resolver (dnspython)",
                available=False,
                critical=True,
                detail=str(exc),
            )

    def _print_report(self, results: dict[str, EngineStatus]) -> None:
        table = Table(title="[bold cyan]Engine Health Check[/]", show_header=True)
        table.add_column("Engine", style="bold")
        table.add_column("Status", justify="center")
        table.add_column("Required")
        table.add_column("Detail", style="dim")

        for status in results.values():
            icon = "[green][OK] Ready[/]" if status.available else "[red][FAIL] Unavailable[/]"
            req = "[yellow]Required[/]" if status.critical else "Optional"
            table.add_row(status.name, icon, req, status.detail)

        self._console.print(table)
        if not all(s.available for s in results.values() if s.critical):
            self._console.print(
                "[bold red]!  One or more required engines are unavailable. "
                "Scan will use Python fallbacks where possible.[/]"
            )
