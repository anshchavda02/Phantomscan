"""Real-time scan progress display using Rich.

Provides :class:`ScanProgressDisplay` which wraps an async scan coroutine
and shows a live progress bar with per-module spinners and a final summary.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text


#: Ordered list of scan module labels shown in the progress bar.
SCAN_MODULES = [
    "Resolving Target",
    "Fetching DNS Records",
    "WHOIS / RDAP Lookup",
    "Subdomain Enumeration",
    "Scanning TCP Ports",
    "Inspecting TLS / SSL",
    "Analyzing HTTP Headers",
    "Deep Web Analysis",
    "Technology Detection",
    "Email Security (SPF/DMARC)",
    "CVE Lookup",
    "False-Positive Filter",
    "Score Calculation",
]


class ScanProgressDisplay:
    """Wraps a scan coroutine and displays real-time Rich progress feedback."""

    def __init__(self, target: str, silent: bool = False) -> None:
        self._target = target
        self._silent = silent
        self._console = Console()
        self._start_time = time.time()

    def _make_progress(self) -> Progress:
        return Progress(
            SpinnerColumn(spinner_name="dots", style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=30, style="cyan", complete_style="green"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self._console,
            expand=False,
        )

    async def run_with_progress(self, scan_coro: Any) -> dict[str, Any]:
        """Execute *scan_coro* while displaying a live progress bar.

        Args:
            scan_coro: An awaitable that returns the final scan report dict.

        Returns:
            The report dict returned by *scan_coro*.
        """
        if self._silent:
            return await scan_coro

        self._console.print()
        self._console.print(
            Panel(
                f"[bold cyan]PhantomScan v2.0.0[/]  [dim]— Authorized Use Only —[/]\n"
                f"[bold]Target:[/] [green]{self._target}[/]\n"
                f"[dim]Scanning {len(SCAN_MODULES)} modules…[/]",
                border_style="cyan",
                expand=False,
            )
        )

        progress = self._make_progress()
        task_id: TaskID = progress.add_task(
            "[cyan]Initializing…[/]", total=len(SCAN_MODULES)
        )

        result: dict[str, Any] = {}
        completed_modules: list[str] = []

        async def _update_loop() -> None:
            """Advance the progress bar label as modules complete."""
            idx = 0
            while idx < len(SCAN_MODULES):
                await asyncio.sleep(0.25)
                if len(completed_modules) > idx:
                    idx = len(completed_modules)
                    label = SCAN_MODULES[min(idx, len(SCAN_MODULES) - 1)]
                    progress.update(task_id, advance=1, description=f"[cyan]{label}[/]")

        with progress:
            updater = asyncio.create_task(_update_loop())
            try:
                result = await scan_coro
                # Advance remaining steps in one shot
                remaining = len(SCAN_MODULES) - int(progress.tasks[0].completed)
                if remaining > 0:
                    progress.update(task_id, advance=remaining, description="[green]Complete[/]")
            finally:
                updater.cancel()
                try:
                    await updater
                except asyncio.CancelledError:
                    pass

        self._print_summary(result)
        return result

    def _print_summary(self, report: dict[str, Any]) -> None:
        elapsed = time.time() - self._start_time
        findings = report.get("findings", [])
        final_score = report.get("score", 0)
        final_grade = report.get("grade", "?")

        # Severity counts
        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = str(f.get("severity", "info")).lower()
            counts[sev] = counts.get(sev, 0) + 1

        score_color = "green" if final_score >= 80 else "yellow" if final_score >= 60 else "red"

        grid = Table.grid(expand=False)
        grid.add_row(
            Text("✅ Scan Complete", style="bold green"),
            Text(f"  {elapsed:.1f}s", style="dim"),
        )

        self._console.print()
        self._console.print(Panel(
            f"[bold]Score:[/]  [{score_color}]{final_score}/100  Grade {final_grade}[/]\n"
            f"[bold]Findings:[/]  "
            f"[red]Critical {counts['critical']}[/]  "
            f"[orange1]High {counts['high']}[/]  "
            f"[yellow]Medium {counts['medium']}[/]  "
            f"[green]Low {counts['low']}[/]  "
            f"[dim]Info {counts['info']}[/]\n"
            f"[dim]Elapsed: {elapsed:.1f}s[/]",
            title="[bold green]✅ Scan Complete[/]",
            border_style="green",
            expand=False,
        ))
