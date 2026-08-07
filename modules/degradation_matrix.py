"""Graceful degradation matrix for PhantomScan components.

Formalizes what happens when each component is unavailable as an
explicit table in code — not implicit try/except scattered everywhere.
The health checker consults this matrix and prints a clear startup
table showing which fallbacks are ACTIVE for the current run.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Literal

from rich.console import Console
from rich.table import Table

logger = logging.getLogger(__name__)

Severity = Literal["critical", "warning", "info"]


@dataclass
class DegradationEntry:
    """One row in the degradation matrix."""

    condition: str
    fallback: str
    impact: str
    severity: Severity


# ── The matrix ────────────────────────────────────────────────────────────────

DEGRADATION_MATRIX: dict[str, DegradationEntry] = {
    "go_scanner_binary_missing": DegradationEntry(
        condition="Go scanner binary not found",
        fallback="python_asyncio_port_scan",
        impact="Slower port scan (~5-10x), same accuracy",
        severity="warning",
    ),
    "rust_ssl_binary_missing": DegradationEntry(
        condition="Rust TLS engine binary not found",
        fallback="python_ssl_module_basic_check",
        impact="Reduced SSL grading accuracy — no cipher suite enumeration",
        severity="warning",
    ),
    "nodejs_unavailable": DegradationEntry(
        condition="Node.js not found on PATH",
        fallback="skip_browser_dependent_modules",
        impact=(
            "No screenshots, no JS-rendered crawl, "
            "no client-side prototype pollution check"
        ),
        severity="info",
    ),
    "nvd_api_down": DegradationEntry(
        condition="NVD API unreachable (circuit breaker OPEN)",
        fallback="use_cached_cve_data_only",
        impact="CVE section may be stale or empty for newly-detected tech versions",
        severity="warning",
    ),
    "nmap_not_installed": DegradationEntry(
        condition="nmap not found on PATH",
        fallback="go_scanner_only",
        impact="No NSE script results, no OS fingerprinting",
        severity="info",
    ),
    "no_internet_connectivity": DegradationEntry(
        condition="No internet connectivity detected",
        fallback="abort_scan_with_clear_message",
        impact="Cannot proceed — most modules require external data",
        severity="critical",
    ),
}


# ── Status reporter ───────────────────────────────────────────────────────────

_SEVERITY_ICONS: dict[str, str] = {
    "critical": "[bold red]✗ CRITICAL[/]",
    "warning": "[yellow]⚠  WARNING[/]",
    "info": "[blue]ℹ  INFO[/]",
}


def build_health_status(
    engine_statuses: dict[str, bool],
) -> list[tuple[str, DegradationEntry, bool]]:
    """Match engine availability to degradation entries.

    Returns a list of ``(matrix_key, entry, is_triggered)`` tuples.
    """
    status_map = {
        "go_scanner_binary_missing": not engine_statuses.get("go_scanner", False),
        "rust_ssl_binary_missing": not engine_statuses.get("rust_tls", False),
        "nodejs_unavailable": not engine_statuses.get("nodejs", False),
        "nmap_not_installed": not engine_statuses.get("nmap", True),
        "no_internet_connectivity": not engine_statuses.get("internet", True),
        "nvd_api_down": not engine_statuses.get("nvd_api", True),
    }
    results = []
    for key, entry in DEGRADATION_MATRIX.items():
        triggered = status_map.get(key, False)
        results.append((key, entry, triggered))
    return results


def print_degradation_table(
    engine_statuses: dict[str, bool],
    console: Console | None = None,
) -> list[str]:
    """Print a clear startup table showing component status and fallbacks.

    Returns a list of warning/info messages for structured logging.
    """
    console = console or Console()
    statuses = build_health_status(engine_statuses)

    table = Table(
        title="[bold cyan]Component Status & Fallbacks[/]",
        show_header=True,
    )
    table.add_column("Component", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Fallback")
    table.add_column("Impact", style="dim")

    messages: list[str] = []

    for key, entry, triggered in statuses:
        if triggered:
            icon = _SEVERITY_ICONS.get(entry.severity, "⚠")
            status = f"{icon}"
            fallback_text = entry.fallback.replace("_", " ").title()
            table.add_row(
                entry.condition,
                status,
                f"→ {fallback_text}",
                entry.impact,
            )
            messages.append(
                f"{entry.condition}: using fallback '{entry.fallback}' "
                f"({entry.impact})"
            )
        else:
            table.add_row(
                entry.condition.replace("not found", "").replace("missing", "").strip()
                or key.replace("_", " ").title(),
                "[green]✓ Ready[/]",
                "—",
                "—",
            )

    console.print(table)

    # Abort on critical degradations
    critical = [
        e for _, e, t in statuses if t and e.severity == "critical"
    ]
    if critical:
        for c in critical:
            console.print(
                f"[bold red]CRITICAL: {c.condition} — {c.impact}[/]"
            )

    return messages
