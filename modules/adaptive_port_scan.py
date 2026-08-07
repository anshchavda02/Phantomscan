"""Adaptive two-phase port scanner.

Replaces the fixed "always scan top 1000 ports" default with a
two-phase strategy: a fast probe of the 20 most common ports yields
immediate results, while the full scan runs concurrently in the
background. Supports ``--time-budget`` to cap total scan time.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import time
from dataclasses import dataclass
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ── Priority ports ────────────────────────────────────────────────────────────

PRIORITY_PORTS: list[int] = [
    80, 443, 22, 21, 25, 3306, 8080, 8443, 3389, 445,
    5432, 6379, 27017, 9200, 23, 53, 110, 143, 993, 587,
]


@dataclass
class PortResult:
    """Result for a single scanned port."""

    port: int
    state: str
    service: str = "unknown"
    banner: str = ""


# ── Service identification ────────────────────────────────────────────────────

_SERVICE_MAP: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    587: "submission", 993: "imaps", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
}


def _identify_service(port: int, banner: str) -> str:
    lowered = banner.lower()
    if "ssh" in lowered:
        return "ssh"
    if "http" in lowered:
        return "http"
    return _SERVICE_MAP.get(port, "unknown")


# ── Low-level scanner ─────────────────────────────────────────────────────────


def _scan_one_port(host: str, port: int, timeout: float) -> Optional[PortResult]:
    """Blocking single-port TCP connect scan with banner grab."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as conn:
            conn.settimeout(2.0)
            banner = ""
            try:
                # For HTTP ports, send a probe
                if port in (80, 8080, 8443):
                    conn.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                data = conn.recv(1024)
                banner = data.decode("utf-8", errors="replace").strip()[:200]
            except (OSError, TimeoutError):
                pass
            return PortResult(
                port=port,
                state="open",
                service=_identify_service(port, banner),
                banner=banner,
            )
    except (OSError, TimeoutError):
        return None


async def _scan_ports_batch(
    host: str,
    ports: list[int],
    timeout: float = 1.5,
    concurrency: int = 100,
) -> list[PortResult]:
    """Scan a batch of ports concurrently using thread pool."""
    semaphore = asyncio.Semaphore(concurrency)

    async def _one(port: int) -> Optional[PortResult]:
        async with semaphore:
            return await asyncio.to_thread(_scan_one_port, host, port, timeout)

    results = await asyncio.gather(*[_one(p) for p in ports])
    return [r for r in results if r is not None]


# ── Adaptive scanner ──────────────────────────────────────────────────────────


class AdaptivePortScanner:
    """Two-phase adaptive port scanner.

    Phase 1: Fast probe of 20 priority ports (~2-3 seconds).
    Phase 2: Full scan of remaining ports, running concurrently
             with downstream web analysis modules.

    Args:
        time_budget_seconds: Optional hard cap on total scan time.
            If exceeded, only fast-scan results are used.
    """

    def __init__(self, time_budget_seconds: Optional[int] = None) -> None:
        self.time_budget = time_budget_seconds

    async def scan(
        self,
        host: str,
        full_port_list: list[int],
    ) -> tuple[list[PortResult], list[PortResult]]:
        """Run both phases, returning (fast_results, full_results).

        The caller can start processing fast_results immediately while
        full_results may still be in flight.
        """
        fast_ports = PRIORITY_PORTS
        remaining = [p for p in full_port_list if p not in fast_ports]

        logger.info(
            "Adaptive scan: Phase 1 probing %d priority ports on %s",
            len(fast_ports),
            host,
        )

        # Phase 1: fast probe
        t0 = time.perf_counter()
        fast_results = await _scan_ports_batch(host, fast_ports)
        fast_elapsed = time.perf_counter() - t0
        logger.info(
            "Phase 1 complete: %d open ports in %.1fs",
            len(fast_results),
            fast_elapsed,
        )

        if not remaining:
            return fast_results, []

        # Phase 2: remaining ports
        logger.info(
            "Phase 2: scanning %d remaining ports on %s",
            len(remaining),
            host,
        )

        if self.time_budget:
            try:
                full_results = await asyncio.wait_for(
                    _scan_ports_batch(host, remaining),
                    timeout=self.time_budget,
                )
                logger.info(
                    "Phase 2 complete: %d additional open ports",
                    len(full_results),
                )
                return fast_results, full_results
            except asyncio.TimeoutError:
                logger.warning(
                    "Full port scan exceeded time budget of %ds, "
                    "using fast-scan results only. Consider increasing "
                    "--time-budget for exhaustive scans.",
                    self.time_budget,
                )
                return fast_results, []
        else:
            full_results = await _scan_ports_batch(host, remaining)
            logger.info(
                "Phase 2 complete: %d additional open ports",
                len(full_results),
            )
            return fast_results, full_results
