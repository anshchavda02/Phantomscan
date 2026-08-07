"""Health endpoint for daemon/monitoring mode.

Exposes ``/health`` and ``/metrics`` endpoints on a local port so
enterprise process managers (systemd, supervisord, Docker HEALTHCHECK)
can verify liveness without parsing logs.

Docker healthcheck example::

    HEALTHCHECK --interval=60s --timeout=5s \\
      CMD curl -f http://localhost:9191/health || exit 1
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

from aiohttp import web

logger = logging.getLogger(__name__)


class DaemonHealthServer:
    """Lightweight HTTP health/metrics server for daemon mode.

    Args:
        port: Local TCP port to bind to (default: 9191).
    """

    def __init__(self, port: int = 9191) -> None:
        self._port = port
        self._start_time = time.time()
        self._last_scan_time: Optional[str] = None
        self._scan_count: int = 0
        self._watched_targets: list[str] = []
        self._runner: Optional[web.AppRunner] = None
        self._extra_metrics: dict[str, Any] = {}

    def record_scan_complete(self, target: str) -> None:
        """Update metrics after a scan finishes."""
        self._scan_count += 1
        from datetime import datetime, timezone
        self._last_scan_time = datetime.now(timezone.utc).isoformat()

    def set_watched_targets(self, targets: list[str]) -> None:
        self._watched_targets = list(targets)

    def set_metrics(self, metrics: dict[str, Any]) -> None:
        """Set additional Prometheus-compatible metrics."""
        self._extra_metrics = metrics

    def _get_uptime(self) -> float:
        return round(time.time() - self._start_time, 1)

    async def health(self, request: web.Request) -> web.Response:
        """JSON health check endpoint."""
        return web.json_response({
            "status": "healthy",
            "uptime_seconds": self._get_uptime(),
            "last_scan_at": self._last_scan_time,
            "scans_completed": self._scan_count,
            "active_targets": len(self._watched_targets),
        })

    async def metrics(self, request: web.Request) -> web.Response:
        """Prometheus-compatible text metrics endpoint."""
        lines = [
            f"# HELP phantomscan_uptime_seconds Time since daemon started",
            f"# TYPE phantomscan_uptime_seconds gauge",
            f"phantomscan_uptime_seconds {self._get_uptime()}",
            f"# HELP phantomscan_scans_completed_total Total scans completed",
            f"# TYPE phantomscan_scans_completed_total counter",
            f"phantomscan_scans_completed_total {self._scan_count}",
            f"# HELP phantomscan_watched_targets Number of targets being monitored",
            f"# TYPE phantomscan_watched_targets gauge",
            f"phantomscan_watched_targets {len(self._watched_targets)}",
        ]
        for key, value in self._extra_metrics.items():
            safe_key = key.replace(".", "_").replace("-", "_")
            lines.append(f"phantomscan_{safe_key} {value}")
        return web.Response(
            text="\n".join(lines) + "\n",
            content_type="text/plain",
        )

    async def start(self) -> None:
        """Start the health server in the background."""
        app = web.Application()
        app.router.add_get("/health", self.health)
        app.router.add_get("/metrics", self.metrics)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", self._port)
        await site.start()
        logger.info(
            "Daemon health server started on http://127.0.0.1:%d",
            self._port,
        )

    async def stop(self) -> None:
        """Gracefully shut down the health server."""
        if self._runner:
            await self._runner.cleanup()
            logger.info("Daemon health server stopped")
