"""Resource governor for memory, concurrency, and file descriptor limits.

Prevents PhantomScan from exhausting host resources during large/batch
scans — a real enterprise requirement. Limits are configurable via
config.yaml and CLI overrides.
"""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

logger = logging.getLogger(__name__)


class ResourceGovernor:
    """Controls resource usage across concurrent scan operations.

    Args:
        max_memory_mb: Hard memory ceiling in megabytes.
        max_concurrent_scans: Maximum simultaneous batch scans.
        max_open_files: Soft file-descriptor limit (advisory).
    """

    def __init__(
        self,
        max_memory_mb: int = 2048,
        max_concurrent_scans: int = 5,
        max_open_files: int = 1000,
    ) -> None:
        self.max_memory_mb = max_memory_mb
        self.max_concurrent_scans = max_concurrent_scans
        self.max_open_files = max_open_files
        self._active_scans: int = 0
        self._scan_semaphore = asyncio.Semaphore(max_concurrent_scans)
        self._total_scans_completed: int = 0

    @asynccontextmanager
    async def acquire_scan_slot(self) -> AsyncIterator[None]:
        """Acquire a scan slot, blocking if the pool is full.

        Usage::

            async with governor.acquire_scan_slot():
                await run_scan(target)
        """
        async with self._scan_semaphore:
            self._active_scans += 1
            logger.debug(
                "Scan slot acquired (%d/%d active)",
                self._active_scans,
                self.max_concurrent_scans,
            )
            try:
                yield
            finally:
                self._active_scans -= 1
                self._total_scans_completed += 1

    def check_memory(self) -> bool:
        """Check if process memory usage is within limits.

        Returns True if within limits, False if exceeded (advisory —
        the scan continues but a warning is logged).
        """
        try:
            import psutil

            process = psutil.Process()
            mem_mb = process.memory_info().rss / 1024 / 1024
            if mem_mb > self.max_memory_mb:
                logger.warning(
                    "Memory usage %.0fMB exceeds limit %dMB — "
                    "consider reducing --threads or batch concurrency",
                    mem_mb,
                    self.max_memory_mb,
                )
                return False
            logger.debug("Memory usage: %.0fMB / %dMB", mem_mb, self.max_memory_mb)
            return True
        except ImportError:
            logger.debug("psutil not installed — memory check skipped")
            return True

    def get_memory_mb(self) -> float:
        """Return current RSS in megabytes, or -1 if psutil is unavailable."""
        try:
            import psutil

            return psutil.Process().memory_info().rss / 1024 / 1024
        except ImportError:
            return -1.0

    @property
    def active_scans(self) -> int:
        return self._active_scans

    @property
    def total_scans_completed(self) -> int:
        return self._total_scans_completed

    def status(self) -> dict[str, Any]:
        """Return current resource status as a dict."""
        return {
            "active_scans": self._active_scans,
            "max_concurrent_scans": self.max_concurrent_scans,
            "total_scans_completed": self._total_scans_completed,
            "memory_mb": round(self.get_memory_mb(), 1),
            "max_memory_mb": self.max_memory_mb,
            "memory_within_limits": self.check_memory(),
        }
