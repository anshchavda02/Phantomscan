"""Shared, connection-pooled HTTP session for the entire scan lifecycle.

Replaces per-module ``aiohttp.ClientSession()`` creation with a single
high-throughput connection pool, eliminating hundreds of redundant
TCP/TLS handshakes per scan.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

import aiohttp

logger = logging.getLogger(__name__)


class SharedHTTPPool:
    """Singleton HTTP connection pool shared across all scan modules.

    Usage::

        pool = SharedHTTPPool.get()
        async with pool.session.get(url) as resp:
            data = await resp.read()

    Call :meth:`close` in a ``finally`` block at the end of every scan
    to avoid leaking connections across repeated scans in daemon mode.
    """

    _instance: Optional["SharedHTTPPool"] = None

    def __init__(self) -> None:
        self.connector = aiohttp.TCPConnector(
            limit=100,                  # total pool size
            limit_per_host=10,          # per-target cap — respects scope
            ttl_dns_cache=300,          # 5 min DNS cache
            enable_cleanup_closed=True,
            force_close=False,          # keep-alive reuse
            keepalive_timeout=30,
        )
        self.session = aiohttp.ClientSession(
            connector=self.connector,
            timeout=aiohttp.ClientTimeout(total=30),
            trust_env=True,             # respects proxy env vars
            headers={
                "User-Agent": "PhantomScan/2.0 Security Scanner",
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
            },
        )

    @classmethod
    def get(cls) -> "SharedHTTPPool":
        """Return the singleton instance, creating it if needed."""
        if cls._instance is None or (
            cls._instance.session is not None and cls._instance.session.closed
        ):
            cls._instance = SharedHTTPPool()
        return cls._instance

    async def close(self) -> None:
        """Gracefully tear down the session and connector.

        Must be called in a ``finally`` block at scan end to prevent
        leaked sockets across daemon cycles.
        """
        if self.session and not self.session.closed:
            await self.session.close()
        # Allow underlying connections to close cleanly
        await asyncio.sleep(0.25)
        SharedHTTPPool._instance = None
        logger.debug("SharedHTTPPool closed and singleton reset")

    @classmethod
    async def shutdown(cls) -> None:
        """Class-level convenience to close the current singleton, if any."""
        if cls._instance is not None:
            await cls._instance.close()
