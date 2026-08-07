"""Standardized retry policy with exponential backoff and jitter.

Replaces all ad-hoc retry loops across the codebase with a single,
consistently-configured retry mechanism. Each external call site
should use one of the pre-defined policy presets.
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Any, Callable

logger = logging.getLogger(__name__)


class RetryPolicy:
    """Executes an async callable with configurable retries and exponential backoff."""

    def __init__(
        self,
        max_attempts: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 30.0,
        jitter: bool = True,
        retryable_exceptions: tuple[type[Exception], ...] = (
            asyncio.TimeoutError,
        ),
    ) -> None:
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.jitter = jitter
        self.retryable_exceptions = retryable_exceptions

    async def execute(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Call *fn* with retry and exponential backoff.

        Raises the last exception after all attempts are exhausted.
        """
        last_exception: Exception | None = None
        for attempt in range(self.max_attempts):
            try:
                return await fn(*args, **kwargs)
            except self.retryable_exceptions as exc:
                last_exception = exc
                if attempt == self.max_attempts - 1:
                    break
                delay = min(self.base_delay * (2 ** attempt), self.max_delay)
                if self.jitter:
                    delay *= 0.5 + random.random()
                logger.debug(
                    "Retry %d/%d after %.1fs: %s",
                    attempt + 1,
                    self.max_attempts,
                    delay,
                    exc,
                )
                await asyncio.sleep(delay)
        if last_exception is not None:
            raise last_exception
        raise RuntimeError("RetryPolicy: no attempts were made")


# ── Pre-defined policy presets ────────────────────────────────────────────────

try:
    import aiohttp

    _HTTP_RETRYABLE: tuple[type[Exception], ...] = (
        asyncio.TimeoutError,
        aiohttp.ClientError,
    )
except ImportError:
    _HTTP_RETRYABLE = (asyncio.TimeoutError,)


#: Standard HTTP requests — fast retries.
HTTP_RETRY = RetryPolicy(
    max_attempts=3,
    base_delay=1.0,
    retryable_exceptions=_HTTP_RETRYABLE,
)

#: DNS resolution — very fast, minimal retries.
DNS_RETRY = RetryPolicy(
    max_attempts=2,
    base_delay=0.5,
    retryable_exceptions=(asyncio.TimeoutError, OSError),
)

#: NVD API — respects NVD rate limit (~6s per request at burst).
NVD_RETRY = RetryPolicy(
    max_attempts=2,
    base_delay=6.0,
    max_delay=30.0,
    retryable_exceptions=_HTTP_RETRYABLE,
)

#: Slow external services (WHOIS, crt.sh, etc.)
SLOW_EXTERNAL_RETRY = RetryPolicy(
    max_attempts=2,
    base_delay=3.0,
    max_delay=15.0,
    retryable_exceptions=_HTTP_RETRYABLE + (OSError,),
)
