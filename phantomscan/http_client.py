"""Production-grade async HTTP client with retry, timeout, and protocol fallback."""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, AsyncIterator

import aiohttp

logger = logging.getLogger(__name__)


# ── Data types ────────────────────────────────────────────────────────────────


@dataclass
class HTTPResult:
    """All relevant data from a single HTTP response."""

    url: str
    status: int
    headers: dict[str, str]
    cookies: dict[str, str]
    body: bytes
    raw_set_cookies: list[str]          # all Set-Cookie header values
    redirect_chain: list[str]
    response_time_ms: int
    content_type: str

    def text(self, encoding: str = "utf-8") -> str:
        """Decode body to text."""
        return self.body.decode(encoding, errors="ignore")


class ScanError(Exception):
    """Raised when a scan operation fails irrecoverably."""


class ScanTimeout(ScanError):
    """Raised when a scan operation times out."""


# ── Robust HTTP client ────────────────────────────────────────────────────────


class RobustHTTPClient:
    """Async HTTP client with retry, exponential backoff, and connection pooling.

    Must be used as an async context manager or via :func:`http_client`.
    """

    _DEFAULT_HEADERS: dict[str, str] = {
        "User-Agent": "PhantomScan/2.0 Security Scanner",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    }

    def __init__(self) -> None:
        self.session: aiohttp.ClientSession | None = None
        self._timeout = aiohttp.ClientTimeout(total=8, connect=3, sock_read=5)
        self._connector: aiohttp.TCPConnector | None = None

    async def start(self) -> None:
        """Create the underlying aiohttp session and connector."""
        self._connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=30,
            ttl_dns_cache=300,
            ssl=False,
            force_close=False,
            enable_cleanup_closed=True,
            resolver=aiohttp.ThreadedResolver(),
        )
        self.session = aiohttp.ClientSession(
            connector=self._connector,
            headers=self._DEFAULT_HEADERS,
        )

    async def close(self) -> None:
        """Close the session and connector."""
        if self.session and not self.session.closed:
            await self.session.close()
            self.session = None
        if self._connector and not self._connector.closed:
            await self._connector.close()
            self._connector = None

    async def get(
        self,
        url: str,
        retries: int = 1,
        allow_redirects: bool = True,
        timeout: aiohttp.ClientTimeout | None = None,
        **kwargs: Any,
    ) -> HTTPResult:
        """GET *url* with retry and exponential backoff.

        Args:
            url: Full URL to fetch.
            retries: Maximum number of attempts.
            allow_redirects: Follow HTTP redirects.
            timeout: Override the default timeout.
            **kwargs: Extra arguments forwarded to ``aiohttp.ClientSession.get``.

        Returns:
            Populated :class:`HTTPResult`.

        Raises:
            The last exception after all retries are exhausted.
        """
        if self.session is None:
            raise RuntimeError("RobustHTTPClient must be started with start() first")
        effective_timeout = timeout or self._timeout
        last_exc: Exception = RuntimeError("no attempts were made")

        for attempt in range(retries):
            try:
                t0 = time.perf_counter()
                async with self.session.get(
                    url,
                    timeout=effective_timeout,
                    allow_redirects=allow_redirects,
                    max_redirects=10,
                    ssl=False,
                    **kwargs,
                ) as response:
                    body = await response.read()
                    elapsed_ms = int((time.perf_counter() - t0) * 1000)
                    raw_set_cookies = response.headers.getall("Set-Cookie", [])
                    return HTTPResult(
                        url=str(response.url),
                        status=response.status,
                        headers={k.lower(): v for k, v in response.headers.items()},
                        cookies={k: v.value for k, v in response.cookies.items()},
                        body=body[:1_000_000],
                        raw_set_cookies=raw_set_cookies,
                        redirect_chain=[str(r.url) for r in response.history],
                        response_time_ms=elapsed_ms,
                        content_type=response.content_type or "",
                    )
            except asyncio.TimeoutError as exc:
                last_exc = exc
                logger.warning("Timeout on %s (attempt %d/%d)", url, attempt + 1, retries)
            except aiohttp.ClientError as exc:
                last_exc = exc
                logger.warning("HTTP error on %s: %s", url, exc)

            if attempt < retries - 1:
                delay = 2**attempt
                logger.debug("Retrying %s in %ds", url, delay)
                await asyncio.sleep(delay)

        raise last_exc

    async def try_both_protocols(self, host: str) -> HTTPResult:
        """Try HTTPS first, then HTTP; raise :class:`ScanError` if both fail."""
        last_exc: Exception = ScanError(f"Cannot reach {host}")
        for scheme in ("https", "http"):
            try:
                return await self.get(
                    f"{scheme}://{host}",
                    timeout=aiohttp.ClientTimeout(total=4.0, connect=2.0),
                )
            except Exception as exc:
                logger.debug("%s failed for %s: %s", scheme, host, exc)
                last_exc = exc
        raise ScanError(f"Cannot reach {host} over HTTPS or HTTP") from last_exc

    async def request(
        self,
        method: str,
        url: str,
        retries: int = 1,
        allow_redirects: bool = True,
        timeout: aiohttp.ClientTimeout | None = None,
        **kwargs: Any,
    ) -> HTTPResult:
        """Send an HTTP request with the given *method*, retry, and backoff.

        This is the generic verb method used by :meth:`post`, :meth:`put`,
        :meth:`delete`, and :meth:`patch`.
        """
        if self.session is None:
            raise RuntimeError("RobustHTTPClient must be started with start() first")
        effective_timeout = timeout or self._timeout
        last_exc: Exception = RuntimeError("no attempts were made")

        for attempt in range(retries):
            try:
                t0 = time.perf_counter()
                async with self.session.request(
                    method,
                    url,
                    timeout=effective_timeout,
                    allow_redirects=allow_redirects,
                    max_redirects=10,
                    ssl=False,
                    **kwargs,
                ) as response:
                    body = await response.read()
                    elapsed_ms = int((time.perf_counter() - t0) * 1000)
                    raw_set_cookies = response.headers.getall("Set-Cookie", [])
                    return HTTPResult(
                        url=str(response.url),
                        status=response.status,
                        headers={k.lower(): v for k, v in response.headers.items()},
                        cookies={k: v.value for k, v in response.cookies.items()},
                        body=body[:1_000_000],
                        raw_set_cookies=raw_set_cookies,
                        redirect_chain=[str(r.url) for r in response.history],
                        response_time_ms=elapsed_ms,
                        content_type=response.content_type or "",
                    )
            except asyncio.TimeoutError as exc:
                last_exc = exc
                logger.warning("Timeout on %s %s (attempt %d/%d)", method, url, attempt + 1, retries)
            except aiohttp.ClientError as exc:
                last_exc = exc
                logger.warning("HTTP error on %s %s: %s", method, url, exc)

            if attempt < retries - 1:
                await asyncio.sleep(2**attempt)

        raise last_exc

    async def post(self, url: str, **kwargs: Any) -> HTTPResult:
        """POST *url* with retry."""
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> HTTPResult:
        """PUT *url* with retry."""
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> HTTPResult:
        """DELETE *url* with retry."""
        return await self.request("DELETE", url, **kwargs)

    async def patch(self, url: str, **kwargs: Any) -> HTTPResult:
        """PATCH *url* with retry."""
        return await self.request("PATCH", url, **kwargs)

    async def send_raw(
        self,
        host: str,
        payload: bytes | str,
        port: int = 80,
        timeout: float = 10.0,
    ) -> HTTPResult:
        """Send a raw TCP payload and return the response.

        Used for HTTP request smuggling detection where precise byte-level
        control over the wire format is required.
        """
        raw = payload.encode("utf-8") if isinstance(payload, str) else payload

        def _blocking() -> tuple[bytes, float]:
            import socket as _socket
            t0 = time.perf_counter()
            with _socket.create_connection((host, port), timeout=timeout) as sock:
                sock.sendall(raw)
                sock.settimeout(timeout)
                chunks: list[bytes] = []
                try:
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        chunks.append(chunk)
                except (_socket.timeout, TimeoutError):
                    pass
            elapsed = time.perf_counter() - t0
            return b"".join(chunks), elapsed

        response_bytes, elapsed = await asyncio.to_thread(_blocking)
        elapsed_ms = int(elapsed * 1000)
        text = response_bytes.decode("utf-8", errors="ignore")

        # Parse a rudimentary status code from the raw HTTP response
        status = 0
        if text.startswith("HTTP/"):
            parts = text.split(" ", 2)
            if len(parts) >= 2 and parts[1].isdigit():
                status = int(parts[1])

        return HTTPResult(
            url=f"raw://{host}:{port}",
            status=status,
            headers={},
            cookies={},
            body=response_bytes[:100_000],
            raw_set_cookies=[],
            redirect_chain=[],
            response_time_ms=elapsed_ms,
            content_type="",
        )


# ── Context manager ───────────────────────────────────────────────────────────


@asynccontextmanager
async def http_client() -> AsyncIterator[RobustHTTPClient]:
    """Yield a ready :class:`RobustHTTPClient` and close it on exit."""
    client = RobustHTTPClient()
    await client.start()
    try:
        yield client
    finally:
        await client.close()


# ── Retry helper ──────────────────────────────────────────────────────────────


async def with_retry(
    func: Any,
    *args: Any,
    max_retries: int = 3,
    base_delay: float = 1.0,
    exceptions: tuple[type[Exception], ...] = (Exception,),
    **kwargs: Any,
) -> Any:
    """Call *func* with exponential backoff on failure.

    Args:
        func: Async callable to invoke.
        *args: Positional arguments forwarded to *func*.
        max_retries: Total number of attempts.
        base_delay: Starting delay in seconds; doubles each attempt.
        exceptions: Exception types that trigger a retry.
        **kwargs: Keyword arguments forwarded to *func*.

    Returns:
        Whatever *func* returns on success.

    Raises:
        The last exception after all attempts are exhausted.
    """
    name = getattr(func, "__name__", repr(func))
    last_exc: Exception = RuntimeError("no attempts were made")
    for attempt in range(max_retries):
        try:
            return await func(*args, **kwargs)
        except exceptions as exc:
            last_exc = exc
            if attempt == max_retries - 1:
                logger.error("All %d retries failed for %s: %s", max_retries, name, exc)
                raise
            delay = base_delay * (2**attempt)
            logger.warning(
                "Attempt %d/%d failed for %s: %s — retrying in %.1fs",
                attempt + 1, max_retries, name, exc, delay,
            )
            await asyncio.sleep(delay)
    raise last_exc


# ── Timeout manager ───────────────────────────────────────────────────────────


class ScanTimeoutManager:
    """Per-operation async timeout enforcer using :func:`asyncio.timeout`."""

    TIMEOUTS: dict[str, int] = {
        "http_request":    10,
        "port_scan_total": 120,
        "ssl_inspect":     15,
        "dns_resolve":     5,
        "whois_lookup":    15,
        "crtsh_query":     30,
        "ip_intel":        10,
        "browser_engine":  45,
        "full_scan":       600,
    }

    @asynccontextmanager
    async def timeout(self, operation: str) -> AsyncIterator[None]:
        """Yield inside a hard timeout for *operation*.

        Raises:
            :class:`ScanTimeout` when the deadline expires.
        """
        seconds = self.TIMEOUTS.get(operation, 30)
        try:
            async with asyncio.timeout(seconds):
                yield
        except TimeoutError as exc:
            logger.warning("Operation '%s' timed out after %ds", operation, seconds)
            raise ScanTimeout(f"{operation} timed out after {seconds}s") from exc


#: Module-level singleton timeout manager.
timeout_manager = ScanTimeoutManager()
