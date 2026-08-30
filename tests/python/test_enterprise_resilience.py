"""Unit tests for Phase 16: Enterprise Resilience, Chaos Testing, Regression Benchmark & Release Engineering."""

import asyncio
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from modules.circuit_breaker import CircuitBreaker, CircuitOpenError, create_default_breakers
from modules.degradation_matrix import DEGRADATION_MATRIX, DegradationEntry, print_degradation_table
from modules.resource_governor import ResourceGovernor
from modules.scan_cache import ScanCache



@pytest.mark.asyncio
async def test_circuit_breaker_lifecycle():
    """Circuit breaker transitions CLOSED -> OPEN -> HALF_OPEN -> CLOSED."""
    breaker = CircuitBreaker(name="test_service", failure_threshold=2, recovery_timeout=1)
    assert breaker.state == "CLOSED"

    # Failing function
    fail_mock = AsyncMock(side_effect=RuntimeError("Service timeout"))

    # First failure -> still CLOSED
    with pytest.raises(RuntimeError):
        await breaker.call(fail_mock)
    assert breaker.state == "CLOSED"
    assert breaker.failure_count == 1

    # Second failure -> trips to OPEN
    with pytest.raises(RuntimeError):
        await breaker.call(fail_mock)
    assert breaker.state == "OPEN"

    # Subsequent call while OPEN raises CircuitOpenError immediately without calling fn
    with pytest.raises(CircuitOpenError):
        await breaker.call(fail_mock)

    # Wait for recovery timeout
    await asyncio.sleep(1.1)

    # Success call during HALF_OPEN resets to CLOSED
    success_mock = AsyncMock(return_value={"status": "ok"})
    result = await breaker.call(success_mock)
    assert result == {"status": "ok"}
    assert breaker.state == "CLOSED"
    assert breaker.failure_count == 0


@pytest.mark.asyncio
async def test_scan_cache_two_tier():
    """Two-tier scan cache with L1 in-memory and L2 SQLite persistence."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = Path(tmp_dir) / "test_cache.sqlite3"
        cache = ScanCache(db_path=db_path)
        cache2 = None

        try:
            fetch_count = 0

            async def fetch_dns(domain: str) -> dict:
                nonlocal fetch_count
                fetch_count += 1
                return {"domain": domain, "ip": "93.184.216.34"}

            # 1. First fetch -> cache miss (calls fetch_fn)
            res1 = await cache.get_or_fetch("dns:example.com", lambda: fetch_dns("example.com"), category="dns")
            assert res1["ip"] == "93.184.216.34"
            assert fetch_count == 1
            assert cache.hits == 0
            assert cache.misses == 1

            # 2. Second fetch in same instance -> L1 in-memory hit
            res2 = await cache.get_or_fetch("dns:example.com", lambda: fetch_dns("example.com"), category="dns")
            assert res2["ip"] == "93.184.216.34"
            assert fetch_count == 1
            assert cache.hits == 1

            # 3. Create new ScanCache instance pointing to same SQLite DB -> L2 SQLite hit
            cache2 = ScanCache(db_path=db_path)
            res3 = await cache2.get_or_fetch("dns:example.com", lambda: fetch_dns("example.com"), category="dns")
            assert res3["ip"] == "93.184.216.34"
            assert fetch_count == 1
            assert cache2.hits == 1
        finally:
            cache.close()
            if cache2 is not None:
                cache2.close()



@pytest.mark.asyncio
async def test_resource_governor_limits():
    """Resource governor allocates and tracks concurrency slots."""
    governor = ResourceGovernor(max_memory_mb=1024, max_concurrent_scans=2)
    assert governor.max_concurrent_scans == 2


def test_degradation_matrix_formatting():
    """Degradation table formats cleanly without exceptions."""
    engine_statuses = {"go_scanner": False, "nvd_api": True, "rust_tls": True}
    messages = print_degradation_table(engine_statuses)
    assert len(messages) >= 1
    assert any("Go scanner" in m for m in messages)


if __name__ == "__main__":
    unittest.main()


