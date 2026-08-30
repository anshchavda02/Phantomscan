"""Unit tests for Phase 13: Polyglot High-Performance Scanning Engine Integration."""

import json
import unittest
from unittest.mock import AsyncMock, patch

import pytest

from phantomscan.engines import MAX_ENGINE_OUTPUT_BYTES, run_engine
from phantomscan.scope import normalize_target


@pytest.mark.asyncio
async def test_engine_success_payload():
    """Parse successful engine result payload."""
    mock_payload = {
        "schema": "phantomscan.engine.v1",
        "engine": "go-portscan",
        "status": "ok",
        "target": "example.com",
        "started_at": "2026-08-30T10:00:00Z",
        "finished_at": "2026-08-30T10:00:05Z",
        "findings": [{"id": "PORT-8080-OPEN", "title": "Port 8080 Open", "severity": "info"}],
        "observations": [{"name": "open_tcp_ports", "value": [80, 443, 8080]}],
        "warnings": [],
    }

    mock_proc = AsyncMock()
    mock_proc.returncode = 0
    mock_proc.communicate = AsyncMock(return_value=(json.dumps(mock_payload).encode("utf-8"), b""))

    with patch("shutil.which", return_value="/usr/local/bin/phantomscan-portscan"), \
         patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await run_engine(
            ["phantomscan-portscan"],
            {"schema": "phantomscan.request.v1"},
            "go-portscan",
            normalize_target("example.com"),
        )

        assert result.status == "ok"
        assert result.engine == "go-portscan"
        assert len(result.findings) == 1
        assert len(result.observations) == 1
        assert result.observations[0]["name"] == "open_tcp_ports"


@pytest.mark.asyncio
async def test_engine_schema_mismatch():
    """Reject engine output with unsupported schema."""
    mock_payload = {
        "schema": "unsupported.v99",
        "status": "ok",
    }

    mock_proc = AsyncMock()
    mock_proc.returncode = 0
    mock_proc.communicate = AsyncMock(return_value=(json.dumps(mock_payload).encode("utf-8"), b""))

    with patch("shutil.which", return_value="/usr/local/bin/phantomscan-portscan"), \
         patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await run_engine(
            ["phantomscan-portscan"],
            {"schema": "phantomscan.request.v1"},
            "go-portscan",
            normalize_target("example.com"),
        )

        assert result.status == "skipped"
        assert "unsupported engine schema" in result.warnings[0]


@pytest.mark.asyncio
async def test_engine_sec_p02_output_limit():
    """SEC-P02: Subprocess output limit is capped at 10MB."""
    assert MAX_ENGINE_OUTPUT_BYTES == 10 * 1024 * 1024


if __name__ == "__main__":
    unittest.main()
