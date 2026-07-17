"""Cross-language engine launcher."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

from .models import EngineResult
from .scope import Target


async def run_engine(command: list[str], request: dict[str, Any], engine: str, target: Target) -> EngineResult:
    """Run one JSON-speaking engine with graceful failure."""
    executable = command[0]
    if not Path(executable).exists() and not _is_path_command(executable):
        return EngineResult.skipped(engine, target.host, f"engine binary missing: {executable}")

    proc = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate(json.dumps(request).encode("utf-8"))
    if proc.returncode != 0:
        result = EngineResult.skipped(engine, target.host, stderr.decode("utf-8", errors="replace").strip())
        result.status = "error"
        return result
    try:
        payload = json.loads(stdout.decode("utf-8"))
    except json.JSONDecodeError as exc:
        return EngineResult.skipped(engine, target.host, f"invalid JSON from engine: {exc}")
    if payload.get("schema") != "phantomscan.engine.v1":
        return EngineResult.skipped(engine, target.host, "unsupported engine schema")
    return EngineResult(
        schema=payload["schema"],
        engine=payload.get("engine", engine),
        status=payload.get("status", "ok"),
        target=payload.get("target", target.host),
        started_at=payload.get("started_at", ""),
        finished_at=payload.get("finished_at", ""),
        findings=payload.get("findings", []),
        observations=payload.get("observations", []),
        warnings=payload.get("warnings", []),
    )


def _is_path_command(command: str) -> bool:
    return os.sep not in command and "/" not in command

