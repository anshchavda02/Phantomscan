"""Cross-language engine launcher."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import shutil
from typing import Any

from .models import EngineResult
from .scope import Target


async def run_engine(command: list[str], request: dict[str, Any], engine: str, target: Target | str) -> EngineResult:
    """Run one JSON-speaking engine with graceful failure."""
    target_host = target.host if hasattr(target, "host") else str(target)
    executable = command[0]
    if _is_path_command(executable):
        resolved = shutil.which(executable)
        if not resolved:
            return EngineResult.skipped(engine, target_host, f"engine command missing on PATH: {executable}")
        command = [resolved, *command[1:]]
    elif not Path(executable).exists():
        return EngineResult.skipped(engine, target_host, f"engine binary missing: {executable}")
    elif not os.access(executable, os.X_OK):
        return EngineResult.skipped(engine, target_host, f"engine binary is not executable: {executable}")

    try:
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        missing = exc.filename or executable
        return EngineResult.skipped(engine, target_host, f"engine command missing: {missing}")
    except PermissionError as exc:
        blocked = exc.filename or executable
        return EngineResult.skipped(engine, target_host, f"engine command not executable: {blocked}")
    except OSError as exc:
        return EngineResult.skipped(engine, target_host, f"engine launch failed: {exc}")
    stdout, stderr = await proc.communicate(json.dumps(request).encode("utf-8"))
    if proc.returncode != 0:
        result = EngineResult.skipped(engine, target_host, stderr.decode("utf-8", errors="replace").strip())
        result.status = "error"
        return result
    try:
        payload = json.loads(stdout.decode("utf-8"))
    except json.JSONDecodeError as exc:
        return EngineResult.skipped(engine, target_host, f"invalid JSON from engine: {exc}")
    if payload.get("schema") != "phantomscan.engine.v1":
        return EngineResult.skipped(engine, target_host, "unsupported engine schema")
    return EngineResult(
        schema=payload["schema"],
        engine=payload.get("engine", engine),
        status=payload.get("status", "ok"),
        target=payload.get("target", target_host),
        started_at=payload.get("started_at", ""),
        finished_at=payload.get("finished_at", ""),
        findings=payload.get("findings", []),
        observations=payload.get("observations", []),
        warnings=payload.get("warnings", []),
    )


def _is_path_command(command: str) -> bool:
    return os.sep not in command and "/" not in command
