"""Known-platform matching helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from phantomscan.postprocess import load_known_platform


def match_platform(data_dir: Path, host: str) -> dict[str, Any] | None:
    """Return known-platform context for host."""
    return load_known_platform(data_dir, host)

