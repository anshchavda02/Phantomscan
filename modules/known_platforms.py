"""Known-platform matching helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from phantomscan.postprocess import load_known_platform
from phantomscan.scope import root_domain


def match_platform(data_dir: Path, host: str) -> dict[str, Any] | None:
    """Return known-platform context for host using root domain extraction."""
    clean_host = host.strip()
    if "://" in clean_host:
        clean_host = urlparse(clean_host).netloc or clean_host
    if ":" in clean_host:
        clean_host = clean_host.split(":")[0]
    r_domain = root_domain(clean_host) if clean_host else clean_host
    return load_known_platform(data_dir, r_domain or clean_host)


