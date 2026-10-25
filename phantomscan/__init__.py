"""PhantomScan package."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

__version__ = "2.3.0"


def main(*args: Any, **kwargs: Any) -> Any:
    """Forward execution to the main CLI orchestrator."""
    root_dir = Path(__file__).resolve().parent.parent
    if str(root_dir) not in sys.path:
        sys.path.insert(0, str(root_dir))
    modules_dir = root_dir / "modules"
    if modules_dir.exists() and str(modules_dir) not in sys.path:
        sys.path.insert(1, str(modules_dir))

    import importlib.util
    cli_path = root_dir / "phantomscan.py"
    if not cli_path.exists():
        raise FileNotFoundError(f"PhantomScan CLI script not found at {cli_path}")

    spec = importlib.util.spec_from_file_location("__phantomscan_cli__", cli_path)
    if spec and spec.loader:
        cli_mod = importlib.util.module_from_spec(spec)
        sys.modules["__phantomscan_cli__"] = cli_mod
        spec.loader.exec_module(cli_mod)
        return cli_mod.main(*args, **kwargs)
    raise RuntimeError(f"Unable to load CLI module from {cli_path}")


__all__ = ["__version__", "main"]
