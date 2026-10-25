"""PhantomScan CLI module runner for `python -m phantomscan`."""
from __future__ import annotations

import sys
from phantomscan import main

if __name__ == "__main__":
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())
