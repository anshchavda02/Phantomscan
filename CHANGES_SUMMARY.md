# Temporary Audit Changes & Decisions Summary

This document records conservative decisions and actions taken during each audit remediation phase on branch `cleanup/audit-fixes`. It will be removed at the conclusion of the audit per instructions.

## Phase 1: Licensing and Version Consistency
- **Authoritative License**: Established full Apache License 2.0 text at repository root (`LICENSE`) with copyright holder "Ansh Chavda" (2026).
- **Badge Synchronization**: Updated `README.md` license badge to `Apache-2.0` linking directly to `LICENSE`. Removed all references to MIT.
- **Dynamic Versioning in pyproject.toml**: Replaced hardcoded `version = "2.3.0"` with `dynamic = ["version"]` and setuptools directive `[tool.setuptools.dynamic] version = {attr = "phantomscan.__init__.__version__"}`. Verified compatibility with `setuptools.build_meta`.
- **Author & URLs in pyproject.toml**: Updated author to `Ansh Chavda` and added Homepage, Issues, and Source URLs pointing to `https://github.com/anshchavda02/Phantomscan`.
- **Single Source of Truth (`__version__`)**:
  - `phantomscan/config.py`: Imported `__version__` for `app.version` and `scan.user_agent`.
  - `phantomscan/progress.py`: Imported `__version__` for live Rich panel banner.
  - `phantomscan/reporting.py`: Imported `__version__` for HTML template context `report_version`.
  - `phantomscan/pdf_report.py`: Imported `__version__` for canvas header and metadata table.
  - `phantomscan/sarif_exporter.py`: Imported `__version__` for driver `semanticVersion`.
  - `phantomscan.py`: Imported `__version__` for CLI `WARNING`, `build_parser` description, and `cprint` banner.
  - `config.yaml`, `engines/rust/Cargo.toml`, `engines/rust/Cargo.lock`, `engines/node/package.json`, `engines/node/package-lock.json`, `PhantomScan-Launcher.ps1`, `scripts/install.sh`, and `scripts/install_macos.sh`: Synchronized to canonical version `2.3.0`.
- **Automated Consistency Test**: Added `tests/python/test_version_consistency.py` testing that `__version__`, `pyproject.toml`, `Cargo.toml`, `package.json`, SARIF output, PDF generator, and User-Agent are strictly in sync.
- **Test Baseline Result**: Baseline 493 passed -> Phase 1 result: 500 passed (7 new consistency tests, 0 failed).
