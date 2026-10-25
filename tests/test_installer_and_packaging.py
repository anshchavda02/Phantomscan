"""Tests for PhantomScan installer, packaging, CLI entrypoints, and module loading."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent


def test_package_exports_main_callable():
    """Verify that `from phantomscan import main` is defined and callable."""
    import phantomscan

    assert hasattr(phantomscan, "main")
    assert callable(phantomscan.main)
    assert hasattr(phantomscan, "__version__")
    assert phantomscan.__version__ == "2.3.0"


def test_phantomscan_main_module_execution():
    """Verify `python -m phantomscan --help` runs cleanly with exit code 0."""
    res = subprocess.run(
        [sys.executable, "-m", "phantomscan", "--help"],
        cwd=str(ROOT_DIR),
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert res.returncode == 0
    assert "PhantomScan" in res.stdout
    assert "--target" in res.stdout


def test_sys_path_bootstrap_in_phantomscan_cli():
    """Verify phantomscan.py ensures ROOT_DIR and modules/ are on sys.path even when invoked from outside."""
    outside_dir = ROOT_DIR.parent
    code = (
        "import sys, subprocess; "
        f"cli = r'{ROOT_DIR / 'phantomscan.py'}'; "
        "res = subprocess.run([sys.executable, cli, '--help'], capture_output=True, text=True); "
        "sys.exit(res.returncode)"
    )
    res = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(outside_dir),
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert res.returncode == 0


def test_all_advanced_modules_importable():
    """Verify that all 45 registered modules in phantomscan.modules are importable."""
    from phantomscan.modules import MODULE_REGISTRY, get_module_class

    assert len(MODULE_REGISTRY) >= 45
    for name in MODULE_REGISTRY:
        cls = get_module_class(name)
        assert cls is not None, f"Failed to load module class for {name}"


def test_root_modules_importable():
    """Verify that all root-level utility modules are importable."""
    root_module_names = [
        "cve_engine",
        "sensitive_path_scanner",
        "template_loader",
        "template_scanner",
        "template_executor",
        "circuit_breaker",
        "degradation_matrix",
        "resource_governor",
        "scan_cache",
        "scan_checkpoint",
        "structured_logging",
        "http_pool",
        "catch_all_detector",
        "extractor_engine",
        "matcher_engine",
        "score_engine",
        "dir_enum",
        "response_validator",
    ]
    import importlib

    for mod in root_module_names:
        imported = importlib.import_module(f"modules.{mod}")
        assert imported is not None


def test_install_bat_syntax_integrity():
    """Verify that install.bat does not contain common CMD syntax hazards."""
    bat_path = ROOT_DIR / "install.bat"
    assert bat_path.exists()
    content = bat_path.read_text(encoding="utf-8")

    # Double colon pseudo-comments must not be used (causes '. was unexpected at this time')
    assert "::" not in content, "install.bat must use REM instead of :: to prevent batch parsing errors"

    # Trailing slash quote hazards: %~dp0 should be normalized without trailing backslash
    assert 'if "%ROOT:~-1%"=="\\"' in content

    # Check that pip install -e is present
    assert "-m pip install -e" in content

    # Check that .venv parenthesized echo was avoided
    assert "(.venv)" not in content


def test_desktop_launcher_script_format():
    """Verify launcher batch scripts contain proper PYTHONPATH and working directory resolution."""
    for fn in ["PhantomScan Launcher.bat", "launcher.bat", "phantomscan-cli.bat"]:
        bat_file = ROOT_DIR / fn
        assert bat_file.exists(), f"{fn} must exist"
        txt = bat_file.read_text(encoding="utf-8")
        assert 'set "PYTHONPATH=' in txt
        assert "(.venv)" not in txt
