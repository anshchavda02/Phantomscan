"""Version consistency tests across polyglot project manifests and components.

Ensures that phantomscan.__version__ serves as the single source of truth across:
- phantomscan.__version__
- pyproject.toml (setuptools dynamic configuration)
- engines/rust/Cargo.toml
- engines/node/package.json
- SARIF export driver semanticVersion
- PDF report header and Engine Version
- Default User-Agent configuration
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import pytest

import phantomscan
from phantomscan import __version__
from phantomscan.config import DEFAULT_CONFIG
from phantomscan.sarif_exporter import generate_sarif_report
import setuptools.config.expand as setuptools_expand


ROOT_DIR = Path(__file__).resolve().parent.parent.parent


def test_version_single_source_of_truth():
    """Verify that __version__ is a valid semver string."""
    assert isinstance(__version__, str)
    assert re.match(r"^\d+\.\d+\.\d+", __version__), f"Invalid semver: {__version__}"


def test_pyproject_version_matches():
    """Verify pyproject.toml references phantomscan.__version__ dynamically."""
    pyproject_path = ROOT_DIR / "pyproject.toml"
    assert pyproject_path.exists()
    content = pyproject_path.read_text(encoding="utf-8")

    # pyproject must declare version as dynamic
    assert 'dynamic = ["version"]' in content or "dynamic = ['version']" in content

    # setuptools dynamic config must point to phantomscan.__init__.__version__
    assert 'version = {attr = "phantomscan.__init__.__version__"}' in content

    # Verify setuptools actually resolves the attribute to __version__
    resolved_version = setuptools_expand.read_attr("phantomscan.__init__.__version__", {}, str(ROOT_DIR))
    assert resolved_version == __version__


def test_cargo_toml_version_matches():
    """Verify engines/rust/Cargo.toml matches __version__."""
    cargo_path = ROOT_DIR / "engines" / "rust" / "Cargo.toml"
    assert cargo_path.exists()
    content = cargo_path.read_text(encoding="utf-8")
    match = re.search(r'\[package\][\s\S]*?version\s*=\s*"([^"]+)"', content)
    assert match is not None, "Could not find package version in Cargo.toml"
    assert match.group(1) == __version__, f"Cargo.toml version {match.group(1)} != {__version__}"


def test_node_package_json_version_matches():
    """Verify engines/node/package.json matches __version__."""
    pkg_path = ROOT_DIR / "engines" / "node" / "package.json"
    assert pkg_path.exists()
    pkg_data = json.loads(pkg_path.read_text(encoding="utf-8"))
    assert pkg_data.get("version") == __version__, f"package.json version {pkg_data.get('version')} != {__version__}"


def test_sarif_semantic_version_matches():
    """Verify SARIF output driver semanticVersion matches __version__."""
    sarif_doc = generate_sarif_report({"target": "example.com", "findings": []})
    driver = sarif_doc["runs"][0]["tool"]["driver"]
    assert driver["semanticVersion"] == __version__, f"SARIF driver version {driver['semanticVersion']} != {__version__}"


def test_pdf_report_version_matches():
    """Verify PDF report generator embeds __version__ in header and metadata."""
    pdf_py_path = ROOT_DIR / "phantomscan" / "pdf_report.py"
    assert pdf_py_path.exists()
    content = pdf_py_path.read_text(encoding="utf-8")

    # Header check
    assert 'f"PHANTOMSCAN {__version__}"' in content or f'"PHANTOMSCAN {__version__}"' in content
    # Engine Version metadata check
    assert 'f"PhantomScan v{__version__} (Polyglot Hardened)"' in content or f'"PhantomScan v{__version__} (Polyglot Hardened)"' in content


def test_user_agent_version_matches():
    """Verify default User-Agent configuration matches __version__."""
    ua = DEFAULT_CONFIG["scan"]["user_agent"]
    expected_ua = f"PhantomScan/{__version__} authorized-security-assessment"
    assert ua == expected_ua, f"Default User-Agent {ua} != {expected_ua}"
