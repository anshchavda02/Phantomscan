"""Module 4 — Dependency Confusion Checker.

Check project package manifests (package.json, requirements.txt) for internal/unscoped package names
and verify if they exist on public package registries (npm, PyPI) to flag dependency confusion risks.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)

_KNOWN_PUBLIC_MARKERS = [
    "react", "lodash", "express", "axios", "typescript", "jest", "next", "vue",
    "requests", "urllib3", "numpy", "pandas", "pytest", "django", "flask", "pydantic",
]


class DependencyConfusionChecker:
    """Detect dependency confusion risks in JavaScript and Python projects."""

    def __init__(self, http: RobustHTTPClient) -> None:
        self.http = http

    async def run(self, **kwargs: Any) -> list[dict[str, Any]]:
        """Module interface."""
        project_path = kwargs.get("project_path", ".")
        return await self.check_project(project_path)

    async def check_project(self, project_path: str) -> list[dict[str, Any]]:
        """Scan package files in project path and check public registries."""
        findings: list[dict[str, Any]] = []
        internal_packages: list[tuple[str, str]] = []  # (package_name, registry_type)

        p = Path(project_path)

        # Parse package.json
        pkg_json = p / "package.json"
        if pkg_json.exists():
            try:
                data = json.loads(pkg_json.read_text(encoding="utf-8"))
                deps = {
                    **data.get("dependencies", {}),
                    **data.get("devDependencies", {}),
                    **data.get("peerDependencies", {}),
                }
                for name in deps:
                    if self.looks_internal(name):
                        internal_packages.append((name, "npm"))
            except Exception as exc:
                logger.error("Failed to parse package.json: %s", exc)

        # Parse requirements.txt
        req_txt = p / "requirements.txt"
        if req_txt.exists():
            try:
                for line in req_txt.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    pkg = line.split("==")[0].split(">=")[0].split("<=")[0].split("~=")[0].strip()
                    if pkg and self.looks_internal(pkg):
                        internal_packages.append((pkg, "pypi"))
            except Exception as exc:
                logger.error("Failed to parse requirements.txt: %s", exc)

        for name, registry in internal_packages:
            exists = await self.check_public_registry(name, registry)
            if exists:
                findings.append({
                    "id": f"DEP-CONFUSION-{name.upper().replace('@', '').replace('/', '-')}",
                    "title": f"Dependency Confusion Risk: {name}",
                    "severity": "high",
                    "confidence": "medium",
                    "category": "dependency_confusion",
                    "target": f"{registry}:{name}",
                    "evidence": f"Package: {name}\nFound on public {registry} registry: yes",
                    "recommendation": (
                        "Use scoped packages (@yourorg/name), configure your package manager "
                        "(.npmrc / pip.conf) to prioritize private registries, or reserve the package name "
                        "on the public registry."
                    ),
                    "references": ["CWE-427"],
                    "module": "dep_confusion",
                })

        return findings

    def looks_internal(self, name: str) -> bool:
        """Determine if a package name appears to be internal/private."""
        name_lower = name.lower()
        if name.startswith("@"):
            return False
        if any(pub in name_lower for pub in _KNOWN_PUBLIC_MARKERS):
            return False

        internal_keywords = ["internal", "private", "corp", "company", "custom", "core-utils", "service-client"]
        return any(kw in name_lower for kw in internal_keywords)

    async def check_public_registry(self, name: str, registry: str) -> bool:
        """Query public registry API to check if package exists."""
        url = (
            f"https://registry.npmjs.org/{name}"
            if registry == "npm"
            else f"https://pypi.org/pypi/{name}/json"
        )
        try:
            resp = await self.http.request("GET", url, timeout=5)
            return resp.get("status") == 200
        except Exception:
            return False
