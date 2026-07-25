"""Module 3 — Mobile App API Extractor.

Extract and test backend APIs from mobile app binaries (.apk, .ipa).
Uses apktool for APK decompilation (graceful skip if missing) and unzip/strings for IPA.
Tests extracted API endpoints for direct accessibility without mobile app context/cert pinning.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)

URL_PATTERN = re.compile(
    r"https?://[a-zA-Z0-9.-]+(?:/[a-zA-Z0-9._~:/?#\[\]@!$&\'()*+,;=%-]*)?"
)


class MobileAPIExtractor:
    """Extract and test backend APIs from APK/IPA files."""

    def __init__(self, http: RobustHTTPClient) -> None:
        self.http = http

    async def run(self, **kwargs: Any) -> list[dict[str, Any]]:
        """Module interface."""
        apk_path = kwargs.get("apk_path")
        ipa_path = kwargs.get("ipa_path")

        endpoints: set[str] = set()

        if apk_path and os.path.exists(apk_path):
            extracted = await self.extract_from_apk(apk_path)
            endpoints.update(extracted)

        if ipa_path and os.path.exists(ipa_path):
            extracted = await self.extract_from_ipa(ipa_path)
            endpoints.update(extracted)

        if not endpoints:
            return []

        return await self.test_mobile_apis(list(endpoints))

    async def extract_from_apk(self, apk_path: str) -> list[str]:
        """Decompile APK using apktool (or unzip fallback) and search for API URLs."""
        endpoints: set[str] = set()
        temp_dir = tempfile.mkdtemp(prefix="phantomscan_apk_")

        try:
            apktool_bin = shutil.which("apktool")
            if apktool_bin:
                proc = await asyncio.create_subprocess_exec(
                    apktool_bin, "d", "-f", apk_path, "-o", temp_dir,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await proc.communicate()
            else:
                logger.info("apktool not found, falling back to zip extraction for %s", apk_path)
                with zipfile.ZipFile(apk_path, "r") as zip_ref:
                    zip_ref.extractall(temp_dir)

            for file_path in Path(temp_dir).rglob("*"):
                if file_path.is_file() and file_path.suffix in [".xml", ".smali", ".json", ".txt", ".js"]:
                    try:
                        content = file_path.read_text(errors="ignore")
                        matches = URL_PATTERN.findall(content)
                        endpoints.update(matches)
                    except Exception:
                        continue
        except Exception as exc:
            logger.error("Failed to extract URLs from APK %s: %s", apk_path, exc)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

        api_endpoints = [
            e for e in endpoints
            if any(kw in e.lower() for kw in ["/api/", "/v1/", "/v2/", "/rest/", "/graphql", ".json"])
        ]
        return api_endpoints

    async def extract_from_ipa(self, ipa_path: str) -> list[str]:
        """Unzip IPA and search binary / plist strings for URLs."""
        endpoints: set[str] = set()
        temp_dir = tempfile.mkdtemp(prefix="phantomscan_ipa_")

        try:
            with zipfile.ZipFile(ipa_path, "r") as zip_ref:
                zip_ref.extractall(temp_dir)

            for file_path in Path(temp_dir).rglob("*"):
                if file_path.is_file():
                    try:
                        if file_path.suffix in [".plist", ".json", ".txt", ".js", ".xml"]:
                            content = file_path.read_text(errors="ignore")
                            matches = URL_PATTERN.findall(content)
                            endpoints.update(matches)
                        elif file_path.stat().st_size < 50_000_000 and not file_path.suffix:
                            # Likely main binary
                            content = file_path.read_bytes()
                            strings = re.findall(rb"[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]{6,}", content)
                            for s in strings:
                                text = s.decode("ascii", errors="ignore")
                                if text.startswith("http://") or text.startswith("https://"):
                                    endpoints.update(URL_PATTERN.findall(text))
                    except Exception:
                        continue
        except Exception as exc:
            logger.error("Failed to extract URLs from IPA %s: %s", ipa_path, exc)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

        api_endpoints = [
            e for e in endpoints
            if any(kw in e.lower() for kw in ["/api/", "/v1/", "/v2/", "/rest/", "/graphql", ".json"])
        ]
        return api_endpoints

    async def test_mobile_apis(self, endpoints: list[str]) -> list[dict[str, Any]]:
        """Test mobile endpoints directly to see if they lack authentication/pinning requirement."""
        findings: list[dict[str, Any]] = []

        for endpoint in endpoints[:20]:  # Limit to 20 endpoints
            try:
                resp = await self.http.request("GET", endpoint, timeout=8)
                status = resp.get("status", 0)
                if status == 200:
                    findings.append({
                        "title": "Mobile API Accessible Without App Context",
                        "severity": "medium",
                        "confidence": "medium",
                        "category": "mobile_api",
                        "target": endpoint,
                        "evidence": f"Endpoint: {endpoint}\nDirect access response HTTP {status}",
                        "recommendation": (
                            "Ensure API endpoints enforce strict authentication and token verification "
                            "regardless of whether requests originate from a mobile client or direct HTTP."
                        ),
                        "references": ["CWE-306"],
                        "module": "mobile_api",
                    })
            except Exception:
                pass

        return findings
