"""OpenAPI & Swagger specification auto-discovery and parser.

Probes standard API documentation endpoints, parses OpenAPI 2.0/3.0/3.1 specs,
and extracts all defined endpoints, methods, and parameters for automated DAST testing.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import urljoin

from phantomscan.http_client import RobustHTTPClient
from phantomscan.models import Finding, Observation

logger = logging.getLogger(__name__)

# Standard OpenAPI / Swagger paths to probe
OPENAPI_PROBE_PATHS = [
    "/api-docs/swagger.json",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api/swagger.json",
    "/api/openapi.json",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/docs/openapi.json",
]


class OpenAPIParser:
    """Discovers and parses OpenAPI / Swagger specifications."""

    def __init__(self, http: RobustHTTPClient) -> None:
        self.http = http

    async def discover_and_parse(
        self, base_url: str, logger_inst: logging.Logger | None = None
    ) -> tuple[list[str], list[Observation], list[Finding]]:
        """Probe for OpenAPI documentation and extract all endpoints."""
        log = logger_inst or logger
        base = base_url.rstrip("/")
        discovered_urls: list[str] = []
        observations: list[Observation] = []
        findings: list[Finding] = []
        found_spec_url: str | None = None
        spec_data: dict[str, Any] | None = None

        for path in OPENAPI_PROBE_PATHS:
            target_url = f"{base}{path}"
            try:
                res = await self.http.get(target_url, retries=1)
                if res.status == 200 and res.body:
                    text = res.text()
                    # Check if response is valid JSON
                    if text.strip().startswith("{"):
                        try:
                            data = json.loads(text)
                            if isinstance(data, dict) and ("swagger" in data or "openapi" in data or "paths" in data):
                                found_spec_url = target_url
                                spec_data = data
                                log.info("Found valid OpenAPI/Swagger specification at %s", target_url)
                                break
                        except json.JSONDecodeError:
                            pass
            except Exception as exc:
                log.debug("OpenAPI probe failed for %s: %s", target_url, exc)

        if not found_spec_url or not spec_data:
            return [], [], []

        # Parse paths and parameters from OpenAPI specification
        paths_dict = spec_data.get("paths", {})
        title = spec_data.get("info", {}).get("title", "API")
        version = spec_data.get("info", {}).get("version", "1.0")
        base_path = spec_data.get("basePath", "")

        extracted_endpoints: list[dict[str, Any]] = []

        for route, path_item in paths_dict.items():
            if not isinstance(path_item, dict):
                continue
            
            full_path = f"{base_path.rstrip('/')}/{route.lstrip('/')}"
            full_url = f"{base}{full_path}"
            discovered_urls.append(full_url)

            for method, op in path_item.items():
                if method.lower() in {"get", "post", "put", "delete", "patch", "options", "head"} and isinstance(op, dict):
                    params = []
                    # Path-level parameters
                    for p in path_item.get("parameters", []):
                        if isinstance(p, dict) and "name" in p:
                            params.append({"name": p["name"], "in": p.get("in", "query")})
                    # Operation-level parameters
                    for p in op.get("parameters", []):
                        if isinstance(p, dict) and "name" in p:
                            params.append({"name": p["name"], "in": p.get("in", "query")})

                    extracted_endpoints.append({
                        "url": full_url,
                        "path": full_path,
                        "method": method.upper(),
                        "summary": op.get("summary", ""),
                        "parameters": params,
                    })

        findings.append(
            Finding(
                id="OPENAPI-SPEC-EXPOSED",
                title=f"OpenAPI / Swagger API Definition Disclosed ({title} v{version})",
                severity="info",
                confidence="high",
                category="api",
                target=found_spec_url,
                evidence=(
                    f"OpenAPI specification reachable at {found_spec_url}.\n"
                    f"Discovered {len(extracted_endpoints)} API operations across {len(paths_dict)} routes."
                ),
                recommendation="Ensure API documentation is intended for public consumption and requires authentication if restricted.",
            )
        )

        observations.append(Observation("openapi_spec_url", found_spec_url, "openapi-parser"))
        observations.append(Observation("openapi_endpoints", extracted_endpoints, "openapi-parser"))
        observations.append(Observation("discovered_urls", list(set(discovered_urls)), "openapi-parser"))

        log.info("OpenAPI parser extracted %d API operations from %s", len(extracted_endpoints), found_spec_url)
        return discovered_urls, observations, findings
