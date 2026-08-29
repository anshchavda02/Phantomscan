"""Module 10 — GraphQL Security Tester.

Tests for introspection exposure, depth limit bypass, batching attacks,
and field suggestion information disclosure.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)

_INTROSPECTION_QUERY = '{ __schema { types { name description } queryType { name } mutationType { name } } }'

_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/gql", "/query",
                  "/v1/graphql", "/v2/graphql", "/graphiql"]


class GraphQLTester:
    """Test GraphQL endpoints for common security misconfigurations."""

    def __init__(self, http: RobustHTTPClient) -> None:
        self.http = http

    async def run(
        self,
        base_url: str,
        observations: list[dict[str, Any]],
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        target = base_url.rstrip("/")

        import asyncio

        # Discover GraphQL endpoints concurrently
        endpoints = await self._discover_graphql(target)

        async def test_endpoint(endpoint: str) -> list[dict[str, Any]]:
            res: list[dict[str, Any]] = []
            tasks = [
                self._test_introspection(endpoint),
                self._test_depth_limit(endpoint),
                self._test_batching(endpoint),
                self._test_field_suggestions(endpoint),
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, dict) and r:
                    res.append(r)
            return res

        endpoint_results = await asyncio.gather(*(test_endpoint(ep) for ep in endpoints), return_exceptions=True)
        for r in endpoint_results:
            if isinstance(r, list):
                findings.extend(r)

        return findings

    async def _discover_graphql(self, target: str) -> list[str]:
        import asyncio

        async def check_path(path: str) -> str | None:
            url = f"{target}{path}"
            try:
                response = await self.http.post(
                    url,
                    json={"query": "{ __typename }"},
                    retries=1,
                )
                body = response.text()
                if response.status == 200 and (
                    "__typename" in body or "data" in body or "errors" in body
                ):
                    return url
            except Exception:
                pass
            return None

        results = await asyncio.gather(*(check_path(p) for p in _GRAPHQL_PATHS), return_exceptions=True)
        return [r for r in results if isinstance(r, str) and r]

    async def _test_introspection(self, endpoint: str) -> dict[str, Any] | None:
        try:
            response = await self.http.post(
                endpoint,
                json={"query": _INTROSPECTION_QUERY},
                retries=1,
            )
            body = response.text()
            if response.status == 200 and "__schema" in body:
                try:
                    data = json.loads(body)
                    types = (
                        data.get("data", {})
                        .get("__schema", {})
                        .get("types", [])
                    )
                    type_count = len(types)
                    type_names = [t.get("name", "") for t in types[:20]]
                except (json.JSONDecodeError, AttributeError):
                    type_count = 0
                    type_names = []

                return {
                    "id": "GRAPHQL-INTROSPECTION",
                    "title": "GraphQL Introspection Enabled in Production",
                    "severity": "medium",
                    "confidence": "high",
                    "category": "graphql",
                    "target": endpoint,
                    "evidence": (
                        f"Full schema introspection returned {type_count} types.\n"
                        f"Sample types: {', '.join(type_names[:10])}\n"
                        f"Attackers can map the entire API surface."
                    ),
                    "recommendation": (
                        "Disable GraphQL introspection in production. "
                        "Most frameworks support an 'introspection: false' option. "
                        "CWE-200."
                    ),
                    "references": ["https://cwe.mitre.org/data/definitions/200.html"],
                }
        except Exception:
            pass
        return None

    async def _test_depth_limit(self, endpoint: str) -> dict[str, Any] | None:
        deep_query = self._build_deep_query(depth=15)
        try:
            t0 = time.perf_counter()
            response = await self.http.post(
                endpoint,
                json={"query": deep_query},
                retries=1,
            )
            elapsed = time.perf_counter() - t0

            if response.status == 200 and elapsed > 3:
                return {
                    "id": "GRAPHQL-NO-DEPTH-LIMIT",
                    "title": "GraphQL No Query Depth Limit (DoS Risk)",
                    "severity": "medium",
                    "confidence": "high",
                    "category": "graphql",
                    "target": endpoint,
                    "evidence": (
                        f"Deeply nested query (depth=15) accepted.\n"
                        f"Response time: {elapsed:.2f}s.\n"
                        f"Attackers can craft resource-exhaustion queries."
                    ),
                    "recommendation": (
                        "Implement query depth limits (typically 5-10 levels). "
                        "Use query cost analysis and complexity limits. CWE-400."
                    ),
                    "references": ["https://cwe.mitre.org/data/definitions/400.html"],
                }
        except Exception:
            pass
        return None

    async def _test_batching(self, endpoint: str) -> dict[str, Any] | None:
        batch = [{"query": "{ __typename }"} for _ in range(50)]
        try:
            response = await self.http.post(endpoint, json=batch, retries=1)
            body = response.text()
            if response.status == 200:
                try:
                    data = json.loads(body)
                    if isinstance(data, list) and len(data) >= 50:
                        return {
                            "id": "GRAPHQL-BATCHING",
                            "title": "GraphQL Batching Enabled",
                            "severity": "low",
                            "confidence": "high",
                            "category": "graphql",
                            "target": endpoint,
                            "evidence": (
                                f"50 batched queries accepted in single request.\n"
                                f"Can be used to bypass rate limits or brute-force."
                            ),
                            "recommendation": (
                                "Limit the number of operations per batched request. "
                                "Implement per-operation rate limiting. CWE-400."
                            ),
                            "references": ["https://cwe.mitre.org/data/definitions/400.html"],
                        }
                except (json.JSONDecodeError, TypeError):
                    pass
        except Exception:
            pass
        return None

    async def _test_field_suggestions(self, endpoint: str) -> dict[str, Any] | None:
        # Send a query with a misspelled field to trigger suggestions
        query = "{ usrs { id } }"
        try:
            response = await self.http.post(
                endpoint, json={"query": query}, retries=1,
            )
            body = response.text().lower()
            if "did you mean" in body or "suggestion" in body:
                return {
                    "id": "GRAPHQL-FIELD-SUGGESTIONS",
                    "title": "GraphQL Field Suggestion Disclosure",
                    "severity": "low",
                    "confidence": "high",
                    "category": "graphql",
                    "target": endpoint,
                    "evidence": (
                        f"Query with misspelled field 'usrs' returned "
                        f"field suggestions, leaking schema information."
                    ),
                    "recommendation": (
                        "Disable field suggestions in production to prevent "
                        "schema enumeration via error messages."
                    ),
                }
        except Exception:
            pass
        return None

    @staticmethod
    def _build_deep_query(depth: int) -> str:
        q = "{ __typename "
        for i in range(depth):
            q += f"... on Query {{ __typename "
        q += "}" * depth + " }"
        return q
