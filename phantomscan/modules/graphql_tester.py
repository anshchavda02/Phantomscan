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

        # Discover GraphQL endpoints
        endpoints = await self._discover_graphql(target)

        for endpoint in endpoints:
            introspection = await self._test_introspection(endpoint)
            if introspection:
                findings.append(introspection)

            depth = await self._test_depth_limit(endpoint)
            if depth:
                findings.append(depth)

            batch = await self._test_batching(endpoint)
            if batch:
                findings.append(batch)

            suggestions = await self._test_field_suggestions(endpoint)
            if suggestions:
                findings.append(suggestions)

        return findings

    async def _discover_graphql(self, target: str) -> list[str]:
        found: list[str] = []
        for path in _GRAPHQL_PATHS:
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
                    found.append(url)
            except Exception:
                continue
        return found

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
