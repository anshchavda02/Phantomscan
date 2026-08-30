"""Unit tests for Phase 12: Modern Web & API Security Engine."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from phantomscan.http_client import HTTPResult, RobustHTTPClient
from phantomscan.modules.business_logic import BusinessLogicAnalyzer
from phantomscan.modules.dep_confusion import DependencyConfusionChecker
from phantomscan.modules.graphql_tester import GraphQLTester


@pytest.mark.asyncio
async def test_graphql_introspection_detection():
    """Detect exposed GraphQL introspection schema."""
    mock_http = MagicMock(spec=RobustHTTPClient)
    introspection_response = {
        "data": {
            "__schema": {
                "types": [
                    {"name": "User", "description": "User entity"},
                    {"name": "PaymentMethod", "description": "Credit card"},
                ],
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
            }
        }
    }
    mock_http.post = AsyncMock(
        return_value=HTTPResult(
            url="https://api.example.com/graphql",
            status=200,
            headers={"content-type": "application/json"},
            cookies={},
            body=json.dumps(introspection_response).encode("utf-8"),
            raw_set_cookies=[],
            redirect_chain=[],
            response_time_ms=45,
            content_type="application/json",
        )
    )

    tester = GraphQLTester(http=mock_http)
    finding = await tester._test_introspection("https://api.example.com/graphql")
    assert finding is not None
    assert finding["id"] == "GRAPHQL-INTROSPECTION"
    assert "User" in finding["evidence"]
    assert "PaymentMethod" in finding["evidence"]


@pytest.mark.asyncio
async def test_business_logic_mass_assignment():
    """Detect mass assignment privilege escalation."""
    mock_http = MagicMock(spec=RobustHTTPClient)
    mock_http.post = AsyncMock(
        return_value=HTTPResult(
            url="https://example.com/api/users",
            status=200,
            headers={"content-type": "application/json"},
            cookies={},
            body=b'{"id": 105, "role": "admin", "privilege": "granted", "status": "active"}',
            raw_set_cookies=[],
            redirect_chain=[],
            response_time_ms=30,
            content_type="application/json",
        )
    )

    analyzer = BusinessLogicAnalyzer(http=mock_http)
    findings = await analyzer._test_mass_assignment("https://example.com", ["https://example.com/api/users"])
    assert len(findings) >= 1
    assert any(f["id"] == "BL-MASS-ASSIGNMENT" for f in findings)


@pytest.mark.asyncio
async def test_dependency_confusion_checker():
    """Detect internal package collision on public registry."""
    mock_http = MagicMock(spec=RobustHTTPClient)
    mock_http.get = AsyncMock(
        return_value=HTTPResult(
            url="https://registry.npmjs.org/corp-internal-billing",
            status=200,
            headers={"content-type": "application/json"},
            cookies={},
            body=b'{"name": "corp-internal-billing", "versions": {"1.0.0": {}}}',
            raw_set_cookies=[],
            redirect_chain=[],
            response_time_ms=35,
            content_type="application/json",
        )
    )

    checker = DependencyConfusionChecker(http=mock_http)
    checker.check_public_registry = AsyncMock(return_value=True)

    with tempfile.TemporaryDirectory() as tmp_dir:
        pkg_path = Path(tmp_dir) / "package.json"
        pkg_path.write_text(json.dumps({
            "dependencies": {
                "corp-internal-billing": "1.0.0",
                "react": "18.2.0",
            }
        }))

        findings = await checker.check_project(tmp_dir)
        assert len(findings) == 1
        assert "DEP-CONFUSION" in findings[0]["id"]
        assert "corp-internal-billing" in findings[0]["title"]


if __name__ == "__main__":
    unittest.main()
