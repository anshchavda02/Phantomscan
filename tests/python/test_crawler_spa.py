"""Unit tests for Phase 5: Crawler, SPA Route Extraction & Form Parameter Intelligence."""

import json
import unittest
from unittest.mock import AsyncMock, MagicMock

import pytest

from phantomscan.asset_graph import AssetGraph
from phantomscan.http_client import HTTPResult, RobustHTTPClient
from phantomscan.js_analyzer import JSRouteExtractor
from phantomscan.openapi_parser import OpenAPIParser
from phantomscan.web_crawler import (
    DiscoveredForm,
    FormField,
    WebCrawler,
    generate_form_baseline_payload,
)


class CrawlerAndSPATests(unittest.TestCase):
    def test_form_baseline_payload_generator(self):
        """PR-D01: Generate type-safe valid payloads for capturing baselines."""
        fields = [
            FormField(name="email", field_type="email"),
            FormField(name="age", field_type="number", min_val="18"),
            FormField(name="phone", field_type="tel"),
            FormField(name="website", field_type="url"),
            FormField(name="password", field_type="password"),
            FormField(name="role", field_type="select", options=["admin", "user", "guest"]),
            FormField(name="csrf_token", field_type="hidden", default_value="secret123"),
            FormField(name="comment", field_type="textarea"),
        ]

        payload = generate_form_baseline_payload(fields)

        self.assertEqual(payload["email"], "testuser@example.com")
        self.assertEqual(payload["age"], "18")
        self.assertEqual(payload["phone"], "5550199283")
        self.assertEqual(payload["website"], "https://example.com")
        self.assertEqual(payload["password"], "P@ssw0rd123!")
        self.assertEqual(payload["role"], "admin")
        self.assertEqual(payload["csrf_token"], "secret123")
        self.assertEqual(payload["comment"], "test")

    def test_html5_form_extraction(self):
        """Extract inputs, textareas, selects, and formactions from HTML5 body."""
        html = """
        <html>
        <body>
            <form action="/submit-feedback" method="POST">
                <input type="text" name="author" required pattern="[A-Za-z ]+" maxlength="50" />
                <input type="email" name="user_email" />
                <input type="hidden" name="__VIEWSTATE" value="dDwtMTIzNDU2" />
                <textarea name="feedback_msg">Great service!</textarea>
                <select name="rating">
                    <option value="1">Poor</option>
                    <option value="5" selected>Excellent</option>
                </select>
                <button type="submit">Submit</button>
                <button type="submit" formaction="/preview-feedback">Preview</button>
            </form>
        </body>
        </html>
        """
        mock_http = MagicMock(spec=RobustHTTPClient)
        crawler = WebCrawler(http=mock_http)
        forms = crawler._extract_forms(html, "https://example.com/contact")

        self.assertTrue(len(forms) >= 2)  # Standard action + button formaction

        f1 = forms[0]
        self.assertEqual(f1.action, "https://example.com/submit-feedback")
        self.assertEqual(f1.method, "POST")

        field_map = {f.name: f for f in f1.fields}
        self.assertIn("author", field_map)
        self.assertTrue(field_map["author"].required)
        self.assertEqual(field_map["author"].pattern, "[A-Za-z ]+")
        self.assertEqual(field_map["author"].maxlength, 50)

        self.assertIn("__VIEWSTATE", field_map)
        self.assertEqual(field_map["__VIEWSTATE"].default_value, "dDwtMTIzNDU2")

        self.assertIn("feedback_msg", field_map)
        self.assertEqual(field_map["feedback_msg"].field_type, "textarea")
        self.assertEqual(field_map["feedback_msg"].default_value, "Great service!")

        self.assertIn("rating", field_map)
        self.assertEqual(field_map["rating"].field_type, "select")
        self.assertEqual(field_map["rating"].default_value, "5")
        self.assertEqual(field_map["rating"].options, ["1", "5"])


@pytest.mark.asyncio
async def test_js_route_extractor_spa():
    """Extract Next.js / React Router / GraphQL endpoints from JavaScript code."""
    js_code = """
    // React / Next.js routing and Axios calls
    axios.get('/api/v2/users?role=admin');
    fetch('/rest/products/search?q=phone');
    const route = { path: '/dashboard/analytics', component: Analytics };
    const hash = '/#/settings/security';

    // GraphQL operation
    const GET_PROFILE = `query GetUserProfile($id: ID!) { user(id: $id) { name email } }`;
    """
    mock_http = AsyncMock(spec=RobustHTTPClient)
    extractor = JSRouteExtractor(http=mock_http)

    discovered_urls, observations, findings = await extractor.analyze(
        base_url="https://app.example.com",
        html_body=f"<script>{js_code}</script>",
    )

    all_paths = [u for u in discovered_urls]
    obs_dict = {o.name: o.value for o in observations}
    routes_found = obs_dict.get("discovered_api_routes", [])

    self_routes = " ".join(routes_found)
    assert "/api/v2/users" in self_routes or any("/api/v2/users" in u for u in all_paths)
    assert "/rest/products/search" in self_routes or any("/rest/products/search" in u for u in all_paths)
    assert "/dashboard/analytics" in self_routes or any("/dashboard/analytics" in u for u in all_paths)


@pytest.mark.asyncio
async def test_openapi_parser_with_asset_graph():
    """OpenAPI parser parses Swagger spec and populates AssetGraph."""
    mock_spec = {
        "openapi": "3.0.0",
        "info": {"title": "Test Banking API", "version": "2.4.0"},
        "paths": {
            "/api/v1/transfers": {
                "post": {
                    "summary": "Initiate wire transfer",
                    "parameters": [
                        {"name": "recipient_id", "in": "query", "required": True},
                        {"name": "amount", "in": "query", "required": True},
                        {"name": "X-Auth-Token", "in": "header", "required": True},
                    ],
                }
            },
            "/api/v1/accounts/{accountId}": {
                "get": {
                    "summary": "Fetch account balance",
                    "parameters": [
                        {"name": "accountId", "in": "path", "required": True},
                    ],
                }
            },
        },
    }

    mock_http = MagicMock(spec=RobustHTTPClient)
    mock_http.get = AsyncMock(
        return_value=HTTPResult(
            url="https://api.bank.com/openapi.json",
            status=200,
            headers={"content-type": "application/json"},
            cookies={},
            body=json.dumps(mock_spec).encode("utf-8"),
            raw_set_cookies=[],
            redirect_chain=[],
            response_time_ms=50,
            content_type="application/json",
        )
    )

    parser = OpenAPIParser(http=mock_http)
    graph = AssetGraph()

    discovered_urls, obs, findings = await parser.discover_and_parse(
        base_url="https://api.bank.com",
        asset_graph=graph,
    )

    assert len(discovered_urls) >= 2
    assert len(findings) == 1
    assert "Test Banking API" in findings[0].title

    # Verify AssetGraph integration
    assert graph.has_technology("OpenAPI/Swagger")
    assert len(graph.endpoints) >= 2
    param_keys = list(graph.parameters.keys())
    assert any("recipient_id" in k for k in param_keys)
    assert any("amount" in k for k in param_keys)


if __name__ == "__main__":
    unittest.main()
