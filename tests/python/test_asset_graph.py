"""Unit tests for Phase 3: Shared Attack-Surface & Asset Graph."""

import unittest

from phantomscan.asset_graph import (
    AssetGraph,
    AuthContextNode,
    EndpointNode,
    HostNode,
    ParameterNode,
    ServiceNode,
    TechnologyNode,
)
from phantomscan.injection_target import build_asset_graph


class AssetGraphTests(unittest.TestCase):
    def test_manual_graph_construction(self):
        graph = AssetGraph()
        host = graph.add_host("example.com", ip_addresses=["93.184.216.34"], is_local=False)
        self.assertEqual(host.hostname, "example.com")
        self.assertIn("93.184.216.34", host.ip_addresses)

        service = graph.add_service("example.com", 443, service_name="https", tls_enabled=True)
        self.assertEqual(service.key, "example.com:443/tcp")
        self.assertTrue(service.tls_enabled)

        endpoint = graph.add_endpoint("https://example.com/api/users", method="GET", status_code=200)
        self.assertEqual(endpoint.path, "/api/users")
        self.assertEqual(endpoint.method, "GET")

        param = graph.add_parameter(
            "https://example.com/api/users",
            method="GET",
            param_name="id",
            param_type="query",
            original_value="42",
        )
        self.assertIsNotNone(param)
        self.assertEqual(param.param_name, "id")

        tech = graph.add_technology("React", version="18.2.0", category="Frontend Framework")
        self.assertEqual(tech.name, "React")
        self.assertTrue(graph.has_technology("react"))
        self.assertFalse(graph.has_technology("django"))

        auth = graph.add_auth_context(
            context_id="admin_session",
            role="admin",
            auth_type="bearer",
            token_or_cookie="eyJhbGciOi...",
            headers={"Authorization": "Bearer eyJhbGciOi..."},
        )
        self.assertEqual(auth.role, "admin")
        self.assertIn("admin_session", graph.auth_contexts)

    def test_from_observations_parsing(self):
        sample_observations = [
            {
                "name": "dns_records",
                "value": {"A": ["10.0.0.5"], "AAAA": []},
            },
            {
                "name": "port_results",
                "value": [
                    {
                        "host": "testsite.local",
                        "port": 8080,
                        "service": "http-proxy",
                        "banner": "Werkzeug/2.2.2",
                    }
                ],
            },
            {
                "name": "technologies",
                "value": [
                    {"name": "FastAPI", "version": "0.95.0", "category": "Web Framework"},
                    {"name": "PostgreSQL", "version": "15.0", "category": "Database"},
                ],
            },
            {
                "name": "discovered_urls",
                "value": [
                    "http://testsite.local:8080/products?category=electronics&sort=asc",
                    "http://testsite.local:8080/about",
                ],
            },
            {
                "name": "discovered_forms",
                "value": [
                    {
                        "action": "/login",
                        "method": "POST",
                        "fields": [
                            {"name": "username", "type": "text", "value": "admin"},
                            {"name": "password", "type": "password", "value": ""},
                            {"name": "csrf_token", "type": "hidden", "value": "abc123secret"},
                        ],
                    }
                ],
            },
        ]

        graph = build_asset_graph(sample_observations, base_url="http://testsite.local:8080")

        # Verify hosts & services
        self.assertIn("testsite.local", graph.hosts)
        self.assertIn("testsite.local:8080/tcp", graph.services)
        self.assertEqual(graph.services["testsite.local:8080/tcp"].service_name, "http-proxy")

        # Verify tech
        self.assertTrue(graph.has_technology("FastAPI"))
        self.assertTrue(graph.has_technology("PostgreSQL"))

        # Verify endpoints & parameters
        targets = graph.get_injection_targets()
        param_names = [t.param_name for t in targets]
        self.assertIn("category", param_names)
        self.assertIn("sort", param_names)
        self.assertIn("username", param_names)
        self.assertIn("password", param_names)

        # Ensure hidden fields are preserved on form targets
        login_targets = [t for t in targets if t.target_type == "form"]
        self.assertTrue(len(login_targets) >= 2)
        for lt in login_targets:
            self.assertEqual(lt.hidden_fields.get("csrf_token"), "abc123secret")

    def test_serialization_roundtrip(self):
        graph = AssetGraph()
        graph.add_host("api.target.com", ip_addresses=["1.2.3.4"])
        graph.add_service("api.target.com", 443, service_name="https")
        graph.add_endpoint("https://api.target.com/v1/search", method="GET")
        graph.add_parameter("https://api.target.com/v1/search", method="GET", param_name="q")
        graph.add_technology("Express", version="4.18.2")

        graph_dict = graph.to_dict()
        self.assertIn("api.target.com", graph_dict["hosts"])
        self.assertIn("express", graph_dict["technologies"])

        restored = AssetGraph.from_dict(graph_dict)
        self.assertEqual(len(restored.hosts), len(graph.hosts))
        self.assertEqual(len(restored.services), len(graph.services))
        self.assertEqual(len(restored.endpoints), len(graph.endpoints))
        self.assertEqual(len(restored.parameters), len(graph.parameters))
        self.assertTrue(restored.has_technology("express"))

    def test_observation_export(self):
        graph = AssetGraph()
        graph.add_endpoint("https://target.com/test", method="GET")
        graph.add_parameter("https://target.com/test", method="GET", param_name="p")
        graph.add_technology("Flask", version="2.3.0")

        obs = graph.to_observations()
        obs_names = [o["name"] for o in obs]
        self.assertIn("asset_graph_technologies", obs_names)
        self.assertIn("asset_graph_endpoints_count", obs_names)
        self.assertIn("asset_graph_parameters_count", obs_names)


if __name__ == "__main__":
    unittest.main()
