import unittest

from phantomscan.scope import parse_target, is_in_scope
from phantomscan.recon import resolve_target, collect_dns_records
from phantomscan.js_analyzer import JSRouteExtractor
from phantomscan.openapi_parser import OpenAPIParser


class TargetPortAndSPATests(unittest.TestCase):
    def test_parse_target_with_port(self):
        target = parse_target("http://localhost:3000")
        self.assertEqual(target.host, "localhost")
        self.assertEqual(target.port, 3000)
        self.assertEqual(target.scheme, "http")
        self.assertEqual(target.base_url, "http://localhost:3000")
        self.assertEqual(target.netloc, "localhost:3000")
        self.assertTrue(target.is_local)

    def test_parse_target_ip_and_port(self):
        target = parse_target("http://127.0.0.1:8080")
        self.assertEqual(target.host, "127.0.0.1")
        self.assertEqual(target.port, 8080)
        self.assertEqual(target.base_url, "http://127.0.0.1:8080")
        self.assertTrue(target.is_local)

    def test_parse_target_standard_port_omitted_in_base_url(self):
        target = parse_target("http://example.com:80")
        self.assertEqual(target.base_url, "http://example.com")

        target_https = parse_target("https://example.com:443")
        self.assertEqual(target_https.base_url, "https://example.com")

    def test_local_detection(self):
        self.assertTrue(parse_target("localhost").is_local)
        self.assertTrue(parse_target("127.0.0.1").is_local)
        self.assertTrue(parse_target("192.168.1.100").is_local)
        self.assertTrue(parse_target("10.0.0.5").is_local)
        self.assertFalse(parse_target("example.com").is_local)
        self.assertFalse(parse_target("8.8.8.8").is_local)

    def test_is_in_scope_with_ports(self):
        target = parse_target("http://localhost:3000")
        self.assertTrue(is_in_scope(target, "http://localhost:3000/api/users"))
        self.assertTrue(is_in_scope(target, "http://localhost:3000/rest/products/search"))
        self.assertFalse(is_in_scope(target, "http://evil.com/api/users"))

    def test_js_route_patterns(self):
        sample_js = """
        function getProducts() {
            return axios.get('/rest/products/search?q=apple');
        }
        function loginUser(data) {
            fetch('/rest/user/login', { method: 'POST', body: JSON.stringify(data) });
        }
        const routes = [
            { path: '/api/Feedbacks', component: FeedbackComponent },
            { path: '/api/Challenges', component: ScoreBoardComponent },
            { path: '/ftp/legal.md', component: FileComponent }
        ];
        """
        import re
        from phantomscan.js_analyzer import _ROUTE_PATTERNS
        found_paths = set()
        for p in _ROUTE_PATTERNS:
            for m in p.finditer(sample_js):
                found_paths.add(m.group(1))

        self.assertTrue(any("/rest/products/search" in p for p in found_paths))
        self.assertTrue(any("/rest/user/login" in p for p in found_paths))
        self.assertTrue(any("/api/Feedbacks" in p for p in found_paths))
        self.assertTrue(any("/api/Challenges" in p for p in found_paths))
        self.assertTrue(any("/ftp/legal.md" in p for p in found_paths))


if __name__ == "__main__":
    unittest.main()

