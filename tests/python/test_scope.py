import unittest

from phantomscan.scope import is_in_scope, parse_target
from phantomscan.recon import whois_lookup_name


class ScopeTests(unittest.TestCase):
    def test_domain_scope_allows_subdomain(self):
        target = parse_target("example.com")
        self.assertTrue(is_in_scope(target, "api.example.com"))

    def test_domain_scope_rejects_other_domain(self):
        target = parse_target("example.com")
        self.assertFalse(is_in_scope(target, "example.org"))

    def test_whois_uses_root_domain(self):
        target = parse_target("www.hackthissite.org")
        self.assertEqual(whois_lookup_name(target), "hackthissite.org")


if __name__ == "__main__":
    unittest.main()
