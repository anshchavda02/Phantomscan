import pytest
import unittest

from phantomscan.scope import (
    ScopePolicy,
    is_in_scope,
    normalize_target,
    parse_target,
)
from phantomscan.http_client import (
    RobustHTTPClient,
    ScopeViolationError,
)
from phantomscan.health import validate_preflight_target
from phantomscan.recon import whois_lookup_name


class ScopeTests(unittest.TestCase):
    def test_domain_scope_allows_subdomain(self):
        target = parse_target("example.com")
        self.assertTrue(is_in_scope(target, "api.example.com"))
        self.assertTrue(is_in_scope(target, "https://sub.api.example.com/v1/test"))

    def test_domain_scope_rejects_other_domain(self):
        target = parse_target("example.com")
        self.assertFalse(is_in_scope(target, "example.org"))
        self.assertFalse(is_in_scope(target, "https://evil.com/callback"))

    def test_whois_uses_root_domain(self):
        target = parse_target("www.hackthissite.org")
        self.assertEqual(whois_lookup_name(target), "hackthissite.org")

    def test_scope_policy_private_ip_rejection(self):
        """SEC-S02: Prohibit private/loopback IPs for external target scope."""
        target = normalize_target("example.com")
        policy = ScopePolicy(target=target, allow_local=False)

        allowed, reason = policy.validate_target("http://127.0.0.1:8080")
        self.assertFalse(allowed)
        self.assertIn("Private/loopback IP", reason)

        allowed, reason = policy.validate_target("http://10.0.1.5/admin")
        self.assertFalse(allowed)

        allowed, reason = policy.validate_target("http://192.168.1.100")
        self.assertFalse(allowed)

    def test_scope_policy_cloud_metadata_rejection(self):
        """SEC-S02: Prohibit cloud metadata endpoints by default."""
        target = normalize_target("example.com")
        policy = ScopePolicy(target=target, allow_local=False)

        allowed, reason = policy.validate_target("http://169.254.169.254/latest/meta-data/")
        self.assertFalse(allowed)
        self.assertIn("Cloud metadata", reason)

        allowed, reason = policy.validate_target("http://metadata.google.internal/computeMetadata/v1/")
        self.assertFalse(allowed)

    def test_scope_policy_allows_local_when_explicit(self):
        """Local targets allow private/loopback ranges."""
        local_target = normalize_target("http://localhost:3000")
        self.assertTrue(local_target.is_local)
        policy = ScopePolicy(target=local_target, allow_local=True)

        allowed, _ = policy.validate_target("http://localhost:3000/api")
        self.assertTrue(allowed)

        allowed, _ = policy.validate_target("http://127.0.0.1:3000")
        self.assertTrue(allowed)

    def test_scope_policy_cidr_matching(self):
        """CIDR range matching."""
        cidr_target = normalize_target("192.168.1.0/24")
        policy = ScopePolicy(target=cidr_target, allow_local=True)

        allowed, _ = policy.validate_target("http://192.168.1.50:8080/status")
        self.assertTrue(allowed)

        allowed, _ = policy.validate_target("http://192.168.2.1")
        self.assertFalse(allowed)

    def test_preflight_target_validation(self):
        """Pre-flight sanity validation."""
        valid_ext = normalize_target("example.com")
        is_ok, errs = validate_preflight_target(valid_ext)
        self.assertTrue(is_ok)
        self.assertEqual(len(errs), 0)

        # Invalid target with metadata host on non-local
        meta_target = normalize_target("http://169.254.169.254")
        # override is_local to simulate non-local misclassification
        object.__setattr__(meta_target, "is_local", False)
        is_ok, errs = validate_preflight_target(meta_target)
        self.assertFalse(is_ok)
        self.assertTrue(any("cloud metadata" in e.lower() for e in errs))


@pytest.mark.asyncio
async def test_http_client_scope_violation():
    """SEC-S01: RobustHTTPClient raises ScopeViolationError on out-of-scope requests."""
    target = normalize_target("example.com")
    policy = ScopePolicy(target=target, allow_local=False)
    client = RobustHTTPClient(scope_policy=policy)
    await client.start()
    try:
        with pytest.raises(ScopeViolationError):
            await client.get("http://evil-attacker.com/steal")

        with pytest.raises(ScopeViolationError):
            await client.get("http://169.254.169.254/latest/meta-data/")
    finally:
        await client.close()

