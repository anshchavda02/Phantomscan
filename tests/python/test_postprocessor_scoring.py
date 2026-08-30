"""Unit tests for Phase 8: False Positive Post-Processor & Evidence Verification Engine."""

import unittest
from pathlib import Path

import pytest

from phantomscan.postprocess import (
    DEDUCTION_CAPS,
    DEDUCTIONS,
    _scan_completeness_penalty,
    load_known_platform,
    post_process,
    score,
)


class TestPostProcessorAndScoring(unittest.TestCase):
    def test_pr_s01_deduction_caps(self):
        """PR-S01: Category deductions are strictly capped."""
        # 10 critical findings
        crit_findings = [{"id": f"CRIT-{i}", "severity": "critical", "title": f"Crit {i}"} for i in range(10)]
        crit_score = score(crit_findings, observations=[{"name": "is_local_target", "value": True}])
        # Base 100 - 30 max deduction = 70. But severities cap critical at 49 max score.
        self.assertLessEqual(crit_score, 49)

        # 10 low findings
        low_findings = [{"id": f"LOW-{i}", "severity": "low", "title": f"Low {i}"} for i in range(10)]
        low_score = score(low_findings, observations=[{"name": "is_local_target", "value": True}])
        # Base 100 - 10 max deduction = 90
        self.assertEqual(low_score, 90)

        # 10 info findings (0 deduction)
        info_findings = [{"id": f"INFO-{i}", "severity": "info", "title": f"Info {i}"} for i in range(10)]
        info_score = score(info_findings, observations=[{"name": "is_local_target", "value": True}])
        self.assertEqual(info_score, 99)

    def test_pr_s02_positive_bonuses(self):
        """PR-S02: Positive bonuses for HTTPS, SSL grade A+, WAF, CDN."""
        obs = [
            {"name": "scheme", "value": "https"},
            {"name": "ssl_grade", "value": "A+"},
            {"name": "waf", "value": "Cloudflare WAF active"},
            {"name": "cdn", "value": "Cloudflare CDN"},
            {"name": "open_tcp_ports", "value": [443]},
        ]
        # Clean findings with full bonuses
        calc = score([], observations=obs)
        self.assertEqual(calc, 100)

    def test_pr_s03_local_target_exemptions(self):
        """PR-S03: Local targets are not penalized for missing DNS/WHOIS/TLS."""
        local_obs = [
            {"name": "is_local_target", "value": True},
            {"name": "dns_error", "value": "NXDOMAIN"},
            {"name": "whois_info", "value": "unavailable"},
            {"name": "tls_error", "value": "unverified"},
        ]
        penalty = _scan_completeness_penalty(local_obs)
        self.assertEqual(penalty, 0)

    def test_pr_fp01_root_domain_platform_matching(self):
        """PR-FP01: Platforms are resolved via root domain."""
        data_dir = Path(__file__).parent.parent.parent / "data"
        platform = load_known_platform(data_dir, "https://subdomain.google.com/test")
        self.assertIsNotNone(platform)
        self.assertEqual(platform.get("minimum_score"), 75)


if __name__ == "__main__":
    unittest.main()
