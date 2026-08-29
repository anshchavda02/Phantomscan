import unittest

from phantomscan.postprocess import deduplicate_findings, grade, score


class PostProcessTests(unittest.TestCase):
    def test_deduplicates_findings(self):
        item = {"id": "A", "target": "t", "evidence": "e", "severity": "low"}
        self.assertEqual(len(deduplicate_findings([item, item])), 1)

    def test_score_and_grade(self):
        # A scan with one medium finding AND port-scan data:
        port_obs = [{"name": "open_tcp_ports", "value": [80], "source": "go-portscan"}]
        self.assertEqual(score([{"severity": "medium"}], port_obs), 92)
        self.assertEqual(grade(92), "A+")
        # Without port scan data a 3-point completeness penalty applies
        self.assertEqual(score([{"severity": "medium"}]), 89)

    def test_incomplete_scan_is_not_perfect(self):
        observations = [
            {"name": "http_error", "value": "connection refused"},
            {"name": "tls_error", "value": "connection refused"},
            {"name": "whois_info", "value": {"status": "unavailable"}},
        ]
        self.assertLess(score([], observations), 100)

    def test_fp_runs_before_score(self):
        """Assert that for a known-platform target (google.com/www.google.com),
        the postprocessor suppresses false positives and score >= 75 platform minimum.
        """
        from pathlib import Path
        from phantomscan.postprocess import post_process, load_known_platform
        from modules.known_platforms import match_platform

        data_dir = Path(__file__).resolve().parent.parent.parent / "data"

        # Platform lookup works for both apex and subdomain
        platform_apex = match_platform(data_dir, "google.com")
        platform_sub = match_platform(data_dir, "www.google.com")
        self.assertIsNotNone(platform_apex)
        self.assertIsNotNone(platform_sub)
        self.assertEqual(platform_apex.get("minimum_score"), 75)
        self.assertEqual(platform_sub.get("minimum_score"), 75)

        raw_findings = [
            {
                "id": "WAF-MISSING",
                "title": "No WAF Detected",
                "severity": "medium",
                "confidence": "high",
                "evidence": "No edge WAF signatures detected.",
            },
            {
                "id": "RATE-LIMIT-MISSING",
                "title": "No Rate Limiting Detected",
                "severity": "medium",
                "confidence": "high",
                "evidence": "No 429 response on burst test.",
            },
        ]
        observations = [
            {"name": "open_tcp_ports", "value": [80, 443], "source": "go-portscan"},
            {"name": "ssl_grade", "value": "A+", "source": "rust-tls"},
        ]

        # 1. FP postprocessing
        final_findings, suppressed, clean_obs = post_process(
            findings=raw_findings,
            observations=observations,
            data_dir=data_dir,
            target_host="www.google.com",
            include_medium=True,
            include_low=False,
        )

        # Suppressed findings should be 2, final findings should be 0
        self.assertEqual(len(final_findings), 0)
        self.assertEqual(len(suppressed), 2)

        # 2. Score calculation on clean findings
        final_score = score(final_findings, clean_obs, platform=platform_sub)
        self.assertGreaterEqual(final_score, 75)
        self.assertEqual(grade(final_score), "A+")


if __name__ == "__main__":
    unittest.main()

