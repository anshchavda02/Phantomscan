import unittest

from phantomscan.postprocess import deduplicate_findings, grade, score


class PostProcessTests(unittest.TestCase):
    def test_deduplicates_findings(self):
        item = {"id": "A", "target": "t", "evidence": "e", "severity": "low"}
        self.assertEqual(len(deduplicate_findings([item, item])), 1)

    def test_score_and_grade(self):
        # A scan with one medium finding AND port-scan data:
        port_obs = [{"name": "open_tcp_ports", "value": [80], "source": "go-portscan"}]
        self.assertEqual(score([{"severity": "medium"}], port_obs), 97)
        self.assertEqual(grade(97), "A+")
        # Without port scan data a 3-point completeness penalty applies
        self.assertEqual(score([{"severity": "medium"}]), 94)

    def test_incomplete_scan_is_not_perfect(self):
        observations = [
            {"name": "http_error", "value": "connection refused"},
            {"name": "tls_error", "value": "connection refused"},
            {"name": "whois_info", "value": {"status": "unavailable"}},
        ]
        self.assertLess(score([], observations), 100)


if __name__ == "__main__":
    unittest.main()
