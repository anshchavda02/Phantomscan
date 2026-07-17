import unittest

from phantomscan.postprocess import deduplicate_findings, grade, score


class PostProcessTests(unittest.TestCase):
    def test_deduplicates_findings(self):
        item = {"id": "A", "target": "t", "evidence": "e", "severity": "low"}
        self.assertEqual(len(deduplicate_findings([item, item])), 1)

    def test_score_and_grade(self):
        self.assertEqual(score([{"severity": "medium"}]), 97)
        self.assertEqual(grade(97), "A+")

    def test_incomplete_scan_is_not_perfect(self):
        observations = [
            {"name": "http_error", "value": "connection refused"},
            {"name": "tls_error", "value": "connection refused"},
            {"name": "whois_info", "value": {"status": "unavailable"}},
        ]
        self.assertLess(score([], observations), 100)


if __name__ == "__main__":
    unittest.main()
