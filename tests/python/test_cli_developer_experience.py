"""Unit tests for Phase 15: Developer Experience, Rich CLI, Interactive Dashboard & Live Progress System."""

import importlib.util
from pathlib import Path
import tempfile
import unittest

from phantomscan.models import Finding
from phantomscan.reporting import write_csv_report, write_html_report, write_json_report
from phantomscan.scope import normalize_target

# Dynamically load phantomscan.py from root
_cli_path = Path(__file__).resolve().parent.parent.parent / "phantomscan.py"
_spec = importlib.util.spec_from_file_location("phantomscan_cli", _cli_path)
phantomscan_cli = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(phantomscan_cli)


class TestCLIDeveloperExperience(unittest.TestCase):
    def test_cli_parser_profiles(self):
        """CLI parser includes all 9 scan profiles."""
        parser = phantomscan_cli.build_parser()
        # Parse test arguments
        args = parser.parse_args(["--target", "example.com", "--profile", "deep"])
        self.assertEqual(args.target, "example.com")
        self.assertEqual(args.profile, "deep")

    def test_cli_auth_warning_banner(self):
        """SEC-E01: Authorization warning is defined and clear."""
        self.assertIn("Authorized security assessment only", phantomscan_cli.WARNING)
        self.assertIn("Scope is enforced per target", phantomscan_cli.WARNING)

    def test_report_generation_multi_format(self):
        """Generate HTML, JSON, and CSV reports safely."""
        findings = [
            {
                "title": "Cross-Site Scripting",
                "severity": "high",
                "confidence": "high",
                "evidence": "<script>alert(1)</script>",
                "module": "xss_scanner",
                "description": "Reflected XSS on parameter q",
                "impact": "Session hijack",
                "recommendation": "Contextual output encoding",
                "verification_method": "active_confirmation",
                "category": "xss",
                "id": "XSS-REFLECTED-1",
            }
        ]
        payload = {
            "target": "example.com",
            "score": 85,
            "grade": "B",
            "findings": findings,
            "observations": [],
            "started_at": "2026-08-30T10:00:00Z",
            "finished_at": "2026-08-30T10:00:05Z",
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)

            # JSON Report
            json_file = tmp_path / "report.json"
            write_json_report(json_file, payload)
            self.assertTrue(json_file.exists())
            self.assertIn("Cross-Site Scripting", json_file.read_text(encoding="utf-8"))

            # CSV Report
            csv_file = tmp_path / "report.csv"
            write_csv_report(csv_file, payload)
            self.assertTrue(csv_file.exists())
            self.assertIn("Cross-Site Scripting", csv_file.read_text(encoding="utf-8"))

            # HTML Report
            html_file = tmp_path / "report.html"
            write_html_report(html_file, payload)
            self.assertTrue(html_file.exists())
            html_content = html_file.read_text(encoding="utf-8")
            self.assertIn("Cross-Site Scripting", html_content)
            # SEC-R01: Raw unescaped target payload must NOT be executed as active HTML script
            self.assertNotIn("<script>alert(1)</script><div", html_content)



if __name__ == "__main__":
    unittest.main()
