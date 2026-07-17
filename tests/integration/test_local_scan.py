import subprocess
import sys
import unittest
from pathlib import Path


class LocalScanTests(unittest.TestCase):
    def test_help_runs(self):
        root = Path(__file__).resolve().parents[2]
        result = subprocess.run(
            [sys.executable, str(root / "phantomscan.py"), "--help"],
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("phantomscan", result.stdout)


if __name__ == "__main__":
    unittest.main()

