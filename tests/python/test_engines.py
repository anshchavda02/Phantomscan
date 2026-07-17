import asyncio
import unittest

from phantomscan.engines import run_engine
from phantomscan.scope import parse_target


class EngineLauncherTests(unittest.TestCase):
    def test_missing_path_command_is_skipped(self):
        result = asyncio.run(
            run_engine(
                ["phantomscan-command-that-does-not-exist"],
                {"schema": "phantomscan.request.v1"},
                "node-browser",
                parse_target("example.com"),
            )
        )

        self.assertEqual(result.status, "skipped")
        self.assertIn("engine command missing on PATH", result.warnings[0])


if __name__ == "__main__":
    unittest.main()
