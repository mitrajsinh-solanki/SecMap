"""
SecMap Phase 16 History CLI & Renderer Test Suite.
Tests history listing formatting, snapshot info rendering, CSV formula injection protection, and JSON/CSV output modes.
"""

import csv
import io
import json
import unittest

from secmap_core.history.models import ScanSnapshot
from secmap_core.history.renderer import render_history_list, render_snapshot_info


class TestHistoryCLI(unittest.TestCase):

    def setUp(self):
        self.snapshots = (
            ScanSnapshot(
                snapshot_id="20260810-093415-a1b2c3",
                created_at="2026-08-10T09:34:15+05:30",
                targets=("127.0.0.1",),
                profile="web",
                host_count=1,
                open_port_count=2,
            ),
        )

    def test_1_rich_history_list_rendering(self):
        """Verify Rich UI history listing output."""
        out = render_history_list(self.snapshots, output_mode="normal", plain=False)
        self.assertIn("SecMap Scan History", out)
        self.assertIn("20260810-093415-a1b2c3", out)
        self.assertIn("web", out)

    def test_2_plain_history_list_rendering(self):
        """Verify plain text history listing output."""
        out = render_history_list(self.snapshots, output_mode="normal", plain=True)
        self.assertIn("SecMap Scan History", out)
        self.assertIn("20260810-093415-a1b2c3", out)

    def test_3_json_history_list_rendering(self):
        """Verify pure JSON history listing output."""
        out = render_history_list(self.snapshots, output_mode="json")
        parsed = json.loads(out)
        self.assertEqual(len(parsed["snapshots"]), 1)
        self.assertEqual(parsed["snapshots"][0]["id"], "20260810-093415-a1b2c3")

    def test_4_csv_history_list_rendering(self):
        """Verify formula-injection protected CSV history listing output."""
        out = render_history_list(self.snapshots, output_mode="csv")
        reader = list(csv.reader(io.StringIO(out)))
        self.assertEqual(reader[0], ["ID", "CREATED_AT", "PROFILE", "TARGETS", "HOST_COUNT", "OPEN_PORT_COUNT"])
        self.assertEqual(reader[1][0], "20260810-093415-a1b2c3")
        self.assertEqual(reader[1][2], "web")

    def test_5_csv_formula_injection_escaping(self):
        """Verify snapshot fields starting with =, +, -, @ are escaped."""
        evil_snapshots = (
            ScanSnapshot(
                snapshot_id="=DDE|'cmd'/C!calc",
                created_at="2026-08-10T09:34:15",
                profile="-profile",
                host_count=1,
            ),
        )
        out = render_history_list(evil_snapshots, output_mode="csv")
        reader = list(csv.reader(io.StringIO(out)))
        self.assertTrue(reader[1][0].startswith("'="))
        self.assertTrue(reader[1][2].startswith("'-"))


if __name__ == "__main__":
    unittest.main()
