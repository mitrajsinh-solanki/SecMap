"""
SecMap Phase 15 Diff Output Renderers Test Suite.
Tests render_diff() formatting in Rich, plain text, JSON, and CSV modes, as well as Rich markup escaping and security cleanliness.
"""

import csv
import io
import json
import unittest

from secmap_core.diff import HostChange, PortChange, ScanDiff, render_diff
from secmap_core.diff.models import DiffSummary


class TestDiffOutput(unittest.TestCase):

    def setUp(self):
        self.diff = ScanDiff(
            summary=DiffSummary(hosts_added=1, ports_opened=1),
            host_changes=(HostChange(address="192.168.1.20", change_type="added", new_status="up"),),
            port_changes=(PortChange(host="192.168.1.10", port=443, protocol="tcp", change_type="opened", new_state="open"),),
        )

    def test_1_rich_diff_rendering(self):
        """Verify Rich UI diff rendering output."""
        out = render_diff(self.diff, output_mode="normal", plain=False)
        self.assertIn("SecMap Scan Difference Report", out)
        self.assertIn("192.168.1.20", out)
        self.assertIn("443/tcp", out)

    def test_2_plain_diff_rendering(self):
        """Verify plain text diff rendering output."""
        out = render_diff(self.diff, output_mode="normal", plain=True)
        self.assertIn("SecMap Scan Difference Report", out)
        self.assertIn("Hosts added:        1", out)
        self.assertIn("+ 192.168.1.10 : 443/tcp OPEN", out)

    def test_3_json_diff_rendering(self):
        """Verify pure JSON diff rendering output."""
        out = render_diff(self.diff, output_mode="json")
        parsed = json.loads(out)
        self.assertEqual(parsed["summary"]["hosts_added"], 1)
        self.assertEqual(parsed["summary"]["ports_opened"], 1)
        self.assertEqual(parsed["port_changes"][0]["port"], 443)

    def test_4_csv_diff_rendering(self):
        """Verify pure CSV diff rendering output."""
        out = render_diff(self.diff, output_mode="csv")
        reader = list(csv.reader(io.StringIO(out)))
        self.assertEqual(reader[0], ["CHANGE_TYPE", "HOST", "PORT", "PROTOCOL", "OLD_VALUE", "NEW_VALUE"])
        self.assertEqual(reader[1][0], "host_added")
        self.assertEqual(reader[1][1], "192.168.1.20")
        self.assertEqual(reader[2][0], "port_opened")
        self.assertEqual(reader[2][1], "192.168.1.10")
        self.assertEqual(reader[2][2], "443")

    def test_5_untrusted_rich_markup_escaping(self):
        """Verify historical strings with Rich markup are escaped safely."""
        diff = ScanDiff(
            summary=DiffSummary(hosts_added=1),
            host_changes=(HostChange(address="[bold red]FAKE_HOST[/bold red]", change_type="added"),),
        )
        out = render_diff(diff, output_mode="normal", plain=False)
        self.assertIn("[bold red]FAKE_HOST[/bold red]", out)


if __name__ == "__main__":
    unittest.main()
