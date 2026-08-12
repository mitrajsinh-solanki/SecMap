"""
SecMap Phase 16 History Manager Test Suite.
Tests HistoryManager business logic: listing, latest snapshot, compare_snapshots, compare_latest, and insufficient history handling.
"""

import pathlib
import tempfile
import unittest

from secmap_core.cli import CLIError
from secmap_core.history.manager import HistoryManager
from secmap_core.normalize import HostResult, PortResult, ScanReport


class TestHistoryManager(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.mgr = HistoryManager(pathlib.Path(self.temp_dir.name))

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_1_get_latest_no_history_error(self):
        """Verify get_latest() raises CLIError when history is empty."""
        with self.assertRaises(CLIError) as ctx:
            self.mgr.get_latest()
        self.assertIn("No scan history found", str(ctx.exception))

    def test_2_compare_latest_insufficient_history_error(self):
        """Verify compare_latest() raises CLIError when fewer than 2 snapshots exist."""
        report = ScanReport(targets=["127.0.0.1"])
        self.mgr.save_scan(report)

        with self.assertRaises(CLIError) as ctx:
            self.mgr.compare_latest()
        self.assertIn("At least two snapshots are required", str(ctx.exception))

    def test_3_compare_latest_success(self):
        """Verify compare_latest compares the newest snapshot against previous."""
        b_report = ScanReport(
            hosts=[
                HostResult(
                    address="127.0.0.1",
                    status="up",
                    ports=[PortResult(port=22, protocol="tcp", state="open")],
                )
            ]
        )
        c_report = ScanReport(
            hosts=[
                HostResult(
                    address="127.0.0.1",
                    status="up",
                    ports=[
                        PortResult(port=22, protocol="tcp", state="open"),
                        PortResult(port=80, protocol="tcp", state="open"),
                    ],
                )
            ]
        )
        s1 = self.mgr.save_scan(b_report, profile="quick")
        s2 = self.mgr.save_scan(c_report, profile="web")

        base_meta, curr_meta, diff = self.mgr.compare_latest()
        self.assertEqual(diff.summary.ports_opened, 1)
        self.assertEqual(diff.port_changes[0].port, 80)

    def test_4_compare_snapshots_by_id(self):
        """Verify compare_snapshots compares two explicitly identified snapshots."""
        b_report = ScanReport(hosts=[HostResult(address="192.168.1.10", status="up")])
        c_report = ScanReport(hosts=[HostResult(address="192.168.1.10", status="up"), HostResult(address="192.168.1.20", status="up")])

        s1 = self.mgr.store.save(b_report, custom_id="id-01")
        s2 = self.mgr.store.save(c_report, custom_id="id-02")

        diff = self.mgr.compare_snapshots("id-01", "id-02")
        self.assertEqual(diff.summary.hosts_added, 1)
        self.assertEqual(diff.host_changes[0].address, "192.168.1.20")


if __name__ == "__main__":
    unittest.main()
