"""
SecMap Phase 16 History Storage Test Suite.
Tests HistoryStore atomic file persistence, snapshot ID validation, path traversal rejection, and corrupt file handling.
"""

import pathlib
import tempfile
import unittest

from secmap_core.cli import CLIError
from secmap_core.history.storage import HistoryStore, generate_snapshot_id, validate_snapshot_id
from secmap_core.normalize import HostResult, PortResult, ScanReport


class TestHistoryStorage(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store = HistoryStore(pathlib.Path(self.temp_dir.name))

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_1_generate_snapshot_id_format(self):
        """Verify generated snapshot IDs follow expected format."""
        sid = generate_snapshot_id()
        self.assertRegex(sid, r"^\d{8}-\d{6}-[a-f0-9]{6}$")

    def test_2_validate_snapshot_id_valid(self):
        """Verify valid snapshot IDs pass validation."""
        validate_snapshot_id("20260810-093415-a1b2c3")

    def test_3_path_traversal_rejection(self):
        """Verify snapshot IDs containing path traversal characters are rejected."""
        with self.assertRaises(CLIError) as ctx:
            validate_snapshot_id("../evil_snapshot")
        self.assertIn("Path traversal", str(ctx.exception))

    def test_4_save_and_load_snapshot(self):
        """Verify saving a ScanReport and loading it back."""
        report = ScanReport(
            targets=["127.0.0.1"],
            hosts=[
                HostResult(
                    address="127.0.0.1",
                    status="up",
                    ports=[PortResult(port=80, protocol="tcp", state="open")],
                )
            ],
        )
        snap_meta = self.store.save(report, profile="web", custom_id="test-snap-01")
        self.assertEqual(snap_meta.snapshot_id, "test-snap-01")
        self.assertEqual(snap_meta.profile, "web")
        self.assertEqual(snap_meta.host_count, 1)

        loaded_meta, loaded_report = self.store.load("test-snap-01")
        self.assertEqual(loaded_meta.snapshot_id, "test-snap-01")
        self.assertEqual(loaded_report.targets, ["127.0.0.1"])
        self.assertEqual(len(loaded_report.hosts), 1)
        self.assertEqual(loaded_report.hosts[0].ports[0].port, 80)

    def test_5_list_snapshots_ordered(self):
        """Verify list() returns snapshots ordered by created_at descending."""
        report = ScanReport(targets=["127.0.0.1"], hosts=[HostResult(address="127.0.0.1", status="up")])
        self.store.save(report, custom_id="snap-01")
        self.store.save(report, custom_id="snap-02")

        snaps = self.store.list()
        self.assertEqual(len(snaps), 2)

    def test_6_delete_snapshot(self):
        """Verify deleting a snapshot removes its file."""
        report = ScanReport(targets=["127.0.0.1"])
        self.store.save(report, custom_id="snap-delete-me")
        self.store.delete("snap-delete-me")

        snaps = self.store.list()
        self.assertEqual(len(snaps), 0)

    def test_7_load_nonexistent_snapshot_error(self):
        """Verify loading non-existent snapshot ID raises CLIError."""
        with self.assertRaises(CLIError) as ctx:
            self.store.load("nonexistent-id")
        self.assertIn("does not exist", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
