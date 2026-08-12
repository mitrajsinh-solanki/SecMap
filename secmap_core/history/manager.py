"""
SecMap History Manager Module
Orchestrates snapshot saving, retrieval, listing, deletion, and comparison workflows.
Phase 16 implementation.
"""

import pathlib
from secmap_core.cli import CLIError
from secmap_core.diff import ScanDiff, ScanDiffEngine
from secmap_core.history.models import ScanSnapshot
from secmap_core.history.storage import HistoryStore
from secmap_core.normalize import ScanReport


class HistoryManager:
    """High-level history management controller."""

    def __init__(self, history_dir: pathlib.Path | None = None):
        self.store = HistoryStore(history_dir)
        self.diff_engine = ScanDiffEngine()

    def save_scan(
        self,
        report: ScanReport,
        profile: str | None = None,
        scan_arguments: list[str] | tuple[str, ...] | None = None,
    ) -> ScanSnapshot:
        """Save scan report and return snapshot metadata."""
        return self.store.save(report, profile=profile, scan_arguments=scan_arguments)

    def list_history(self) -> tuple[ScanSnapshot, ...]:
        """List all scan history snapshots."""
        return self.store.list()

    def get_snapshot(self, snapshot_id: str) -> tuple[ScanSnapshot, ScanReport]:
        """Retrieve snapshot metadata and report model by snapshot ID."""
        return self.store.load(snapshot_id)

    def get_latest(self) -> tuple[ScanSnapshot, ScanReport]:
        """Retrieve newest snapshot and report model."""
        snapshots = self.store.list()
        if not snapshots:
            raise CLIError("SecMap: No scan history found.")
        latest_meta = snapshots[0]
        return self.store.load(latest_meta.snapshot_id)

    def delete_snapshot(self, snapshot_id: str) -> None:
        """Delete a specified history snapshot."""
        self.store.delete(snapshot_id)

    def compare_snapshots(self, baseline_id: str, current_id: str) -> ScanDiff:
        """Compare two specified historical snapshots."""
        _, base_report = self.store.load(baseline_id)
        _, curr_report = self.store.load(current_id)
        return self.diff_engine.compare(base_report, curr_report)

    def compare_latest(self) -> tuple[ScanSnapshot, ScanSnapshot, ScanDiff]:
        """Compare the newest snapshot against the previous snapshot."""
        snapshots = self.store.list()
        if len(snapshots) < 2:
            raise CLIError("SecMap: At least two snapshots are required for comparison.")

        curr_meta = snapshots[0]
        base_meta = snapshots[1]

        _, curr_report = self.store.load(curr_meta.snapshot_id)
        _, base_report = self.store.load(base_meta.snapshot_id)

        diff = self.diff_engine.compare(base_report, curr_report)
        return base_meta, curr_meta, diff
