"""
SecMap History Storage Module
Manages cross-platform filesystem persistence, atomic JSON file writes, and path traversal validation for scan history snapshots.
Phase 16 implementation.
"""

import datetime
import json
import os
import pathlib
import re
import sys
import uuid
from secmap_core.cli import CLIError
from secmap_core.history.models import ScanSnapshot
from secmap_core.normalize import ScanReport, get_open_ports, load_scan_report

VALID_SNAPSHOT_ID_REGEX = re.compile(r"^[A-Za-z0-9_-]+$")


def get_history_dir(custom_path: pathlib.Path | None = None) -> pathlib.Path:
    """
    Determine cross-platform storage directory for SecMap history snapshots.

    Returns:
        pathlib.Path: Resolved history directory path.
    """
    if custom_path:
        p = pathlib.Path(custom_path)
        p.mkdir(parents=True, exist_ok=True)
        return p

    home = pathlib.Path.home()

    if sys.platform.startswith("win"):
        appdata = os.environ.get("APPDATA")
        if appdata:
            p = pathlib.Path(appdata) / "secmap" / "history"
            p.mkdir(parents=True, exist_ok=True)
            return p

    xdg_data = os.environ.get("XDG_DATA_HOME")
    if xdg_data:
        p = pathlib.Path(xdg_data) / "secmap" / "history"
        p.mkdir(parents=True, exist_ok=True)
        return p

    p = home / ".secmap" / "history"
    p.mkdir(parents=True, exist_ok=True)
    return p


def generate_snapshot_id() -> str:
    """
    Generate a safe, unique snapshot identifier string.

    Returns:
        str: Timestamped snapshot ID (e.g. 20260810-093415-a1b2c3).
    """
    now = datetime.datetime.now()
    ts = now.strftime("%Y%m%d-%H%M%S")
    rand_hex = uuid.uuid4().hex[:6]
    return f"{ts}-{rand_hex}"


def validate_snapshot_id(snapshot_id: str) -> None:
    """
    Validate snapshot ID against strict identifier regex and path traversal rules.

    Args:
        snapshot_id (str): Snapshot identifier.

    Raises:
        CLIError: If snapshot ID is invalid or contains path traversal characters.
    """
    if not snapshot_id or not isinstance(snapshot_id, str):
        raise CLIError("SecMap Error: Snapshot ID must be a non-empty string.")

    if ".." in snapshot_id or "/" in snapshot_id or "\\" in snapshot_id:
        raise CLIError(f"SecMap Error: Invalid snapshot ID '{snapshot_id}'. Path traversal characters are forbidden.")

    if not VALID_SNAPSHOT_ID_REGEX.match(snapshot_id):
        raise CLIError(
            f"SecMap Error: Invalid snapshot ID '{snapshot_id}'. IDs must contain only letters, numbers, underscores, and hyphens."
        )


class HistoryStore:
    """Provides atomic persistence and lookup operations for scan history snapshots."""

    def __init__(self, history_dir: pathlib.Path | None = None):
        self.history_dir = get_history_dir(history_dir)

    def save(
        self,
        report: ScanReport,
        profile: str | None = None,
        scan_arguments: list[str] | tuple[str, ...] | None = None,
        custom_id: str | None = None,
    ) -> ScanSnapshot:
        """
        Atomically save a ScanReport and its metadata to the history directory.

        Args:
            report (ScanReport): Scan report domain object.
            profile (str | None): Optional scan profile name.
            scan_arguments: Scan command arguments.
            custom_id (str | None): Optional specific snapshot ID.

        Returns:
            ScanSnapshot: Created snapshot metadata.
        """
        snapshot_id = custom_id or generate_snapshot_id()
        validate_snapshot_id(snapshot_id)

        created_at = datetime.datetime.now().isoformat()
        targets = tuple(report.targets) if report.targets else ()
        scan_args_tuple = tuple(scan_arguments) if scan_arguments else ()

        open_ports_count = sum(len(get_open_ports(h)) for h in report.hosts)

        # Build JSON dictionary for snapshot file
        report_dict = {
            "targets": list(targets),
            "hosts": [
                {
                    "address": h.address,
                    "address_type": h.address_type,
                    "status": h.status,
                    "hostname": h.hostname,
                    "ports": [
                        {
                            "port": p.port,
                            "protocol": p.protocol,
                            "state": p.state,
                            "reason": p.reason,
                            "service": (
                                {
                                    "name": p.service.name,
                                    "product": p.service.product,
                                    "version": p.service.version,
                                    "extra_info": p.service.extra_info,
                                }
                                if p.service
                                else None
                            ),
                            "scripts": [
                                {"script_id": s.script_id, "output": s.output} for s in p.scripts
                            ],
                        }
                        for p in h.ports
                    ],
                    "os": (
                        {
                            "matches": [
                                {
                                    "name": m.name,
                                    "accuracy": m.accuracy,
                                    "cpes": list(m.cpes),
                                }
                                for m in h.os.matches
                            ]
                        }
                        if h.os and h.os.matches
                        else None
                    ),
                    "scripts": [
                        {"script_id": s.script_id, "output": s.output} for s in h.scripts
                    ],
                }
                for h in report.hosts
            ],
        }

        full_data = {
            "schema_version": 1,
            "snapshot": {
                "id": snapshot_id,
                "created_at": created_at,
                "targets": list(targets),
                "profile": profile,
                "scan_arguments": list(scan_args_tuple),
                "host_count": len(report.hosts),
                "open_port_count": open_ports_count,
            },
            "report": report_dict,
        }

        target_file = self.history_dir / f"{snapshot_id}.json"
        tmp_file = self.history_dir / f"{snapshot_id}.tmp"

        # Perform atomic write
        try:
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(full_data, f, indent=2, ensure_ascii=False)
            tmp_file.replace(target_file)
        except Exception as e:
            if tmp_file.exists():
                try:
                    tmp_file.unlink()
                except Exception:
                    pass
            raise CLIError(f"SecMap Error: Failed to save scan history snapshot '{snapshot_id}': {str(e)}")

        return ScanSnapshot(
            snapshot_id=snapshot_id,
            created_at=created_at,
            targets=targets,
            profile=profile,
            scan_arguments=scan_args_tuple,
            report_path=str(target_file),
            host_count=len(report.hosts),
            open_port_count=open_ports_count,
        )

    def load(self, snapshot_id: str) -> tuple[ScanSnapshot, ScanReport]:
        """
        Load a snapshot metadata entry and its ScanReport domain model.

        Args:
            snapshot_id (str): Snapshot identifier.

        Returns:
            tuple[ScanSnapshot, ScanReport]: Snapshot metadata and domain report.
        """
        validate_snapshot_id(snapshot_id)
        target_file = self.history_dir / f"{snapshot_id}.json"

        if not target_file.exists():
            raise CLIError(f"SecMap Error: History snapshot '{snapshot_id}' does not exist.")

        try:
            with open(target_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            raise CLIError(f"SecMap Error: Failed to load snapshot file '{target_file}': {str(e)}")

        if not isinstance(data, dict):
            raise CLIError(f"SecMap Error: Invalid snapshot format in '{target_file}'. Root must be an object.")

        meta_dict = data.get("snapshot", {})
        report_dict = data.get("report", {})

        snapshot = ScanSnapshot(
            snapshot_id=meta_dict.get("id", snapshot_id),
            created_at=meta_dict.get("created_at", ""),
            targets=tuple(meta_dict.get("targets", [])),
            profile=meta_dict.get("profile"),
            scan_arguments=tuple(meta_dict.get("scan_arguments", [])),
            report_path=str(target_file),
            host_count=meta_dict.get("host_count", 0),
            open_port_count=meta_dict.get("open_port_count", 0),
        )

        # Parse embedded report dict cleanly using json_importer logic
        # Write to temporary file or load from dict directly
        tmp_report_file = self.history_dir / f"_tmp_load_{uuid.uuid4().hex}.json"
        try:
            with open(tmp_report_file, "w", encoding="utf-8") as f:
                json.dump(report_dict, f)
            report = load_scan_report(tmp_report_file)
        finally:
            if tmp_report_file.exists():
                try:
                    tmp_report_file.unlink()
                except Exception:
                    pass

        return snapshot, report

    def list(self) -> tuple[ScanSnapshot, ...]:
        """
        Retrieve all persisted scan snapshots ordered by created_at descending.

        Returns:
            tuple[ScanSnapshot, ...]: Tuple of metadata entries.
        """
        if not self.history_dir.exists():
            return ()

        snapshots = []
        for file in self.history_dir.glob("*.json"):
            if file.name.startswith("_tmp_"):
                continue
            try:
                with open(file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                meta_dict = data.get("snapshot", {})
                if not meta_dict:
                    continue

                snapshots.append(
                    ScanSnapshot(
                        snapshot_id=meta_dict.get("id", file.stem),
                        created_at=meta_dict.get("created_at", ""),
                        targets=tuple(meta_dict.get("targets", [])),
                        profile=meta_dict.get("profile"),
                        scan_arguments=tuple(meta_dict.get("scan_arguments", [])),
                        report_path=str(file),
                        host_count=meta_dict.get("host_count", 0),
                        open_port_count=meta_dict.get("open_port_count", 0),
                    )
                )
            except Exception as e:
                print(f"WARNING: Snapshot file '{file.name}' is unreadable or corrupt: {str(e)}", file=sys.stderr)

        snapshots.sort(key=lambda s: s.created_at, reverse=True)
        return tuple(snapshots)

    def delete(self, snapshot_id: str) -> None:
        """
        Delete a specified scan snapshot.

        Args:
            snapshot_id (str): Snapshot identifier.
        """
        validate_snapshot_id(snapshot_id)
        target_file = self.history_dir / f"{snapshot_id}.json"

        if not target_file.exists():
            raise CLIError(f"SecMap Error: History snapshot '{snapshot_id}' does not exist.")

        try:
            target_file.unlink()
        except Exception as e:
            raise CLIError(f"SecMap Error: Failed to delete history snapshot '{snapshot_id}': {str(e)}")
