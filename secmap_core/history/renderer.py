"""
SecMap History Renderer Module
Renders scan history listing and snapshot metadata into Rich terminal UI, plain text, JSON, or CSV outputs.
Phase 16 implementation.
"""

import csv
import io
import json
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from secmap_core.history.models import ScanSnapshot


def _sanitize_csv(field: str) -> str:
    """Escape CSV formula injection triggers (=, +, -, @)."""
    if not field:
        return ""
    field_str = str(field)
    if field_str.startswith(("=", "+", "-", "@")):
        return f"'{field_str}"
    return field_str


def render_history_list(
    snapshots: tuple[ScanSnapshot, ...],
    output_mode: str = "normal",
    plain: bool = False,
) -> str:
    """
    Render scan history list into requested format.

    Args:
        snapshots (tuple[ScanSnapshot, ...]): List of snapshot entries.
        output_mode (str): Output format ("normal", "json", "csv").
        plain (bool): Disable Rich UI if True.

    Returns:
        str: Rendered string.
    """
    mode = output_mode.strip().lower() if output_mode else "normal"

    if mode == "json":
        return _render_json_list(snapshots)

    if mode == "csv":
        return _render_csv_list(snapshots)

    if plain:
        return _render_plain_list(snapshots)

    return _render_rich_list(snapshots)


def _render_json_list(snapshots: tuple[ScanSnapshot, ...]) -> str:
    """Render history list into valid JSON format."""
    data = {
        "snapshots": [
            {
                "id": s.snapshot_id,
                "created_at": s.created_at,
                "profile": s.profile,
                "targets": list(s.targets),
                "scan_arguments": list(s.scan_arguments),
                "host_count": s.host_count,
                "open_port_count": s.open_port_count,
            }
            for s in snapshots
        ]
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


def _render_csv_list(snapshots: tuple[ScanSnapshot, ...]) -> str:
    """Render history list into formula-injection protected CSV format."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")

    writer.writerow(["ID", "CREATED_AT", "PROFILE", "TARGETS", "HOST_COUNT", "OPEN_PORT_COUNT"])
    for s in snapshots:
        targets_str = ",".join(s.targets)
        writer.writerow(
            [
                _sanitize_csv(s.snapshot_id),
                _sanitize_csv(s.created_at),
                _sanitize_csv(s.profile or "none"),
                _sanitize_csv(targets_str),
                str(s.host_count),
                str(s.open_port_count),
            ]
        )
    return buf.getvalue()


def _render_plain_list(snapshots: tuple[ScanSnapshot, ...]) -> str:
    """Render history list into plain text format."""
    if not snapshots:
        return "SecMap: No scan history found."

    lines = ["SecMap Scan History\n"]
    lines.append(f"{'SNAPSHOT ID':<26} {'DATE':<20} {'PROFILE':<10} {'TARGETS':<20} {'HOSTS':<6} {'PORTS'}")
    lines.append("-" * 90)

    for s in snapshots:
        prof = s.profile or "-"
        t_str = ",".join(s.targets) if s.targets else "-"
        dt_str = s.created_at[:19].replace("T", " ") if s.created_at else "-"
        lines.append(f"{s.snapshot_id:<26} {dt_str:<20} {prof:<10} {t_str:<20} {s.host_count:<6} {s.open_port_count}")

    return "\n".join(lines)


def _render_rich_list(snapshots: tuple[ScanSnapshot, ...]) -> str:
    """Render history list into styled Rich terminal output."""
    if not snapshots:
        return "SecMap: No scan history found."

    buf = io.StringIO()
    console = Console(file=buf, force_terminal=True, width=100, highlight=False)

    table = Table(title="SecMap Scan History", header_style="bold cyan", border_style="dim")
    table.add_column("SNAPSHOT ID", style="bold yellow")
    table.add_column("DATE", style="dim")
    table.add_column("PROFILE", style="cyan")
    table.add_column("TARGETS")
    table.add_column("HOSTS", justify="right")
    table.add_column("OPEN PORTS", justify="right", style="bold green")

    for s in snapshots:
        prof = s.profile or "-"
        t_str = ",".join(s.targets) if s.targets else "-"
        dt_str = s.created_at[:19].replace("T", " ") if s.created_at else "-"
        table.add_row(Text(s.snapshot_id), Text(dt_str), Text(prof), Text(t_str), str(s.host_count), str(s.open_port_count))

    console.print(table)
    return buf.getvalue()


def render_snapshot_info(
    snapshot: ScanSnapshot,
    output_mode: str = "normal",
    plain: bool = False,
) -> str:
    """
    Render snapshot metadata information into requested format.

    Args:
        snapshot (ScanSnapshot): Snapshot metadata.
        output_mode (str): Output format ("normal", "json", "csv").
        plain (bool): Disable Rich UI if True.

    Returns:
        str: Rendered string output.
    """
    mode = output_mode.strip().lower() if output_mode else "normal"

    if mode == "json":
        data = {
            "snapshot": {
                "id": snapshot.snapshot_id,
                "created_at": snapshot.created_at,
                "profile": snapshot.profile,
                "targets": list(snapshot.targets),
                "scan_arguments": list(snapshot.scan_arguments),
                "host_count": snapshot.host_count,
                "open_port_count": snapshot.open_port_count,
                "report_path": snapshot.report_path,
            }
        }
        return json.dumps(data, indent=2, ensure_ascii=False)

    if mode == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow(["ID", "CREATED_AT", "PROFILE", "TARGETS", "HOST_COUNT", "OPEN_PORT_COUNT"])
        writer.writerow(
            [
                _sanitize_csv(snapshot.snapshot_id),
                _sanitize_csv(snapshot.created_at),
                _sanitize_csv(snapshot.profile or "none"),
                _sanitize_csv(",".join(snapshot.targets)),
                str(snapshot.host_count),
                str(snapshot.open_port_count),
            ]
        )
        return buf.getvalue()

    if plain:
        lines = [
            f"Snapshot ID:     {snapshot.snapshot_id}",
            f"Created:         {snapshot.created_at}",
            f"Profile:         {snapshot.profile or 'none'}",
            f"Targets:         {', '.join(snapshot.targets) if snapshot.targets else 'none'}",
            f"Scan Arguments:  {' '.join(snapshot.scan_arguments) if snapshot.scan_arguments else 'none'}",
            f"Hosts Count:     {snapshot.host_count}",
            f"Open Ports:      {snapshot.open_port_count}",
            f"Report Path:     {snapshot.report_path}",
        ]
        return "\n".join(lines)

    buf = io.StringIO()
    console = Console(file=buf, force_terminal=True, width=100, highlight=False)

    text = Text()
    text.append("Snapshot ID:     ", style="bold")
    text.append(f"{snapshot.snapshot_id}\n", style="yellow")
    text.append("Created:         ", style="bold")
    text.append(f"{snapshot.created_at}\n", style="dim")
    text.append("Profile:         ", style="bold")
    text.append(f"{snapshot.profile or 'none'}\n", style="cyan")
    text.append("Targets:         ", style="bold")
    text.append(f"{', '.join(snapshot.targets) if snapshot.targets else 'none'}\n")
    text.append("Scan Arguments:  ", style="bold")
    text.append(f"{' '.join(snapshot.scan_arguments) if snapshot.scan_arguments else 'none'}\n", style="dim")
    text.append("Hosts Count:     ", style="bold")
    text.append(f"{snapshot.host_count}\n")
    text.append("Open Ports:      ", style="bold")
    text.append(f"{snapshot.open_port_count}\n", style="bold green")
    text.append("Report Path:     ", style="bold")
    text.append(f"{snapshot.report_path}", style="dim")

    console.print(Panel(text, title=f"[bold]Scan Snapshot ({snapshot.snapshot_id})[/bold]", border_style="cyan"))
    return buf.getvalue()
