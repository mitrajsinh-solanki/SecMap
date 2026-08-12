"""
SecMap Diff Renderer Module
Renders ScanDiff comparison results into Rich terminal UI, plain text, JSON, or CSV formats.
Phase 15 implementation.
"""

import csv
import io
import json
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from secmap_core.diff.models import ScanDiff


def render_diff(
    diff: ScanDiff,
    output_mode: str = "normal",
    plain: bool = False,
    baseline_name: str = "baseline",
    current_name: str = "current",
) -> str:
    """
    Render a ScanDiff result into requested output format (normal, plain, json, csv).

    Args:
        diff (ScanDiff): Scan difference object.
        output_mode (str): Output format ("normal", "json", "csv").
        plain (bool): Disable Rich UI if True.
        baseline_name (str): Baseline filename or descriptor.
        current_name (str): Current filename or descriptor.

    Returns:
        str: Rendered string output.
    """
    mode = output_mode.strip().lower() if output_mode else "normal"

    if mode == "json":
        return _render_json_diff(diff, baseline_name, current_name)

    if mode == "csv":
        return _render_csv_diff(diff)

    if plain:
        return _render_plain_diff(diff, baseline_name, current_name)

    return _render_rich_diff(diff, baseline_name, current_name)


def _render_json_diff(diff: ScanDiff, baseline_name: str, current_name: str) -> str:
    """Render ScanDiff into valid JSON string."""
    data = {
        "baseline": baseline_name,
        "current": current_name,
        "summary": {
            "hosts_added": diff.summary.hosts_added,
            "hosts_removed": diff.summary.hosts_removed,
            "hosts_changed": diff.summary.hosts_changed,
            "ports_opened": diff.summary.ports_opened,
            "ports_closed": diff.summary.ports_closed,
            "ports_changed": diff.summary.ports_changed,
            "services_changed": diff.summary.services_changed,
            "os_changed": diff.summary.os_changed,
            "scripts_changed": diff.summary.scripts_changed,
        },
        "host_changes": [
            {
                "address": h.address,
                "change_type": h.change_type,
                "old_status": h.old_status,
                "new_status": h.new_status,
            }
            for h in diff.host_changes
        ],
        "port_changes": [
            {
                "host": p.host,
                "port": p.port,
                "protocol": p.protocol,
                "change_type": p.change_type,
                "old_state": p.old_state,
                "new_state": p.new_state,
            }
            for p in diff.port_changes
        ],
        "service_changes": [
            {
                "host": s.host,
                "port": s.port,
                "protocol": s.protocol,
                "old_service": s.old_service,
                "new_service": s.new_service,
            }
            for s in diff.service_changes
        ],
        "os_changes": [
            {"host": o.host, "old_os": o.old_os, "new_os": o.new_os} for o in diff.os_changes
        ],
        "script_changes": [
            {
                "host": s.host,
                "port": s.port,
                "protocol": s.protocol,
                "script_id": s.script_id,
                "change_type": s.change_type,
                "old_output": s.old_output,
                "new_output": s.new_output,
            }
            for s in diff.script_changes
        ],
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


def _render_csv_diff(diff: ScanDiff) -> str:
    """Render ScanDiff into CSV string format."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")

    headers = ["CHANGE_TYPE", "HOST", "PORT", "PROTOCOL", "OLD_VALUE", "NEW_VALUE"]
    writer.writerow(headers)

    for h in diff.host_changes:
        writer.writerow([f"host_{h.change_type}", h.address, "", "", h.old_status or "", h.new_status or ""])

    for p in diff.port_changes:
        writer.writerow([f"port_{p.change_type}", p.host, str(p.port), p.protocol, p.old_state or "", p.new_state or ""])

    for s in diff.service_changes:
        writer.writerow(["service_changed", s.host, str(s.port), s.protocol, s.old_service or "", s.new_service or ""])

    for o in diff.os_changes:
        writer.writerow(["os_changed", o.host, "", "", o.old_os or "", o.new_os or ""])

    for s in diff.script_changes:
        p_num = str(s.port) if s.port is not None else ""
        proto = s.protocol or ""
        writer.writerow([f"script_{s.change_type}", s.host, p_num, proto, s.old_output or "", s.new_output or ""])

    return buf.getvalue()


def _render_plain_diff(diff: ScanDiff, baseline_name: str, current_name: str) -> str:
    """Render ScanDiff into plain text format."""
    lines = []
    lines.append("SecMap Scan Difference Report\n")
    lines.append(f"Baseline: {baseline_name}")
    lines.append(f"Current:  {current_name}\n")

    lines.append("Summary")
    lines.append("-" * 32)
    lines.append(f"Hosts added:        {diff.summary.hosts_added}")
    lines.append(f"Hosts removed:      {diff.summary.hosts_removed}")
    lines.append(f"Hosts changed:      {diff.summary.hosts_changed}")
    lines.append(f"Ports opened:       {diff.summary.ports_opened}")
    lines.append(f"Ports closed:       {diff.summary.ports_closed}")
    lines.append(f"Ports state changed:{diff.summary.ports_changed}")
    lines.append(f"Services changed:   {diff.summary.services_changed}")
    lines.append(f"OS changes:         {diff.summary.os_changed}")
    lines.append(f"Scripts changed:    {diff.summary.scripts_changed}\n")

    if diff.host_changes:
        lines.append("Host Changes")
        lines.append("-" * 32)
        for h in diff.host_changes:
            if h.change_type == "added":
                lines.append(f"  + Host added: {h.address} ({h.new_status})")
            elif h.change_type == "removed":
                lines.append(f"  - Host absent: {h.address} ({h.old_status})")
            else:
                lines.append(f"  * Host status: {h.address} ({h.old_status} -> {h.new_status})")
        lines.append("")

    opened_ports = [p for p in diff.port_changes if p.change_type == "opened"]
    if opened_ports:
        lines.append("New Open Ports")
        lines.append("-" * 32)
        for p in opened_ports:
            lines.append(f"  + {p.host} : {p.port}/{p.protocol} OPEN")
        lines.append("")

    closed_ports = [p for p in diff.port_changes if p.change_type == "closed"]
    if closed_ports:
        lines.append("Closed Ports")
        lines.append("-" * 32)
        for p in closed_ports:
            lines.append(f"  - {p.host} : {p.port}/{p.protocol} CLOSED")
        lines.append("")

    if diff.service_changes:
        lines.append("Service Changes")
        lines.append("-" * 32)
        for s in diff.service_changes:
            lines.append(f"  * {s.host} : {s.port}/{s.protocol}")
            lines.append(f"      Old: {s.old_service}")
            lines.append(f"      New: {s.new_service}")
        lines.append("")

    if diff.os_changes:
        lines.append("OS Detection Changes")
        lines.append("-" * 32)
        for o in diff.os_changes:
            lines.append(f"  * {o.host} : {o.old_os} -> {o.new_os}")
        lines.append("")

    if diff.script_changes:
        lines.append("NSE Script Changes")
        lines.append("-" * 32)
        for s in diff.script_changes:
            p_str = f" {s.port}/{s.protocol}" if s.port else ""
            lines.append(f"  * {s.host}{p_str} [{s.script_id}] ({s.change_type})")
        lines.append("")

    return "\n".join(lines)


def _render_rich_diff(diff: ScanDiff, baseline_name: str, current_name: str) -> str:
    """Render ScanDiff into styled Rich terminal output safely."""
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=True, width=100, highlight=False)

    # Header Panel
    hdr = Text("SecMap Scan Difference Report", style="bold cyan", justify="center")
    console.print(Panel(hdr, title="[bold]SecMap Diff[/bold]", border_style="cyan"))

    # Files Panel
    files_text = Text()
    files_text.append("Baseline: ", style="bold")
    files_text.append(f"{baseline_name}\n")
    files_text.append("Current:  ", style="bold")
    files_text.append(f"{current_name}")
    console.print(Panel(files_text, border_style="dim"))

    # Summary Panel
    st = Table.grid(padding=(0, 2))
    st.add_column(style="bold")
    st.add_column()

    st.add_row("Hosts Added:", Text(str(diff.summary.hosts_added), style="green" if diff.summary.hosts_added > 0 else "dim"))
    st.add_row("Hosts Removed:", Text(str(diff.summary.hosts_removed), style="red" if diff.summary.hosts_removed > 0 else "dim"))
    st.add_row("Hosts Changed:", Text(str(diff.summary.hosts_changed), style="yellow" if diff.summary.hosts_changed > 0 else "dim"))
    st.add_row("Ports Opened:", Text(str(diff.summary.ports_opened), style="bold green" if diff.summary.ports_opened > 0 else "dim"))
    st.add_row("Ports Closed:", Text(str(diff.summary.ports_closed), style="bold red" if diff.summary.ports_closed > 0 else "dim"))
    st.add_row("Services Changed:", Text(str(diff.summary.services_changed), style="bold yellow" if diff.summary.services_changed > 0 else "dim"))
    st.add_row("OS Changes:", Text(str(diff.summary.os_changed), style="cyan" if diff.summary.os_changed > 0 else "dim"))
    st.add_row("Scripts Changed:", Text(str(diff.summary.scripts_changed), style="magenta" if diff.summary.scripts_changed > 0 else "dim"))

    console.print(Panel(st, title="[bold]Diff Summary[/bold]", border_style="blue"))

    # Host Changes Table
    if diff.host_changes:
        ht = Table(title="Host Changes", header_style="bold cyan", border_style="dim")
        ht.add_column("HOST")
        ht.add_column("CHANGE TYPE")
        ht.add_column("OLD STATUS")
        ht.add_column("NEW STATUS")

        for h in diff.host_changes:
            c_style = "green" if h.change_type == "added" else ("red" if h.change_type == "removed" else "yellow")
            ht.add_row(Text(h.address), Text(h.change_type, style=c_style), Text(h.old_status or "-"), Text(h.new_status or "-"))

        console.print(ht)

    # Opened Ports Table
    opened_ports = [p for p in diff.port_changes if p.change_type == "opened"]
    if opened_ports:
        pt = Table(title="New Open Ports", header_style="bold green", border_style="green")
        pt.add_column("HOST", style="cyan")
        pt.add_column("PORT", style="bold green")
        pt.add_column("STATE", style="bold green")

        for p in opened_ports:
            pt.add_row(Text(p.host), Text(f"{p.port}/{p.protocol}"), Text("OPEN"))

        console.print(pt)

    # Closed Ports Table
    closed_ports = [p for p in diff.port_changes if p.change_type == "closed"]
    if closed_ports:
        ct = Table(title="Closed Ports", header_style="bold red", border_style="red")
        ct.add_column("HOST", style="cyan")
        ct.add_column("PORT", style="bold red")
        ct.add_column("STATE", style="bold red")

        for p in closed_ports:
            ct.add_row(Text(p.host), Text(f"{p.port}/{p.protocol}"), Text("CLOSED"))

        console.print(ct)

    # Service Changes Panel
    if diff.service_changes:
        stext = Text()
        for s in diff.service_changes:
            stext.append(f"{s.host} : {s.port}/{s.protocol}\n", style="bold cyan")
            stext.append("  Old: ")
            stext.append(f"{s.old_service or 'none'}\n", style="dim red")
            stext.append("  New: ")
            stext.append(f"{s.new_service or 'none'}\n\n", style="bold green")

        console.print(Panel(stext, title="[bold]Service Changes[/bold]", border_style="yellow"))

    # OS Changes Panel
    if diff.os_changes:
        otext = Text()
        for o in diff.os_changes:
            otext.append(f"{o.host}\n", style="bold cyan")
            otext.append("  Old: ")
            otext.append(f"{o.old_os or 'none'}\n", style="dim")
            otext.append("  New: ")
            otext.append(f"{o.new_os or 'none'}\n\n", style="bold green")

        console.print(Panel(otext, title="[bold]OS Fingerprint Changes[/bold]", border_style="magenta"))

    # Script Changes Panel
    if diff.script_changes:
        scrtext = Text()
        for s in diff.script_changes:
            p_info = f" ({s.port}/{s.protocol})" if s.port else ""
            scrtext.append(f"{s.host}{p_info} - {s.script_id} [{s.change_type}]\n", style="bold yellow")
            if s.old_output:
                scrtext.append("  Old: ")
                scrtext.append(f"{s.old_output.strip()}\n", style="dim red")
            if s.new_output:
                scrtext.append("  New: ")
                scrtext.append(f"{s.new_output.strip()}\n", style="bold green")
            scrtext.append("\n")

        console.print(Panel(scrtext, title="[bold]NSE Script Output Changes[/bold]", border_style="yellow"))

    return buf.getvalue()
