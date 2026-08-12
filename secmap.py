#!/usr/bin/env python3
"""
SecMap - Custom CLI Network Security Scanner powered by Nmap.
Main Application Entry Point (Phase 16 Scan History & Baseline Management Engine).
"""

import json
import shutil
import subprocess
import sys

from secmap_core.cli import CLIError, ScanArguments, parse_args
from secmap_core.config import SECMAP_NAME, SECMAP_VERSION
from secmap_core.diff import ScanDiffEngine, render_diff
from secmap_core.execution import NmapExecutionError, NmapExecutor, NmapResult
from secmap_core.history import HistoryManager, render_history_list, render_snapshot_info
from secmap_core.normalize import (
    ResultNormalizationError,
    ScanReport,
    load_scan_report,
    normalize_scan_result,
)
from secmap_core.output import get_output_renderer
from secmap_core.parser import NmapXMLParseError
from secmap_core.profiles import get_all_profiles, get_profile, resolve_profile
from secmap_core.security import check_scan_privileges, is_elevated

# Ensure UTF-8 stdout encoding on Windows terminals to prevent UnicodeEncodeError
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def check_nmap() -> tuple[bool, str]:
    """
    Check whether Nmap is available in system PATH and retrieve driver status.

    Returns:
        tuple[bool, str]: (is_available, status_message)
    """
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        return False, "SecMap Error: Nmap was not found in PATH."

    try:
        process = subprocess.Popen(
            ["nmap", "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
        )
        stdout, stderr = process.communicate()

        if process.returncode == 0 and stdout:
            first_line = stdout.splitlines()[0]
            return True, f"Nmap: available ({first_line})"
        else:
            return True, "Nmap: available"
    except Exception as e:
        return False, f"SecMap Error: Failed to execute Nmap driver: {str(e)}"


def print_help() -> None:
    """Print clean, custom SecMap help output."""
    help_text = f"""{SECMAP_NAME} {SECMAP_VERSION}

Custom CLI network security scanner.

Usage:
  secmap [OPTIONS] <TARGET>
  secmap diff BASELINE.json CURRENT.json [OPTIONS]
  secmap history <ACTION> [OPTIONS]

Commands:
  diff                   Compare two historical SecMap JSON scan reports
  history                Manage scan history snapshots (list, show, latest, delete, compare, compare-latest)

Scan Options:
  -p PORTS               Specify target ports to scan (e.g., -p 80,443 or -p 1-1000)
  -sV                    Enable service and version detection
  -O                     Enable operating system (OS) detection
  -A                     Enable aggressive scan (OS & version detection, script scanning, traceroute)
  -Pn                    Skip host discovery (treat all target hosts as online)
  -sS                    Perform TCP SYN stealth scan
  -sT                    Perform TCP Connect scan
  -sU                    Perform UDP scan
  -T <0-5>               Set timing template (0=slowest to 5=fastest)
  --script SCRIPT        Execute Nmap Script Engine (NSE) scripts (e.g., --script http-title)

SecMap Options:
  -h, --help             Show this help message
  --version              Show SecMap version
  --save                 Persist scan result into history storage
  --profiles             List available scan profiles
  --profile NAME         Use a pre-configured scan profile (quick, service, web, full)
  --profile-info NAME    Display detailed information about a specific scan profile
  --debug                Display debug details, command array, and rendered output

Output Options:
  --output MODE          Set output mode: normal (default), json, csv
  -o, --output-file FILE Write scan output to specified file path
  --plain, --no-color    Disable Rich UI styling and output plain text

Examples:
  secmap -sV -p 80,443 127.0.0.1
  secmap --profile web 127.0.0.1 --save
  secmap -A 127.0.0.1 --output json -o report.json
  secmap diff baseline.json current.json
  secmap history list
  secmap history compare-latest
  secmap history show 20260810-083015-a1b2c3 --full
"""
    print(help_text)


def print_history_help() -> None:
    """Print help output specifically for the history subcommand."""
    help_text = f"""{SECMAP_NAME} {SECMAP_VERSION} - Scan History Management

Usage:
  secmap history list [OPTIONS]
  secmap history show SNAPSHOT_ID [--full] [OPTIONS]
  secmap history latest [--full] [OPTIONS]
  secmap history delete SNAPSHOT_ID
  secmap history compare BASELINE_ID CURRENT_ID [OPTIONS]
  secmap history compare-latest [OPTIONS]

Actions:
  list                 List all saved scan snapshots
  show                 Display snapshot metadata (use --full for complete scan report)
  latest               Display newest snapshot metadata (use --full for complete report)
  delete               Delete a specific snapshot by ID
  compare              Compare two saved snapshots by ID
  compare-latest       Compare the newest snapshot against the previous snapshot

Options:
  -h, --help           Show this help message
  --full               Render complete stored ScanReport
  --plain, --no-color  Disable Rich UI styling and output plain text
  --output MODE        Set output mode: normal (default), json, csv
  -o, --output-file F  Write history output to specified file path F
"""
    print(help_text)


def display_profiles(output_mode: str = "normal", plain: bool = False) -> None:
    """Display all available scan profiles in requested output format."""
    profiles = get_all_profiles()

    if output_mode == "json":
        data = {
            "profiles": [
                {
                    "name": p.name,
                    "description": p.description,
                    "arguments": list(p.nmap_args),
                    "source": p.source,
                }
                for p in profiles.values()
            ]
        }
        print(json.dumps(data, indent=2))
        return

    if plain:
        print("Available scan profiles:\n")
        for p in profiles.values():
            print(f"  {p.name:<12} ({p.source})")
            print(f"    {p.description}")
            print(f"    Args: {' '.join(p.nmap_args)}\n")
        return

    from rich.console import Console
    from rich.table import Table

    console = Console(highlight=False)
    table = Table(title="Available SecMap Scan Profiles", header_style="bold cyan", border_style="dim")
    table.add_column("PROFILE", style="bold yellow")
    table.add_column("DESCRIPTION")
    table.add_column("DEFAULT ARGS", style="cyan")
    table.add_column("SOURCE", style="dim")

    for p in profiles.values():
        table.add_row(p.name, p.description, " ".join(p.nmap_args), p.source)

    console.print(table)


def display_profile_info(name: str, output_mode: str = "normal", plain: bool = False) -> None:
    """Display detailed information about a specific scan profile."""
    prof = get_profile(name)

    if output_mode == "json":
        data = {
            "profile": {
                "name": prof.name,
                "description": prof.description,
                "arguments": list(prof.nmap_args),
                "source": prof.source,
            }
        }
        print(json.dumps(data, indent=2))
        return

    if plain:
        print(f"Profile:     {prof.name}")
        print(f"Source:      {prof.source}")
        print(f"Description: {prof.description}")
        print("Arguments:")
        for arg in prof.nmap_args:
            print(f"  {arg}")
        return

    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text

    console = Console(highlight=False)
    info_text = Text()
    info_text.append("Profile:     ", style="bold")
    info_text.append(f"{prof.name}\n")
    info_text.append("Source:      ", style="bold")
    info_text.append(f"{prof.source}\n", style="dim")
    info_text.append("Description: ", style="bold")
    info_text.append(f"{prof.description}\n\n")
    info_text.append("Arguments:\n", style="bold yellow")
    for arg in prof.nmap_args:
        info_text.append(f"  {arg}\n", style="cyan")

    console.print(Panel(info_text, title=f"[bold]Scan Profile Details ({prof.name})[/bold]", border_style="cyan"))


def handle_history_command(scan_args: ScanArguments) -> None:
    """Handle all history subcommand actions cleanly."""
    mgr = HistoryManager()
    action = scan_args.history_action or "list"

    if action == "list":
        snapshots = mgr.list_history()
        out = render_history_list(snapshots, output_mode=scan_args.output_mode, plain=scan_args.plain)
        _output_result(out, scan_args.output_file)
        return

    if action == "show":
        if not scan_args.history_args:
            raise CLIError("SecMap Error: history show action requires a SNAPSHOT_ID.\nUsage: secmap history show SNAPSHOT_ID [--full]")

        snapshot_id = scan_args.history_args[0]
        meta, report = mgr.get_snapshot(snapshot_id)

        if scan_args.show_full_report:
            renderer = get_output_renderer(scan_args.output_mode, plain=scan_args.plain)
            out = renderer.render(report)
        else:
            out = render_snapshot_info(meta, output_mode=scan_args.output_mode, plain=scan_args.plain)

        _output_result(out, scan_args.output_file)
        return

    if action == "latest":
        meta, report = mgr.get_latest()
        if scan_args.show_full_report:
            renderer = get_output_renderer(scan_args.output_mode, plain=scan_args.plain)
            out = renderer.render(report)
        else:
            out = render_snapshot_info(meta, output_mode=scan_args.output_mode, plain=scan_args.plain)

        _output_result(out, scan_args.output_file)
        return

    if action == "delete":
        if not scan_args.history_args:
            raise CLIError("SecMap Error: history delete action requires a SNAPSHOT_ID.\nUsage: secmap history delete SNAPSHOT_ID")

        snapshot_id = scan_args.history_args[0]
        mgr.delete_snapshot(snapshot_id)
        print(f"SecMap: History snapshot '{snapshot_id}' deleted successfully.")
        return

    if action == "compare":
        if len(scan_args.history_args) < 2:
            raise CLIError(
                "SecMap Error: history compare action requires BASELINE_ID and CURRENT_ID.\nUsage: secmap history compare BASELINE_ID CURRENT_ID"
            )

        base_id = scan_args.history_args[0]
        curr_id = scan_args.history_args[1]
        diff_res = mgr.compare_snapshots(base_id, curr_id)

        out = render_diff(
            diff_res,
            output_mode=scan_args.output_mode,
            plain=scan_args.plain,
            baseline_name=base_id,
            current_name=curr_id,
        )
        _output_result(out, scan_args.output_file)
        return

    if action == "compare-latest":
        base_meta, curr_meta, diff_res = mgr.compare_latest()
        out = render_diff(
            diff_res,
            output_mode=scan_args.output_mode,
            plain=scan_args.plain,
            baseline_name=base_meta.snapshot_id,
            current_name=curr_meta.snapshot_id,
        )
        _output_result(out, scan_args.output_file)
        return


def _output_result(content: str, file_path: str | None) -> None:
    """Helper to write or print output content."""
    if file_path:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
    print(content)


def main() -> None:
    """Main application entry point."""
    if len(sys.argv) == 1:
        print_help()
        sys.exit(0)

    try:
        scan_args = parse_args(sys.argv[1:])
    except CLIError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)

    if scan_args.version_requested:
        print(f"{SECMAP_NAME} {SECMAP_VERSION}")
        sys.exit(0)

    if scan_args.help_requested:
        if scan_args.is_history_command:
            print_history_help()
        elif scan_args.is_diff_command:
            print("SecMap Diff Help: secmap diff BASELINE CURRENT [OPTIONS]")
        else:
            print_help()
        sys.exit(0)

    # Handle secmap history subcommand
    if scan_args.is_history_command:
        try:
            handle_history_command(scan_args)
            sys.exit(0)
        except (CLIError, OSError) as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)

    # Handle secmap diff subcommand
    if scan_args.is_diff_command:
        try:
            baseline_report = load_scan_report(scan_args.baseline_path)
            current_report = load_scan_report(scan_args.current_path)
            diff_result = ScanDiffEngine().compare(baseline_report, current_report)

            rendered_diff = render_diff(
                diff_result,
                output_mode=scan_args.output_mode,
                plain=scan_args.plain,
                baseline_name=scan_args.baseline_path,
                current_name=scan_args.current_path,
            )

            if scan_args.output_file:
                with open(scan_args.output_file, "w", encoding="utf-8") as f:
                    f.write(rendered_diff)

            print(rendered_diff)
            sys.exit(0)
        except (CLIError, OSError) as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)

    if scan_args.check_nmap_requested:
        available, msg = check_nmap()
        if available:
            print(msg)
            sys.exit(0)
        else:
            print(msg, file=sys.stderr)
            sys.exit(1)

    if scan_args.show_profiles:
        try:
            display_profiles(output_mode=scan_args.output_mode, plain=scan_args.plain)
            sys.exit(0)
        except CLIError as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)

    if scan_args.profile_info_name:
        try:
            display_profile_info(scan_args.profile_info_name, output_mode=scan_args.output_mode, plain=scan_args.plain)
            sys.exit(0)
        except CLIError as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)

    # Resolve profile parameters if selected
    if scan_args.selected_profile:
        try:
            prof = get_profile(scan_args.selected_profile)
            scan_args = resolve_profile(prof, scan_args)
        except CLIError as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)

    if not scan_args.targets:
        print("SecMap Error: No scan target specified.", file=sys.stderr)
        sys.exit(1)

    # Perform advisory privilege check and route warnings to stderr
    req_raw, req_reason, warnings = check_scan_privileges(scan_args)
    for warn in warnings:
        print(warn, file=sys.stderr)

    executor = NmapExecutor()

    try:
        result, parsed_xml = executor.execute_xml(scan_args)
        scan_report = normalize_scan_result(parsed_xml, targets=scan_args.targets)
    except (NmapExecutionError, NmapXMLParseError, ResultNormalizationError) as e:
        err_msg = str(e)
        if "cancelled by user" in err_msg.lower():
            print(f"\n{err_msg}", file=sys.stderr)
            sys.exit(130)
        elif any(term in err_msg.lower() for term in ("privileges", "root", "raw socket", "permission denied", "dnet")):
            print(err_msg, file=sys.stderr)
            print("\nSuggestions:", file=sys.stderr)
            print("  • Re-run SecMap with elevated privileges (e.g., sudo or Administrator terminal)", file=sys.stderr)
            print("  • Or use -sT for unprivileged TCP Connect scanning", file=sys.stderr)
        else:
            print(err_msg, file=sys.stderr)
        sys.exit(1)

    # Save to history if --save flag was specified
    if scan_args.save_history:
        try:
            mgr = HistoryManager()
            snapshot = mgr.save_scan(
                scan_report,
                profile=scan_args.selected_profile,
                scan_arguments=scan_args.nmap_args,
            )
            print(f"[SecMap] Scan saved to history storage (Snapshot ID: {snapshot.snapshot_id})", file=sys.stderr)
        except Exception as e:
            print(f"SecMap Warning: Failed to save scan snapshot to history: {str(e)}", file=sys.stderr)

    try:
        renderer = get_output_renderer(scan_args.output_mode, plain=scan_args.plain)
        rendered_output = renderer.render(scan_report)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)

    if scan_args.output_file:
        try:
            with open(scan_args.output_file, "w", encoding="utf-8") as f:
                f.write(rendered_output)
        except OSError as e:
            print(f"SecMap Error: Failed to write output file '{scan_args.output_file}': {str(e)}", file=sys.stderr)
            sys.exit(1)

    print(rendered_output)
    sys.exit(result.returncode)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nSecMap Error: Scan cancelled by user.", file=sys.stderr)
        sys.exit(130)
