"""
SecMap CLI Argument Parsing & Validation Layer
Phase 2, Phase 9, Phase 10, Phase 11, Phase 14, Phase 15 & Phase 16 implementation.
"""

from dataclasses import dataclass, field
import sys
from secmap_core.targets import validate_target


class CLIError(ValueError):
    """Raised when command-line arguments are invalid or missing."""

    pass


@dataclass
class ScanArguments:
    """Structured representation of validated CLI options and target destinations."""

    targets: list[str] = field(default_factory=list)
    ports: str | None = None
    service_version: bool = False
    os_detection: bool = False
    aggressive: bool = False
    scripts: list[str] = field(default_factory=list)
    no_ping: bool = False
    scan_types: list[str] = field(default_factory=list)
    timing: int | None = None
    debug: bool = False
    check_nmap: bool = False
    show_version: bool = False
    show_help: bool = False
    show_profiles: bool = False
    selected_profile: str | None = None
    profile_info_name: str | None = None
    is_diff_command: bool = False
    baseline_path: str | None = None
    current_path: str | None = None
    is_history_command: bool = False
    history_action: str | None = None
    history_args: list[str] = field(default_factory=list)
    save_history: bool = False
    show_full_report: bool = False
    output_mode: str = "normal"
    output_file: str | None = None
    plain: bool = False
    nmap_args: list[str] = field(default_factory=list)

    @property
    def version_requested(self) -> bool:
        return self.show_version

    @property
    def help_requested(self) -> bool:
        return self.show_help

    @property
    def check_nmap_requested(self) -> bool:
        return self.check_nmap


def parse_args(argv: list[str]) -> ScanArguments:
    """
    Parse a list of raw CLI arguments into a validated ScanArguments object.

    Args:
        argv (list[str]): Command line arguments list (excluding process binary name).

    Returns:
        ScanArguments: Structured and validated scan arguments.

    Raises:
        CLIError: If arguments contain malformed syntax or missing required options.
    """
    args = ScanArguments()
    if not argv:
        return args

    # Check for history subcommand
    if argv[0].strip().lower() == "history":
        args.is_history_command = True
        return _parse_history_args(argv[1:], args)

    # Check for diff subcommand
    if argv[0].strip().lower() == "diff":
        args.is_diff_command = True
        return _parse_diff_args(argv[1:], args)

    i = 0
    raw_targets = []

    while i < len(argv):
        arg = argv[i]

        if arg in ("-h", "--help"):
            args.show_help = True
            i += 1
            continue

        if arg == "--version":
            args.show_version = True
            i += 1
            continue

        if arg == "--check-nmap":
            args.check_nmap = True
            i += 1
            continue

        if arg == "--debug":
            args.debug = True
            i += 1
            continue

        if arg in ("--plain", "--no-color"):
            args.plain = True
            i += 1
            continue

        if arg == "--save":
            args.save_history = True
            i += 1
            continue

        if arg == "--profiles":
            args.show_profiles = True
            i += 1
            continue

        if arg == "--profile":
            if i + 1 >= len(argv):
                raise CLIError("SecMap Error: --profile option requires a profile name.")
            i += 1
            args.selected_profile = argv[i]
            i += 1
            continue
        elif arg.startswith("--profile="):
            args.selected_profile = arg.split("=", 1)[1]
            i += 1
            continue

        if arg == "--profile-info":
            if i + 1 >= len(argv):
                raise CLIError("SecMap Error: --profile-info option requires a profile name.")
            i += 1
            args.profile_info_name = argv[i]
            i += 1
            continue
        elif arg.startswith("--profile-info="):
            args.profile_info_name = arg.split("=", 1)[1]
            i += 1
            continue

        if arg == "--output":
            if i + 1 >= len(argv):
                raise CLIError("SecMap Error: --output option requires a format specification (normal, json, csv).")
            i += 1
            mode_val = argv[i].strip().lower()
            if mode_val not in ("normal", "json", "csv"):
                raise CLIError(f"SecMap Error: Unsupported output format '{argv[i]}'. Supported formats: normal, json, csv.")
            args.output_mode = mode_val
            i += 1
            continue
        elif arg.startswith("--output="):
            mode_val = arg.split("=", 1)[1].strip().lower()
            if mode_val not in ("normal", "json", "csv"):
                raise CLIError(f"SecMap Error: Unsupported output format '{mode_val}'. Supported formats: normal, json, csv.")
            args.output_mode = mode_val
            i += 1
            continue

        if arg in ("-o", "--output-file"):
            if i + 1 >= len(argv):
                raise CLIError("SecMap Error: -o / --output-file option requires a filepath.")
            i += 1
            args.output_file = argv[i]
            i += 1
            continue
        elif arg.startswith("--output-file="):
            args.output_file = arg.split("=", 1)[1]
            i += 1
            continue

        if arg == "-sV":
            args.service_version = True
            args.nmap_args.append("-sV")
            i += 1
            continue

        if arg == "-O":
            args.os_detection = True
            args.nmap_args.append("-O")
            i += 1
            continue

        if arg == "-A":
            args.aggressive = True
            args.nmap_args.append("-A")
            i += 1
            continue

        if arg == "-Pn":
            args.no_ping = True
            args.nmap_args.append("-Pn")
            i += 1
            continue

        if arg in ("-sS", "-sT", "-sU"):
            if arg not in args.scan_types:
                args.scan_types.append(arg)
            args.nmap_args.append(arg)
            i += 1
            continue

        if arg.startswith("-T"):
            val_str = arg[2:]
            if not val_str and i + 1 < len(argv):
                i += 1
                val_str = argv[i]

            try:
                t_val = int(val_str)
                if not (0 <= t_val <= 5):
                    raise ValueError()
                args.timing = t_val
                args.nmap_args.append(f"-T{t_val}")
            except ValueError:
                raise CLIError(f"SecMap Error: Invalid timing value -T{val_str}. Must be between 0 and 5.")

            i += 1
            continue

        if arg == "-p":
            if i + 1 >= len(argv):
                raise CLIError("SecMap Error: -p option requires a port specification.")
            i += 1
            args.ports = argv[i]
            args.nmap_args.extend(["-p", argv[i]])
            i += 1
            continue
        elif arg.startswith("-p"):
            args.ports = arg[2:]
            args.nmap_args.extend(["-p", arg[2:]])
            i += 1
            continue

        if arg == "--script":
            if i + 1 >= len(argv):
                raise CLIError("SecMap Error: --script option requires a script name.")
            i += 1
            args.scripts.append(argv[i])
            args.nmap_args.append(f"--script={argv[i]}")
            i += 1
            continue
        elif arg.startswith("--script="):
            scr_val = arg.split("=", 1)[1]
            args.scripts.append(scr_val)
            args.nmap_args.append(f"--script={scr_val}")
            i += 1
            continue

        if arg.startswith("-"):
            raise CLIError(f"SecMap Error: Unrecognized flag or option '{arg}'.")

        raw_targets.append(arg)
        i += 1

    if args.show_help or args.show_version or args.check_nmap or args.show_profiles or args.profile_info_name:
        return args

    if not raw_targets:
        raise CLIError("SecMap Error: No scan target specified.")

    validated_targets = []
    for tgt in raw_targets:
        is_valid, _ = validate_target(tgt)
        if not is_valid:
            raise CLIError(f"SecMap Error: Invalid target destination '{tgt}'.")
        validated_targets.append(tgt)

    args.targets = validated_targets
    return args


def _parse_diff_args(diff_argv: list[str], args: ScanArguments) -> ScanArguments:
    """Parse CLI arguments specifically for the diff subcommand."""
    i = 0
    paths = []

    while i < len(diff_argv):
        arg = diff_argv[i]

        if arg in ("-h", "--help"):
            args.show_help = True
            i += 1
            continue

        if arg == "--debug":
            args.debug = True
            i += 1
            continue

        if arg in ("--plain", "--no-color"):
            args.plain = True
            i += 1
            continue

        if arg == "--output":
            if i + 1 >= len(diff_argv):
                raise CLIError("SecMap Error: --output option requires a format specification (normal, json, csv).")
            i += 1
            mode_val = diff_argv[i].strip().lower()
            if mode_val not in ("normal", "json", "csv"):
                raise CLIError(f"SecMap Error: Unsupported output format '{diff_argv[i]}'. Supported formats: normal, json, csv.")
            args.output_mode = mode_val
            i += 1
            continue
        elif arg.startswith("--output="):
            mode_val = arg.split("=", 1)[1].strip().lower()
            if mode_val not in ("normal", "json", "csv"):
                raise CLIError(f"SecMap Error: Unsupported output format '{mode_val}'. Supported formats: normal, json, csv.")
            args.output_mode = mode_val
            i += 1
            continue

        if arg in ("-o", "--output-file"):
            if i + 1 >= len(diff_argv):
                raise CLIError("SecMap Error: -o / --output-file option requires a filepath.")
            i += 1
            args.output_file = diff_argv[i]
            i += 1
            continue
        elif arg.startswith("--output-file="):
            args.output_file = arg.split("=", 1)[1]
            i += 1
            continue

        if arg.startswith("-"):
            raise CLIError(f"SecMap Error: Unrecognized flag or option '{arg}' for diff command.")

        paths.append(arg)
        i += 1

    if args.show_help:
        return args

    if len(paths) < 2:
        raise CLIError("SecMap Error: diff command requires BASELINE and CURRENT report file paths.\nUsage: secmap diff BASELINE CURRENT [OPTIONS]")

    args.baseline_path = paths[0]
    args.current_path = paths[1]
    return args


def _parse_history_args(hist_argv: list[str], args: ScanArguments) -> ScanArguments:
    """Parse CLI arguments specifically for the history subcommand."""
    if not hist_argv:
        args.history_action = "list"
        return args

    action = hist_argv[0].strip().lower()
    if action in ("-h", "--help"):
        args.show_help = True
        return args

    valid_actions = ("list", "show", "latest", "delete", "compare", "compare-latest")
    if action not in valid_actions:
        raise CLIError(f"SecMap Error: Unknown history action '{action}'. Supported actions: list, show, latest, delete, compare, compare-latest.")

    args.history_action = action
    i = 1

    while i < len(hist_argv):
        arg = hist_argv[i]

        if arg in ("-h", "--help"):
            args.show_help = True
            i += 1
            continue

        if arg == "--debug":
            args.debug = True
            i += 1
            continue

        if arg in ("--plain", "--no-color"):
            args.plain = True
            i += 1
            continue

        if arg == "--full":
            args.show_full_report = True
            i += 1
            continue

        if arg == "--output":
            if i + 1 >= len(hist_argv):
                raise CLIError("SecMap Error: --output option requires a format specification (normal, json, csv).")
            i += 1
            mode_val = hist_argv[i].strip().lower()
            if mode_val not in ("normal", "json", "csv"):
                raise CLIError(f"SecMap Error: Unsupported output format '{hist_argv[i]}'. Supported formats: normal, json, csv.")
            args.output_mode = mode_val
            i += 1
            continue
        elif arg.startswith("--output="):
            mode_val = arg.split("=", 1)[1].strip().lower()
            if mode_val not in ("normal", "json", "csv"):
                raise CLIError(f"SecMap Error: Unsupported output format '{mode_val}'. Supported formats: normal, json, csv.")
            args.output_mode = mode_val
            i += 1
            continue

        if arg in ("-o", "--output-file"):
            if i + 1 >= len(hist_argv):
                raise CLIError("SecMap Error: -o / --output-file option requires a filepath.")
            i += 1
            args.output_file = hist_argv[i]
            i += 1
            continue
        elif arg.startswith("--output-file="):
            args.output_file = arg.split("=", 1)[1]
            i += 1
            continue

        if arg.startswith("-"):
            raise CLIError(f"SecMap Error: Unrecognized flag or option '{arg}' for history command.")

        args.history_args.append(arg)
        i += 1

    return args


def build_nmap_args(scan_args: ScanArguments) -> list[str]:
    """
    Construct a safe array of command arguments for Nmap execution.

    Args:
        scan_args (ScanArguments): Validated CLI options.

    Returns:
        list[str]: Discrete array of string arguments suitable for subprocess.run(shell=False).
    """
    return list(scan_args.nmap_args)
