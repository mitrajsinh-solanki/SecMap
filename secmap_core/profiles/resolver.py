"""
SecMap Profile Resolver Module
Resolves scan profile lookups, merges profile parameters with CLI flags, and enforces precedence & conflict rules.
Phase 14 implementation.
"""

import pathlib
from secmap_core.cli import CLIError, ScanArguments
from secmap_core.profiles.builtins import BUILTIN_PROFILES
from secmap_core.profiles.loader import ProfileConfigError, load_custom_profiles, validate_profile_name
from secmap_core.profiles.models import ScanProfile


def get_all_profiles(custom_path: pathlib.Path | None = None) -> dict[str, ScanProfile]:
    """
    Retrieve all available scan profiles (built-in + custom user profiles).

    Returns:
        dict[str, ScanProfile]: Combined dictionary of scan profiles.
    """
    profiles = dict(BUILTIN_PROFILES)
    try:
        customs = load_custom_profiles(custom_path)
        profiles.update(customs)
    except ProfileConfigError as e:
        raise CLIError(str(e))
    return profiles


def get_profile(name: str, custom_path: pathlib.Path | None = None) -> ScanProfile:
    """
    Look up a scan profile by name.

    Args:
        name (str): Profile identifier name.

    Returns:
        ScanProfile: Resolved profile instance.

    Raises:
        CLIError: If profile name is unknown or invalid.
    """
    validate_profile_name(name)
    all_profiles = get_all_profiles(custom_path)

    if name not in all_profiles:
        raise CLIError(f"SecMap Error: Unknown scan profile '{name}'. Use --profiles to list available profiles.")

    return all_profiles[name]


def resolve_profile(profile: ScanProfile, scan_args: ScanArguments) -> ScanArguments:
    """
    Merge profile arguments with explicit CLI scan arguments.
    Explicit CLI flags take precedence over profile default arguments.

    Args:
        profile (ScanProfile): Selected scan profile.
        scan_args (ScanArguments): Explicit CLI scan arguments.

    Returns:
        ScanArguments: Updated scan arguments containing merged options.

    Raises:
        CLIError: If conflicting scan types are detected.
    """
    # Build list of effective Nmap arguments starting from profile defaults
    effective_nmap_args = list(profile.nmap_args)

    # Detect conflicts in explicit CLI scan types vs profile scan types
    cli_has_st = "-sT" in scan_args.scan_types or "-sT" in scan_args.nmap_args
    cli_has_ss = "-sS" in scan_args.scan_types or "-sS" in scan_args.nmap_args
    prof_has_st = "-sT" in effective_nmap_args
    prof_has_ss = "-sS" in effective_nmap_args

    if (cli_has_st and prof_has_ss) or (cli_has_ss and prof_has_st) or (cli_has_st and cli_has_ss):
        raise CLIError("SecMap Error: Conflicting scan types: -sS and -sT cannot be specified simultaneously.")

    # Override ports if explicit CLI ports provided
    if scan_args.ports:
        # Remove any -p options from profile defaults
        new_prof_args = []
        skip_next = False
        for arg in effective_nmap_args:
            if skip_next:
                skip_next = False
                continue
            if arg == "-p":
                skip_next = True
                continue
            if arg.startswith("-p"):
                continue
            new_prof_args.append(arg)
        effective_nmap_args = new_prof_args

    # Append remaining explicit CLI Nmap arguments without duplicating flags
    for cli_arg in scan_args.nmap_args:
        if cli_arg not in effective_nmap_args:
            effective_nmap_args.append(cli_arg)

    # Update flags on scan_args
    if "-sV" in effective_nmap_args:
        scan_args.service_version = True
    if "-O" in effective_nmap_args:
        scan_args.os_detection = True
    if "-A" in effective_nmap_args:
        scan_args.aggressive = True
    if "-Pn" in effective_nmap_args:
        scan_args.no_ping = True

    scan_args.nmap_args = effective_nmap_args
    return scan_args
