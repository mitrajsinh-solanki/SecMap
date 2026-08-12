"""
SecMap Security & Privilege Detection Module
Detects operating system privilege levels and evaluates raw socket scan requirements.
Phase 12 implementation.
"""

from dataclasses import dataclass
import os
import sys


@dataclass
class PrivilegeStatus:
    """Dataclass storing detected platform privilege status."""

    elevated: bool | None
    platform: str
    reason: str


def is_elevated() -> tuple[bool | None, str]:
    """
    Check if the current process is running with elevated privileges (root / Administrator).

    Returns:
        tuple[bool | None, str]: (is_elevated, platform_name)
    """
    platform_name = sys.platform.lower()

    if platform_name.startswith("win"):
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            return is_admin, "windows"
        except Exception:
            return None, "windows"
    elif platform_name.startswith(("linux", "darwin", "freebsd")):
        try:
            return os.geteuid() == 0, platform_name
        except AttributeError:
            return None, platform_name

    return None, platform_name


def check_scan_privileges(scan_args) -> tuple[bool, str, list[str]]:
    """
    Evaluate scan flags against current process privileges.

    Args:
        scan_args (ScanArguments): CLI scan parameters.

    Returns:
        tuple[bool, str, list[str]]: (requires_elevation, reason, warnings_list)
    """
    elevated, platform_name = is_elevated()

    requires_raw_sockets = False
    reasons = []
    warnings = []

    # Check for flags requiring raw sockets / elevated privileges
    if scan_args.os_detection or "-O" in scan_args.nmap_args:
        requires_raw_sockets = True
        reasons.append("OS detection (-O) requires raw socket packet access")

    if "-sS" in scan_args.scan_types or "-sS" in scan_args.nmap_args:
        requires_raw_sockets = True
        reasons.append("TCP SYN scan (-sS) requires raw socket packet access")

    if "-sU" in scan_args.scan_types or "-sU" in scan_args.nmap_args:
        requires_raw_sockets = True
        reasons.append("UDP scan (-sU) requires raw socket packet access")

    reason_text = "; ".join(reasons) if reasons else "Scan type does not explicitly require raw sockets."

    if requires_raw_sockets and elevated is False:
        warnings.append(
            f"SecMap Warning: Requested scan type ({reason_text}) may require administrator/root privileges on this platform.\n"
            f"Consider running SecMap from an elevated terminal (e.g. sudo or Administrator) or use -sT for unprivileged TCP Connect scanning."
        )

    return requires_raw_sockets, reason_text, warnings
