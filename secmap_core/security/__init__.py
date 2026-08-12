"""
SecMap Security Package
Privilege detection and raw socket safety checks.
"""

from .privileges import PrivilegeStatus, check_scan_privileges, is_elevated

__all__ = ["PrivilegeStatus", "is_elevated", "check_scan_privileges"]
