"""
SecMap Profiles Package
Reusable scan profile definitions, TOML config loader, and profile resolver engine.
"""

from .builtins import BUILTIN_PROFILES
from .loader import ProfileConfigError, get_config_path, load_custom_profiles, validate_profile_name
from .models import ScanProfile
from .resolver import get_all_profiles, get_profile, resolve_profile

__all__ = [
    "ScanProfile",
    "BUILTIN_PROFILES",
    "ProfileConfigError",
    "get_config_path",
    "load_custom_profiles",
    "validate_profile_name",
    "get_all_profiles",
    "get_profile",
    "resolve_profile",
]
