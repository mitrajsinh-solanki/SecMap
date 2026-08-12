"""
SecMap Profile Configuration Loader Module
Loads custom user profiles from platform TOML configuration files safely without dynamic execution.
Phase 14 implementation.
"""

import os
import pathlib
import re
import sys
from secmap_core.profiles.models import ScanProfile

# Python 3.11+ standard library tomllib or fallback
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

VALID_PROFILE_NAME_REGEX = re.compile(r"^[A-Za-z0-9_-]+$")


class ProfileConfigError(ValueError):
    """Raised when profile configuration format or data is invalid."""

    pass


def get_config_path() -> pathlib.Path | None:
    """
    Determine cross-platform user configuration path for SecMap.

    Returns:
        pathlib.Path | None: Resolved config file path.
    """
    home = pathlib.Path.home()

    if sys.platform.startswith("win"):
        appdata = os.environ.get("APPDATA")
        if appdata:
            p = pathlib.Path(appdata) / "secmap" / "config.toml"
            if p.exists():
                return p

    # Standard XDG / home config locations
    xdg_config = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config:
        p = pathlib.Path(xdg_config) / "secmap" / "config.toml"
        if p.exists():
            return p

    p_dot = home / ".secmap" / "config.toml"
    if p_dot.exists():
        return p_dot

    p_conf = home / ".config" / "secmap" / "config.toml"
    if p_conf.exists():
        return p_conf

    return None


def validate_profile_name(name: str) -> None:
    """
    Validate that profile name matches identifier rules and contains no path traversal.

    Args:
        name (str): Profile identifier name.

    Raises:
        ProfileConfigError: If name contains path traversal or invalid characters.
    """
    if not name or not isinstance(name, str):
        raise ProfileConfigError("SecMap Error: Profile name must be a non-empty string.")

    if ".." in name or "/" in name or "\\" in name:
        raise ProfileConfigError(f"SecMap Error: Invalid profile name '{name}'. Path traversal characters are forbidden.")

    if not VALID_PROFILE_NAME_REGEX.match(name):
        raise ProfileConfigError(
            f"SecMap Error: Invalid profile name '{name}'. Names must contain only letters, numbers, underscores, and hyphens."
        )


def load_custom_profiles(custom_path: pathlib.Path | None = None) -> dict[str, ScanProfile]:
    """
    Load custom scan profiles from a TOML configuration file.

    Args:
        custom_path (pathlib.Path | None): Optional specific path to config file.

    Returns:
        dict[str, ScanProfile]: Dictionary of validated custom profiles.

    Raises:
        ProfileConfigError: If TOML syntax or profile data is invalid.
    """
    config_file = custom_path or get_config_path()
    if not config_file or not config_file.exists():
        return {}

    if tomllib is None:
        # If tomllib/tomli unavailable, fail safely without crash
        return {}

    try:
        with open(config_file, "rb") as f:
            data = tomllib.load(f)
    except Exception as e:
        raise ProfileConfigError(f"SecMap Error: Failed to parse configuration file '{config_file}': {str(e)}")

    if not isinstance(data, dict):
        raise ProfileConfigError(f"SecMap Error: Configuration root in '{config_file}' must be a TOML table.")

    profiles_table = data.get("profiles", {})
    if not isinstance(profiles_table, dict):
        raise ProfileConfigError(f"SecMap Error: '[profiles]' entry in '{config_file}' must be a TOML table.")

    custom_profiles = {}
    for name, p_data in profiles_table.items():
        validate_profile_name(name)

        if not isinstance(p_data, dict):
            raise ProfileConfigError(f"SecMap Error: Profile '[profiles.{name}]' must be a table.")

        desc = p_data.get("description", f"Custom profile '{name}'")
        if not isinstance(desc, str):
            raise ProfileConfigError(f"SecMap Error: Profile '{name}' description must be a string.")

        raw_args = p_data.get("args", [])
        if not isinstance(raw_args, (list, tuple)):
            raise ProfileConfigError(f"SecMap Error: Profile '{name}' 'args' must be a list of string flags.")

        validated_args = []
        for arg in raw_args:
            if not isinstance(arg, str) or not arg.strip():
                raise ProfileConfigError(f"SecMap Error: Profile '{name}' argument element must be a non-empty string.")
            validated_args.append(arg.strip())

        custom_profiles[name] = ScanProfile(
            name=name,
            description=desc,
            nmap_args=tuple(validated_args),
            source=f"custom ({config_file})",
        )

    return custom_profiles
