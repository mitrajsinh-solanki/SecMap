"""
SecMap Built-in Scan Profiles
Defines standard pre-packaged scan profiles.
Phase 14 implementation.
"""

from secmap_core.profiles.models import ScanProfile

BUILTIN_PROFILES: dict[str, ScanProfile] = {
    "quick": ScanProfile(
        name="quick",
        description="Common ports (22, 80, 443) for fast discovery",
        nmap_args=("-p", "22,80,443"),
        source="built-in",
    ),
    "service": ScanProfile(
        name="service",
        description="Service and version detection on top 1000 ports",
        nmap_args=("-sV", "-p", "1-1000"),
        source="built-in",
    ),
    "web": ScanProfile(
        name="web",
        description="Common web service ports (80, 443, 8080, 8443) with HTTP title script",
        nmap_args=("-sV", "-p", "80,443,8080,8443", "--script=http-title"),
        source="built-in",
    ),
    "full": ScanProfile(
        name="full",
        description="Comprehensive port (1-65535), service version, and OS detection assessment",
        nmap_args=("-sV", "-O", "-p", "1-65535"),
        source="built-in",
    ),
}
