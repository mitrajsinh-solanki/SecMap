"""
SecMap Scan Profile Models
Defines immutable ScanProfile representation.
Phase 14 implementation.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ScanProfile:
    """Immutable representation of a reusable SecMap scan profile."""

    name: str
    description: str
    nmap_args: tuple[str, ...] = field(default_factory=tuple)
    source: str = "built-in"
