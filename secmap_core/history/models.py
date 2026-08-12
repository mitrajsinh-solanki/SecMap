"""
SecMap Scan History Models
Defines immutable domain models for scan snapshot metadata.
Phase 16 implementation.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ScanSnapshot:
    """Represents a persisted scan snapshot metadata entry."""

    snapshot_id: str
    created_at: str
    targets: tuple[str, ...] = field(default_factory=tuple)
    profile: str | None = None
    scan_arguments: tuple[str, ...] = field(default_factory=tuple)
    report_path: str | None = None
    host_count: int = 0
    open_port_count: int = 0
