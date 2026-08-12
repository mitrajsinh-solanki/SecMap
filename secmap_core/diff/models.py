"""
SecMap Scan Difference Models
Defines immutable domain objects representing changes between baseline and current ScanReport models.
Phase 15 implementation.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class HostChange:
    """Represents a host addition, removal, or status change."""

    address: str
    change_type: str  # "added", "removed", "status_changed"
    old_status: str | None = None
    new_status: str | None = None


@dataclass(frozen=True)
class PortChange:
    """Represents a port state opening, closure, addition, or removal."""

    host: str
    port: int
    protocol: str
    change_type: str  # "opened", "closed", "state_changed", "added", "removed"
    old_state: str | None = None
    new_state: str | None = None


@dataclass(frozen=True)
class ServiceChange:
    """Represents a service name, product, or version modification."""

    host: str
    port: int
    protocol: str
    old_service: str | None = None
    new_service: str | None = None


@dataclass(frozen=True)
class OSChange:
    """Represents an OS fingerprint modification."""

    host: str
    old_os: str | None = None
    new_os: str | None = None


@dataclass(frozen=True)
class ScriptChange:
    """Represents an NSE script addition, removal, or output update."""

    host: str
    script_id: str
    change_type: str  # "added", "removed", "output_changed"
    port: int | None = None
    protocol: str | None = None
    old_output: str | None = None
    new_output: str | None = None


@dataclass(frozen=True)
class DiffSummary:
    """Summary statistics of observed scan report differences."""

    hosts_added: int = 0
    hosts_removed: int = 0
    hosts_changed: int = 0
    ports_opened: int = 0
    ports_closed: int = 0
    ports_changed: int = 0
    services_changed: int = 0
    os_changed: int = 0
    scripts_changed: int = 0


@dataclass(frozen=True)
class ScanDiff:
    """Complete immutable scan report comparison result."""

    summary: DiffSummary
    host_changes: tuple[HostChange, ...] = field(default_factory=tuple)
    port_changes: tuple[PortChange, ...] = field(default_factory=tuple)
    service_changes: tuple[ServiceChange, ...] = field(default_factory=tuple)
    os_changes: tuple[OSChange, ...] = field(default_factory=tuple)
    script_changes: tuple[ScriptChange, ...] = field(default_factory=tuple)
