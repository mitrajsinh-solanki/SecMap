"""
SecMap Data Models (Nmap Parser Stream Models)
Structured representations of raw Nmap XML scan results.
Phase 4, 5 & 7 implementation.
"""

from dataclasses import dataclass, field


@dataclass
class OSClassNode:
    """Represents an OS class element in Nmap XML."""

    type: str | None = None
    vendor: str | None = None
    osfamily: str | None = None
    osgen: str | None = None
    accuracy: int | None = None
    cpe: list[str] = field(default_factory=list)


@dataclass
class OSMatchNode:
    """Represents an OS match guess in Nmap XML."""

    name: str
    accuracy: int | None = None
    line: str | None = None
    osclasses: list[OSClassNode] = field(default_factory=list)
    cpes: list[str] = field(default_factory=list)


@dataclass
class ScriptNode:
    """Represents an NSE script output node in Nmap XML."""

    id: str
    output: str | None = None


@dataclass
class Service:
    """Represents service fingerprinting details for a network port."""

    name: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None


@dataclass
class Port:
    """Represents a scanned network port."""

    portid: int
    protocol: str
    state: str | None = None
    reason: str | None = None
    service: Service | None = None
    scripts: list[ScriptNode] = field(default_factory=list)


@dataclass
class Host:
    """Represents a scanned target host."""

    address: str | None = None
    address_type: str | None = "ipv4"
    status: str | None = None
    hostname: str | None = None
    ports: list[Port] = field(default_factory=list)
    os_matches: list[OSMatchNode] = field(default_factory=list)
    scripts: list[ScriptNode] = field(default_factory=list)


@dataclass
class ScanResult:
    """Represents the overall parsed results of an Nmap scan run."""

    hosts: list[Host] = field(default_factory=list)
    scanner: str | None = None
    scanner_version: str | None = None
    args: str | None = None
