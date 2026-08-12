"""
SecMap Internal Data Model & Result Normalizer
Decouples SecMap result representation from raw Nmap XML streams for backend independence.
Phase 5, Phase 7 & Phase 9 implementation.
"""

from dataclasses import dataclass, field
from secmap_core.parser import ScanResult


class ResultNormalizationError(ValueError):
    """Raised when scan result data is malformed or cannot be normalized."""

    pass


@dataclass
class AddressResult:
    """Represents a network IP address."""

    address: str
    address_type: str = "ipv4"


@dataclass
class ServiceResult:
    """Represents normalized service fingerprinting details."""

    name: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None


@dataclass
class ScriptResult:
    """Represents an NSE script output result."""

    script_id: str
    output: str | None = None


@dataclass
class PortResult:
    """Represents a normalized scanned network port."""

    port: int
    protocol: str
    state: str | None = None
    reason: str | None = None
    service: ServiceResult | None = None
    scripts: list[ScriptResult] = field(default_factory=list)


@dataclass
class OSClass:
    """Represents an OS classification node."""

    type: str | None = None
    vendor: str | None = None
    family: str | None = None
    generation: str | None = None
    accuracy: int | None = None
    cpes: list[str] = field(default_factory=list)


@dataclass
class OSMatch:
    """Represents an OS detection match guess."""

    name: str
    accuracy: int | None = None
    osclasses: list[OSClass] = field(default_factory=list)
    cpes: list[str] = field(default_factory=list)


@dataclass
class OSResult:
    """Represents OS fingerprint detection results."""

    matches: list[OSMatch] = field(default_factory=list)

    @property
    def best_match(self) -> OSMatch | None:
        """Returns the highest accuracy OS match guess if available."""
        return self.matches[0] if self.matches else None


@dataclass
class HostResult:
    """Represents a normalized scan target host."""

    address: str | None = None
    address_type: str | None = "ipv4"
    status: str | None = None
    hostname: str | None = None
    ports: list[PortResult] = field(default_factory=list)
    os: OSResult | None = None
    scripts: list[ScriptResult] = field(default_factory=list)


@dataclass
class ScanReport:
    """Represents SecMap's top-level backend-independent scan report."""

    targets: list[str] = field(default_factory=list)
    hosts: list[HostResult] = field(default_factory=list)
    scanner: str | None = None
    scanner_version: str | None = None
    arguments: str | None = None

    @property
    def discovered_hosts_count(self) -> int:
        """Return total number of discovered hosts in scan report."""
        return len(self.hosts)

    @property
    def hosts_up_count(self) -> int:
        """Return count of hosts with status 'up'."""
        return len([h for h in self.hosts if h.status == "up"])

    @property
    def hosts_down_count(self) -> int:
        """Return count of hosts with status 'down'."""
        return len([h for h in self.hosts if h.status == "down"])

    @property
    def total_open_ports_count(self) -> int:
        """Return total count of open ports across all reachable hosts."""
        return sum(len(get_open_ports(h)) for h in self.hosts if h.status == "up")

    @property
    def total_service_instances_count(self) -> int:
        """Return total count of service instances identified across all hosts."""
        return sum(len(get_services(h)) for h in self.hosts if h.status == "up")

    @property
    def unique_services_count(self) -> int:
        """Return count of distinct service names identified across all hosts."""
        svc_names = {s.name for h in self.hosts if h.status == "up" for s in get_services(h) if s.name}
        return len(svc_names)


def normalize_scan_result(parsed_result: ScanResult, targets: list[str] | None = None) -> ScanReport:
    """
    Convert a parser ScanResult into SecMap's internal backend-independent ScanReport.

    Args:
        parsed_result (ScanResult): Nmap XML parser output data.
        targets (list[str] | None): Original requested target list.

    Returns:
        ScanReport: Normalized SecMap scan report model.

    Raises:
        ResultNormalizationError: If port values or required data structures are malformed.
    """
    if parsed_result is None:
        raise ResultNormalizationError("SecMap Normalization Error: Parsed result cannot be None.")

    normalized_hosts: list[HostResult] = []

    for host in parsed_result.hosts:
        status = host.status.lower() if host.status else None
        address = host.address
        address_type = host.address_type.lower() if host.address_type else "ipv4"

        os_result = None
        if host.os_matches:
            matches: list[OSMatch] = []
            for m in host.os_matches:
                classes = [
                    OSClass(
                        type=c.type,
                        vendor=c.vendor,
                        family=c.osfamily,
                        generation=c.osgen,
                        accuracy=c.accuracy,
                        cpes=list(c.cpe),
                    )
                    for c in m.osclasses
                ]
                match_name = m.name if m.name else "Unknown OS fingerprint"
                matches.append(
                    OSMatch(
                        name=match_name,
                        accuracy=m.accuracy,
                        osclasses=classes,
                        cpes=list(m.cpes),
                    )
                )

            matches.sort(key=lambda x: (x.accuracy is not None, x.accuracy or 0), reverse=True)
            os_result = OSResult(matches=matches)

        host_scripts = [ScriptResult(script_id=s.id, output=s.output) for s in host.scripts]

        normalized_ports: list[PortResult] = []
        for port in host.ports:
            try:
                port_num = int(port.portid)
            except (TypeError, ValueError):
                raise ResultNormalizationError(f"SecMap Normalization Error: Invalid port number '{port.portid}'.")

            if port_num <= 0 or port_num > 65535:
                raise ResultNormalizationError(f"SecMap Normalization Error: Port number '{port_num}' out of range.")

            protocol = port.protocol.lower() if port.protocol else "tcp"
            state = port.state.lower() if port.state else None

            service_res = None
            if port.service:
                svc_name = port.service.name.lower() if port.service.name else None
                service_res = ServiceResult(
                    name=svc_name,
                    product=port.service.product,
                    version=port.service.version,
                    extra_info=port.service.extrainfo,
                )

            port_scripts = [ScriptResult(script_id=s.id, output=s.output) for s in port.scripts]

            normalized_ports.append(
                PortResult(
                    port=port_num,
                    protocol=protocol,
                    state=state,
                    reason=port.reason,
                    service=service_res,
                    scripts=port_scripts,
                )
            )

        normalized_hosts.append(
            HostResult(
                address=address,
                address_type=address_type,
                status=status,
                hostname=host.hostname,
                ports=normalized_ports,
                os=os_result,
                scripts=host_scripts,
            )
        )

    report_targets = list(targets) if targets else []

    return ScanReport(
        targets=report_targets,
        hosts=normalized_hosts,
        scanner=parsed_result.scanner,
        scanner_version=parsed_result.scanner_version,
        arguments=parsed_result.args,
    )


def get_up_hosts(report: ScanReport) -> list[HostResult]:
    """Retrieve all hosts in the scan report with status 'up'."""
    return [h for h in report.hosts if h.status == "up"]


def get_open_ports(host: HostResult) -> list[PortResult]:
    """Retrieve all ports on a host with state 'open'."""
    return [p for p in host.ports if p.state == "open"]


def get_services(host: HostResult) -> list[ServiceResult]:
    """Retrieve all defined service results on a host."""
    return [p.service for p in host.ports if p.service is not None]
