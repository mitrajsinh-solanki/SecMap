"""
SecMap Scan Difference Engine
Compares baseline and current ScanReport domain objects and returns structured, deterministic ScanDiff results.
Phase 15 implementation.
"""

from secmap_core.diff.models import (
    DiffSummary,
    HostChange,
    OSChange,
    PortChange,
    ScanDiff,
    ScriptChange,
    ServiceChange,
)
from secmap_core.normalize.results import HostResult, ScanReport, ServiceResult


def _service_description(svc: ServiceResult | None) -> str:
    """Format service object into a readable identification string."""
    if not svc:
        return "none"
    parts = [svc.name or "unknown"]
    if svc.product:
        parts.append(svc.product)
    if svc.version:
        parts.append(svc.version)
    return " ".join(parts)


class ScanDiffEngine:
    """Side-effect-free engine comparing two ScanReport domain models."""

    def compare(self, baseline: ScanReport, current: ScanReport) -> ScanDiff:
        """
        Compare baseline and current ScanReport domain models.

        Args:
            baseline (ScanReport): Historical baseline scan report.
            current (ScanReport): Current scan report.

        Returns:
            ScanDiff: Immutable comparison result.
        """
        host_changes: list[HostChange] = []
        port_changes: list[PortChange] = []
        service_changes: list[ServiceChange] = []
        os_changes: list[OSChange] = []
        script_changes: list[ScriptChange] = []

        base_hosts = {h.address: h for h in (baseline.hosts if baseline else []) if h.address}
        curr_hosts = {h.address: h for h in (current.hosts if current else []) if h.address}

        all_host_addrs = sorted(set(base_hosts.keys()) | set(curr_hosts.keys()))

        for addr in all_host_addrs:
            b_host = base_hosts.get(addr)
            c_host = curr_hosts.get(addr)

            if b_host and not c_host:
                host_changes.append(HostChange(address=addr, change_type="removed", old_status=b_host.status))
                continue

            if c_host and not b_host:
                host_changes.append(HostChange(address=addr, change_type="added", new_status=c_host.status))
                continue

            # Both hosts exist
            if b_host.status != c_host.status:
                host_changes.append(
                    HostChange(
                        address=addr,
                        change_type="status_changed",
                        old_status=b_host.status,
                        new_status=c_host.status,
                    )
                )

            # Compare ports
            self._compare_ports(addr, b_host, c_host, port_changes, service_changes, script_changes)

            # Compare OS
            self._compare_os(addr, b_host, c_host, os_changes)

            # Compare host-level scripts
            self._compare_host_scripts(addr, b_host, c_host, script_changes)

        # Sort changes deterministically
        host_changes.sort(key=lambda x: x.address)
        port_changes.sort(key=lambda x: (x.host, x.port, x.protocol))
        service_changes.sort(key=lambda x: (x.host, x.port, x.protocol))
        os_changes.sort(key=lambda x: x.host)
        script_changes.sort(key=lambda x: (x.host, x.port or 0, x.protocol or "", x.script_id))

        summary = DiffSummary(
            hosts_added=sum(1 for h in host_changes if h.change_type == "added"),
            hosts_removed=sum(1 for h in host_changes if h.change_type == "removed"),
            hosts_changed=sum(1 for h in host_changes if h.change_type == "status_changed"),
            ports_opened=sum(1 for p in port_changes if p.change_type == "opened"),
            ports_closed=sum(1 for p in port_changes if p.change_type == "closed"),
            ports_changed=sum(1 for p in port_changes if p.change_type == "state_changed"),
            services_changed=len(service_changes),
            os_changed=len(os_changes),
            scripts_changed=len(script_changes),
        )

        return ScanDiff(
            summary=summary,
            host_changes=tuple(host_changes),
            port_changes=tuple(port_changes),
            service_changes=tuple(service_changes),
            os_changes=tuple(os_changes),
            script_changes=tuple(script_changes),
        )

    def _compare_ports(
        self,
        host_addr: str,
        b_host: HostResult,
        c_host: HostResult,
        port_changes: list[PortChange],
        service_changes: list[ServiceChange],
        script_changes: list[ScriptChange],
    ) -> None:
        """Compare port and service states for a common host."""
        b_ports = {(p.port, p.protocol): p for p in b_host.ports}
        c_ports = {(p.port, p.protocol): p for p in c_host.ports}

        all_port_keys = sorted(set(b_ports.keys()) | set(c_ports.keys()), key=lambda k: (k[0], k[1]))

        for key in all_port_keys:
            port_num, proto = key
            b_port = b_ports.get(key)
            c_port = c_ports.get(key)

            if b_port and not c_port:
                ctype = "closed" if b_port.state == "open" else "removed"
                port_changes.append(
                    PortChange(
                        host=host_addr,
                        port=port_num,
                        protocol=proto,
                        change_type=ctype,
                        old_state=b_port.state,
                    )
                )
                continue

            if c_port and not b_port:
                ctype = "opened" if c_port.state == "open" else "added"
                port_changes.append(
                    PortChange(
                        host=host_addr,
                        port=port_num,
                        protocol=proto,
                        change_type=ctype,
                        new_state=c_port.state,
                    )
                )
                continue

            # Both ports exist
            if b_port.state != c_port.state:
                if c_port.state == "open":
                    ctype = "opened"
                elif b_port.state == "open":
                    ctype = "closed"
                else:
                    ctype = "state_changed"

                port_changes.append(
                    PortChange(
                        host=host_addr,
                        port=port_num,
                        protocol=proto,
                        change_type=ctype,
                        old_state=b_port.state,
                        new_state=c_port.state,
                    )
                )

            # Compare services
            old_desc = _service_description(b_port.service)
            new_desc = _service_description(c_port.service)
            if old_desc != new_desc:
                service_changes.append(
                    ServiceChange(
                        host=host_addr,
                        port=port_num,
                        protocol=proto,
                        old_service=old_desc if b_port.service else None,
                        new_service=new_desc if c_port.service else None,
                    )
                )

            # Compare port scripts
            self._compare_port_scripts(host_addr, port_num, proto, b_port, c_port, script_changes)

    def _compare_os(self, host_addr: str, b_host: HostResult, c_host: HostResult, os_changes: list[OSChange]) -> None:
        """Compare OS detection best matches for a common host."""
        b_os_match = b_host.os.best_match if (b_host.os and b_host.os.best_match) else None
        c_os_match = c_host.os.best_match if (c_host.os and c_host.os.best_match) else None

        b_name = b_os_match.name if b_os_match else None
        c_name = c_os_match.name if c_os_match else None

        if b_name != c_name:
            if b_os_match and b_os_match.accuracy is not None:
                b_name = f"{b_name} ({b_os_match.accuracy}%)"
            if c_os_match and c_os_match.accuracy is not None:
                c_name = f"{c_name} ({c_os_match.accuracy}%)"

            os_changes.append(OSChange(host=host_addr, old_os=b_name, new_os=c_name))

    def _compare_port_scripts(
        self,
        host_addr: str,
        port_num: int,
        proto: str,
        b_port,
        c_port,
        script_changes: list[ScriptChange],
    ) -> None:
        """Compare port-level NSE scripts."""
        b_scrs = {s.script_id: s for s in (b_port.scripts if b_port else [])}
        c_scrs = {s.script_id: s for s in (c_port.scripts if c_port else [])}

        all_ids = sorted(set(b_scrs.keys()) | set(c_scrs.keys()))

        for sid in all_ids:
            bs = b_scrs.get(sid)
            cs = c_scrs.get(sid)

            if bs and not cs:
                script_changes.append(
                    ScriptChange(
                        host=host_addr,
                        port=port_num,
                        protocol=proto,
                        script_id=sid,
                        change_type="removed",
                        old_output=bs.output,
                    )
                )
            elif cs and not bs:
                script_changes.append(
                    ScriptChange(
                        host=host_addr,
                        port=port_num,
                        protocol=proto,
                        script_id=sid,
                        change_type="added",
                        new_output=cs.output,
                    )
                )
            elif bs and cs and bs.output != cs.output:
                script_changes.append(
                    ScriptChange(
                        host=host_addr,
                        port=port_num,
                        protocol=proto,
                        script_id=sid,
                        change_type="output_changed",
                        old_output=bs.output,
                        new_output=cs.output,
                    )
                )

    def _compare_host_scripts(
        self,
        host_addr: str,
        b_host: HostResult,
        c_host: HostResult,
        script_changes: list[ScriptChange],
    ) -> None:
        """Compare host-level NSE scripts."""
        b_scrs = {s.script_id: s for s in b_host.scripts}
        c_scrs = {s.script_id: s for s in c_host.scripts}

        all_ids = sorted(set(b_scrs.keys()) | set(c_scrs.keys()))

        for sid in all_ids:
            bs = b_scrs.get(sid)
            cs = c_scrs.get(sid)

            if bs and not cs:
                script_changes.append(
                    ScriptChange(
                        host=host_addr,
                        script_id=sid,
                        change_type="removed",
                        old_output=bs.output,
                    )
                )
            elif cs and not bs:
                script_changes.append(
                    ScriptChange(
                        host=host_addr,
                        script_id=sid,
                        change_type="added",
                        new_output=cs.output,
                    )
                )
            elif bs and cs and bs.output != cs.output:
                script_changes.append(
                    ScriptChange(
                        host=host_addr,
                        script_id=sid,
                        change_type="output_changed",
                        old_output=bs.output,
                        new_output=cs.output,
                    )
                )
