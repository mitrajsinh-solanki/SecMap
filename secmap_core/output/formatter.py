"""
SecMap Output Formatter
Renders normalized ScanReport models into clean, predictable, tabular terminal output.
Phase 6, 7, 8 & 9 implementation.
"""

from secmap_core.normalize.results import (
    HostResult,
    OSResult,
    PortResult,
    ScanReport,
    ScriptResult,
    ServiceResult,
    get_open_ports,
    get_services,
)


class SecMapFormatter:
    """Formats ScanReport data models into human-readable text output."""

    def __init__(self, use_color: bool = False):
        self.use_color = use_color

    def _format_version(self, service: ServiceResult | None) -> str:
        """Combine product, version, and extra_info intelligently."""
        if not service:
            return "-"

        parts = []
        if service.product:
            parts.append(service.product)
        if service.version:
            parts.append(service.version)

        ver_str = " ".join(parts) if parts else ""

        if service.extra_info:
            if ver_str:
                ver_str += f" ({service.extra_info})"
            else:
                ver_str = service.extra_info

        return ver_str if ver_str else "-"

    def _format_ports_table(self, ports: list[PortResult]) -> tuple[list[str], int]:
        """Format sorted ports list into aligned tabular rows."""
        sorted_ports = sorted(ports, key=lambda p: p.port)

        col_port = ["PORT"]
        col_state = ["STATE"]
        col_service = ["SERVICE"]
        col_version = ["VERSION"]

        items_data = []
        for p in sorted_ports:
            port_proto = f"{p.port}/{p.protocol}"
            state = p.state or "unknown"
            svc_name = p.service.name if (p.service and p.service.name) else "-"
            version_str = self._format_version(p.service)

            col_port.append(port_proto)
            col_state.append(state)
            col_service.append(svc_name)
            col_version.append(version_str)

            items_data.append((port_proto, state, svc_name, version_str))

        w_port = max(len(s) for s in col_port)
        w_state = max(len(s) for s in col_state)
        w_service = max(len(s) for s in col_service)

        rows = []
        header = f"{'PORT':<{w_port}}   {'STATE':<{w_state}}   {'SERVICE':<{w_service}}   VERSION"
        rows.append(header)

        for port_proto, state, svc_name, version_str in items_data:
            line = f"{port_proto:<{w_port}}   {state:<{w_state}}   {svc_name:<{w_service}}   {version_str}"
            rows.append(line)

        return rows, len(sorted_ports)

    def _format_os_section(self, os_info: OSResult | None) -> list[str]:
        """Format the OS detection section."""
        if not os_info or not os_info.matches:
            return []

        lines = ["\nOS Detection", "------------"]
        best = os_info.best_match

        acc_str = f" ({best.accuracy}%)" if best.accuracy is not None else ""
        lines.append(f"Best match: {best.name}{acc_str}")

        if best.cpes:
            lines.append(f"CPE: {best.cpes[0]}")

        if best.osclasses:
            cls = best.osclasses[0]
            class_parts = []
            if cls.vendor:
                class_parts.append(f"Vendor: {cls.vendor}")
            if cls.family:
                class_parts.append(f"Family: {cls.family}")
            if cls.generation:
                class_parts.append(f"Gen: {cls.generation}")
            if cls.type:
                class_parts.append(f"Type: {cls.type}")
            if class_parts:
                lines.append(f"OS Class: {', '.join(class_parts)}")

        other_matches = os_info.matches[1:]
        if other_matches:
            lines.append("\nOther matches:")
            for m in other_matches:
                m_acc = f" ({m.accuracy}%)" if m.accuracy is not None else ""
                lines.append(f"- {m.name}{m_acc}")

        return lines

    def _format_single_script(self, script: ScriptResult, base_indent: str = "  ") -> list[str]:
        """Format an individual script result with consistent indentation."""
        lines = []
        script_id = script.script_id.strip() if script.script_id else "Unknown script"
        lines.append(f"{base_indent}{script_id}:")

        sub_indent = base_indent + "  "

        if script.output is None or not script.output.strip():
            lines.append(f"{sub_indent}No output")
            return lines

        out_lines = script.output.strip().splitlines()
        for oline in out_lines:
            lines.append(f"{sub_indent}{oline}")

        return lines

    def _format_script_section(self, host: HostResult) -> list[str]:
        """Format port-level and host-level NSE script blocks."""
        lines = []

        ports_with_scripts = [p for p in sorted(host.ports, key=lambda x: x.port) if p.scripts]

        if ports_with_scripts:
            lines.append("\nNSE Scripts")
            lines.append("-----------")

            for idx, p in enumerate(ports_with_scripts):
                if idx > 0:
                    lines.append("")
                port_proto = f"{p.port}/{p.protocol}"
                lines.append(f"{port_proto}")
                for s in p.scripts:
                    lines.extend(self._format_single_script(s, base_indent="  "))

        if host.scripts:
            lines.append("\nHost Scripts")
            lines.append("------------")
            for s in host.scripts:
                lines.extend(self._format_single_script(s, base_indent="  "))

        return lines

    def _format_host(self, host: HostResult) -> str:
        """Format a single host result block."""
        lines = []

        target_str = host.address or "Unknown"
        if host.hostname:
            target_str += f" ({host.hostname})"

        lines.append(f"Target: {target_str}")
        lines.append(f"Status: {host.status or 'unknown'}")

        if host.status == "down":
            lines.append("\nNo port information available.")
            return "\n".join(lines)

        if not host.ports:
            lines.append("\nNo open ports detected.")

            lines.extend(self._format_os_section(host.os))
            lines.extend(self._format_script_section(host))

            return "\n".join(lines)

        table_rows, port_count = self._format_ports_table(host.ports)
        lines.append("")
        lines.extend(table_rows)
        lines.append("")

        if port_count == 1:
            lines.append("1 port shown")
        else:
            lines.append(f"{port_count} ports shown")

        lines.extend(self._format_os_section(host.os))
        lines.extend(self._format_script_section(host))

        return "\n".join(lines)

    def _format_multi_host_summary(self, report: ScanReport) -> list[str]:
        """Format top-level summary and overview table for multi-host scans."""
        lines = []

        if report.targets:
            lines.append("Targets:")
            for t in report.targets:
                lines.append(f"  {t}")
            lines.append("")

        lines.append("Scan Summary")
        lines.append("------------")
        lines.append(f"Hosts discovered: {report.discovered_hosts_count}")
        lines.append(f"Hosts up: {report.hosts_up_count}")
        lines.append(f"Hosts down: {report.hosts_down_count}")
        lines.append(f"Open ports: {report.total_open_ports_count}")
        lines.append(f"Service instances: {report.total_service_instances_count}")
        lines.append("")

        lines.append("Hosts Overview")
        lines.append("--------------")

        col_host = ["HOST"]
        col_status = ["STATUS"]
        col_ports = ["OPEN PORTS"]
        col_svc = ["SERVICES"]

        host_rows = []
        for h in report.hosts:
            h_str = h.address or "Unknown"
            if h.hostname:
                h_str += f" ({h.hostname})"

            status_str = h.status or "unknown"

            if h.status == "down":
                p_count_str = "-"
                svc_count_str = "-"
            else:
                p_count_str = str(len(get_open_ports(h)))
                svc_count_str = str(len(get_services(h)))

            col_host.append(h_str)
            col_status.append(status_str)
            col_ports.append(p_count_str)
            col_svc.append(svc_count_str)

            host_rows.append((h_str, status_str, p_count_str, svc_count_str))

        w_host = max(len(s) for s in col_host)
        w_status = max(len(s) for s in col_status)
        w_ports = max(len(s) for s in col_ports)

        header = f"{'HOST':<{w_host}}   {'STATUS':<{w_status}}   {'OPEN PORTS':<{w_ports}}   SERVICES"
        lines.append(header)

        for h_str, status_str, p_count_str, svc_count_str in host_rows:
            row = f"{h_str:<{w_host}}   {status_str:<{w_status}}   {p_count_str:<{w_ports}}   {svc_count_str}"
            lines.append(row)

        lines.append("")
        lines.append("Host Details")
        lines.append("------------")
        return lines

    def render(self, report: ScanReport) -> str:
        """
        Render a ScanReport into a formatted string.

        Args:
            report (ScanReport): SecMap backend-independent scan report.

        Returns:
            str: Formatted terminal text output.
        """
        if not report or not report.hosts:
            return "SecMap Scan Report\n\nNo targets scanned or scan report is empty."

        output_blocks = ["SecMap Scan Report\n"]

        if len(report.hosts) > 1:
            output_blocks.append("\n".join(self._format_multi_host_summary(report)))

        host_blocks = [self._format_host(host) for host in report.hosts]
        output_blocks.append("\n\n".join(host_blocks))

        return "\n".join(output_blocks)
