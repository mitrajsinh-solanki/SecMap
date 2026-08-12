"""
SecMap Rich Terminal UI Renderer
Renders ScanReport domain models into styled terminal UI elements (Panels, Tables, Colored Text) using Rich.
Phase 11 implementation.
"""

import io
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

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


class RichRenderer:
    """Renders ScanReport data models into Rich terminal UI presentations."""

    def __init__(self, color_system: str | None = "auto"):
        self.color_system = color_system

    def _get_console(self) -> tuple[Console, io.StringIO]:
        """Create a recording Console capturing string output."""
        buf = io.StringIO()
        console = Console(
            file=buf,
            force_terminal=True if self.color_system != "none" else False,
            color_system=self.color_system,
            width=100,
            highlight=False,
            legacy_windows=False,
        )
        return console, buf

    def _format_state_text(self, state: str | None) -> Text:
        """Format port state with explicit text and visual style."""
        st = state.upper() if state else "UNKNOWN"
        if st == "OPEN":
            return Text("OPEN", style="bold green")
        elif st == "CLOSED":
            return Text("CLOSED", style="dim red")
        elif st == "FILTERED":
            return Text("FILTERED", style="bold yellow")
        else:
            return Text(st, style="dim")

    def _format_status_text(self, status: str | None) -> Text:
        """Format host status with explicit text and visual style."""
        st = status.upper() if status else "UNKNOWN"
        if st == "UP":
            return Text("UP", style="bold green")
        elif st == "DOWN":
            return Text("DOWN", style="bold red")
        else:
            return Text(st, style="dim")

    def _format_version_text(self, service: ServiceResult | None) -> Text:
        """Combine product, version, and extra_info into a safe Text object."""
        if not service:
            return Text("-", style="dim")

        parts = []
        if service.product:
            parts.append(service.product)
        if service.version:
            parts.append(service.version)

        ver_str = " ".join(parts) if parts else ""
        if service.extra_info:
            ver_str = f"{ver_str} ({service.extra_info})" if ver_str else service.extra_info

        return Text(ver_str) if ver_str else Text("-", style="dim")

    def _build_header_panel(self) -> Panel:
        """Build SecMap banner panel."""
        header_text = Text("SecMap Network Security Scanner", style="bold cyan", justify="center")
        return Panel(header_text, border_style="cyan", title="[bold]SecMap[/bold]", title_align="center")

    def _build_summary_panel(self, report: ScanReport) -> Panel:
        """Build summary metrics panel for multi-host scans."""
        summary_table = Table.grid(padding=(0, 2))
        summary_table.add_column(style="bold")
        summary_table.add_column()

        summary_table.add_row("Hosts Discovered:", str(report.discovered_hosts_count))
        summary_table.add_row("Hosts UP:", Text(str(report.hosts_up_count), style="green"))
        summary_table.add_row("Hosts DOWN:", Text(str(report.hosts_down_count), style="red" if report.hosts_down_count > 0 else "dim"))
        summary_table.add_row("Total Open Ports:", Text(str(report.total_open_ports_count), style="bold yellow"))
        summary_table.add_row("Service Instances:", str(report.total_service_instances_count))

        return Panel(summary_table, title="[bold]Scan Summary[/bold]", border_style="blue")

    def _build_hosts_overview_table(self, report: ScanReport) -> Table:
        """Build overview table for multi-host scans."""
        table = Table(title="Hosts Overview", header_style="bold magenta", border_style="dim")
        table.add_column("HOST", style="cyan")
        table.add_column("STATUS")
        table.add_column("OPEN PORTS", justify="right")
        table.add_column("SERVICES", justify="right")

        for h in report.hosts:
            h_addr = h.address or "Unknown"
            if h.hostname:
                h_addr += f" ({h.hostname})"

            host_text = Text(h_addr)
            status_text = self._format_status_text(h.status)

            if h.status == "down":
                ports_text = Text("-", style="dim")
                svc_text = Text("-", style="dim")
            else:
                p_count = len(get_open_ports(h))
                ports_text = Text(str(p_count), style="bold green" if p_count > 0 else "dim")
                svc_text = Text(str(len(get_services(h))))

            table.add_row(host_text, status_text, ports_text, svc_text)

        return table

    def _build_ports_table(self, ports: list[PortResult]) -> Table:
        """Build port scan details table."""
        table = Table(header_style="bold blue", border_style="dim", box=None)
        table.add_column("PORT", style="bold cyan")
        table.add_column("STATE")
        table.add_column("SERVICE", style="cyan")
        table.add_column("VERSION")

        sorted_ports = sorted(ports, key=lambda p: p.port)

        for p in sorted_ports:
            port_text = Text(f"{p.port}/{p.protocol}")
            state_text = self._format_state_text(p.state)

            svc_name = p.service.name if (p.service and p.service.name) else "-"
            svc_text = Text(svc_name) if svc_name != "-" else Text("-", style="dim")
            ver_text = self._format_version_text(p.service)

            table.add_row(port_text, state_text, svc_text, ver_text)

        return table

    def _render_os_panel(self, console: Console, os_info: OSResult | None) -> None:
        """Render OS detection panel safely."""
        if not os_info or not os_info.matches:
            return

        best = os_info.best_match
        os_text = Text()

        acc_str = f" ({best.accuracy}%)" if best.accuracy is not None else ""
        os_text.append("Best match: ", style="bold")
        os_text.append(f"{best.name}{acc_str}", style="green")

        if best.cpes:
            os_text.append(f"\nCPE: {best.cpes[0]}", style="dim")

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
                os_text.append(f"\nOS Class: {', '.join(class_parts)}", style="dim")

        other_matches = os_info.matches[1:]
        if other_matches:
            os_text.append("\n\nOther matches:", style="bold")
            for m in other_matches:
                m_acc = f" ({m.accuracy}%)" if m.accuracy is not None else ""
                os_text.append(f"\n• {m.name}{m_acc}", style="dim")

        console.print(Panel(os_text, title="[bold]OS Detection[/bold]", border_style="green"))

    def _render_scripts_panel(self, console: Console, host: HostResult) -> None:
        """Render NSE script results panel safely."""
        ports_with_scripts = [p for p in sorted(host.ports, key=lambda x: x.port) if p.scripts]
        if not ports_with_scripts and not host.scripts:
            return

        scr_text = Text()

        if ports_with_scripts:
            scr_text.append("Port Scripts\n", style="bold yellow")
            for p in ports_with_scripts:
                scr_text.append(f"{p.port}/{p.protocol}\n", style="bold cyan")
                for s in p.scripts:
                    sid = s.script_id.strip() if s.script_id else "Unknown script"
                    scr_text.append(f"  {sid}:\n", style="bold")
                    output_str = s.output.strip() if s.output else "No output"
                    for oline in output_str.splitlines():
                        scr_text.append(f"    {oline}\n")

        if host.scripts:
            if ports_with_scripts:
                scr_text.append("\n")
            scr_text.append("Host Scripts\n", style="bold yellow")
            for s in host.scripts:
                sid = s.script_id.strip() if s.script_id else "Unknown script"
                scr_text.append(f"  {sid}:\n", style="bold")
                output_str = s.output.strip() if s.output else "No output"
                for oline in output_str.splitlines():
                    scr_text.append(f"    {oline}\n")

        console.print(Panel(scr_text, title="[bold]NSE Scripts[/bold]", border_style="yellow"))

    def render(self, report: ScanReport) -> str:
        """
        Render a ScanReport into a styled Rich terminal string.

        Args:
            report (ScanReport): SecMap backend-independent scan report.

        Returns:
            str: Styled terminal output string.
        """
        console, buf = self._get_console()

        if not report or not report.hosts:
            console.print(self._build_header_panel())
            console.print(Panel(Text("No targets scanned or scan report is empty.", style="dim"), border_style="red"))
            return buf.getvalue()

        console.print(self._build_header_panel())

        if len(report.hosts) > 1:
            console.print(self._build_summary_panel(report))
            console.print(self._build_hosts_overview_table(report))
            console.print(Text("\nHost Details", style="bold magenta"))

        for idx, host in enumerate(report.hosts):
            if idx > 0 and len(report.hosts) > 1:
                console.print()

            host_title = host.address or "Unknown Target"
            if host.hostname:
                host_title += f" ({host.hostname})"

            host_status = host.status.upper() if host.status else "UNKNOWN"
            status_style = "bold green" if host_status == "UP" else "bold red"

            host_info_text = Text()
            host_info_text.append("Target: ", style="bold")
            host_info_text.append(f"{host_title}\n")
            host_info_text.append("Status: ", style="bold")
            host_info_text.append(host_status, style=status_style)

            console.print(Panel(host_info_text, border_style="cyan" if host_status == "UP" else "red"))

            if host.status == "down":
                console.print(Text("No port information available.", style="dim"))
                continue

            if not host.ports:
                console.print(Text("No open ports detected.", style="dim"))
                self._render_os_panel(console, host.os)
                self._render_scripts_panel(console, host)
                continue

            console.print(self._build_ports_table(host.ports))
            port_count = len(host.ports)
            console.print(Text(f"\n{port_count} {'port' if port_count == 1 else 'ports'} shown\n", style="dim"))

            self._render_os_panel(console, host.os)
            self._render_scripts_panel(console, host)

        return buf.getvalue()
