"""
SecMap CSV Exporter Module
Serializes normalized ScanReport domain models into valid CSV string output with formula injection protection.
Phase 10 implementation.
"""

import csv
import io
from secmap_core.normalize.results import HostResult, ScanReport


class CsvExporter:
    """Renders ScanReport models into row-oriented CSV strings."""

    HEADERS = [
        "HOST",
        "HOSTNAME",
        "STATUS",
        "PORT",
        "PROTOCOL",
        "STATE",
        "SERVICE",
        "PRODUCT",
        "VERSION",
        "OS",
        "OS_ACCURACY",
        "SCRIPT",
    ]

    def _sanitize_cell(self, val: str | int | float | None) -> str:
        """
        Sanitize string values against CSV formula injection (=, +, -, @).

        Args:
            val: Cell input value.

        Returns:
            str: Safely escaped cell string.
        """
        if val is None:
            return ""

        val_str = str(val)
        if not val_str:
            return ""

        # Protect against CSV formula injection
        if val_str.startswith(("=", "+", "-", "@")):
            return f"'{val_str}"

        return val_str

    def render(self, report: ScanReport) -> str:
        """
        Render a ScanReport into a formatted CSV string.

        Args:
            report (ScanReport): SecMap backend-independent scan report.

        Returns:
            str: CSV text string.
        """
        output_buffer = io.StringIO()
        writer = csv.writer(output_buffer, lineterminator="\n")

        writer.writerow(self.HEADERS)

        if not report or not report.hosts:
            return output_buffer.getvalue()

        for host in report.hosts:
            self._write_host_rows(writer, host)

        return output_buffer.getvalue()

    def _write_host_rows(self, writer: csv.writer, host: HostResult) -> None:
        """Generate and write CSV rows for a host."""
        host_addr = self._sanitize_cell(host.address)
        hostname = self._sanitize_cell(host.hostname)
        status = self._sanitize_cell(host.status)

        os_name = ""
        os_accuracy = ""
        if host.os and host.os.best_match:
            os_name = self._sanitize_cell(host.os.best_match.name)
            if host.os.best_match.accuracy is not None:
                os_accuracy = self._sanitize_cell(host.os.best_match.accuracy)

        if host.status == "down" or not host.ports:
            # Row for down host or host with no open ports
            writer.writerow(
                [
                    host_addr,
                    hostname,
                    status,
                    "",  # PORT
                    "",  # PROTOCOL
                    "",  # STATE
                    "",  # SERVICE
                    "",  # PRODUCT
                    "",  # VERSION
                    os_name,
                    os_accuracy,
                    "",  # SCRIPT
                ]
            )
            return

        for p in host.ports:
            port_num = self._sanitize_cell(p.port)
            protocol = self._sanitize_cell(p.protocol)
            state = self._sanitize_cell(p.state)

            svc_name = ""
            product = ""
            version = ""
            if p.service:
                svc_name = self._sanitize_cell(p.service.name)
                product = self._sanitize_cell(p.service.product)
                version = self._sanitize_cell(p.service.version)

            scripts_to_render = p.scripts if p.scripts else host.scripts

            if not scripts_to_render:
                writer.writerow(
                    [
                        host_addr,
                        hostname,
                        status,
                        port_num,
                        protocol,
                        state,
                        svc_name,
                        product,
                        version,
                        os_name,
                        os_accuracy,
                        "",
                    ]
                )
            else:
                for s in scripts_to_render:
                    scr_str = self._sanitize_cell(f"{s.script_id}: {s.output or ''}")
                    writer.writerow(
                        [
                            host_addr,
                            hostname,
                            status,
                            port_num,
                            protocol,
                            state,
                            svc_name,
                            product,
                            version,
                            os_name,
                            os_accuracy,
                            scr_str,
                        ]
                    )
