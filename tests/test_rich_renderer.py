"""
SecMap Phase 11 Rich Terminal UI Renderer Test Suite.
Tests RichRenderer formatting, text states (OPEN, CLOSED, FILTERED), Rich markup escaping, Unicode support, and safety.
"""

import unittest

from secmap_core.normalize import (
    HostResult,
    OSMatch,
    OSResult,
    PortResult,
    ScanReport,
    ScriptResult,
    ServiceResult,
)
from secmap_core.output import RichRenderer


class TestRichRenderer(unittest.TestCase):

    def setUp(self):
        self.renderer = RichRenderer(color_system=None)

    def test_1_single_host(self):
        """Verify target address and status appear in Rich single host output."""
        report = ScanReport(
            hosts=[HostResult(address="192.168.1.10", hostname="gateway.local", status="up")]
        )
        out = self.renderer.render(report)
        self.assertIn("192.168.1.10", out)
        self.assertIn("gateway.local", out)
        self.assertIn("UP", out)

    def test_2_port_table(self):
        """Verify ports appear in Rich table layout."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    ports=[
                        PortResult(port=22, protocol="tcp", state="open"),
                        PortResult(port=80, protocol="tcp", state="open"),
                    ],
                )
            ]
        )
        out = self.renderer.render(report)
        self.assertIn("22/tcp", out)
        self.assertIn("80/tcp", out)

    def test_3_explicit_text_states(self):
        """Verify open, closed, filtered port states are explicitly visible as uppercase text."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    ports=[
                        PortResult(port=22, protocol="tcp", state="open"),
                        PortResult(port=80, protocol="tcp", state="closed"),
                        PortResult(port=443, protocol="tcp", state="filtered"),
                    ],
                )
            ]
        )
        out = self.renderer.render(report)
        self.assertIn("OPEN", out)
        self.assertIn("CLOSED", out)
        self.assertIn("FILTERED", out)

    def test_4_service_version_details(self):
        """Verify service name, product, and version display in Rich renderer."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    ports=[
                        PortResult(
                            port=80,
                            protocol="tcp",
                            state="open",
                            service=ServiceResult(name="http", product="Apache httpd", version="2.4.57"),
                        )
                    ],
                )
            ]
        )
        out = self.renderer.render(report)
        self.assertIn("http", out)
        self.assertIn("Apache httpd 2.4.57", out)

    def test_5_multiple_hosts(self):
        """Verify multi-host scan output displays all hosts."""
        report = ScanReport(
            hosts=[
                HostResult(address="192.168.1.10", status="up"),
                HostResult(address="192.168.1.20", status="up"),
            ]
        )
        out = self.renderer.render(report)
        self.assertIn("192.168.1.10", out)
        self.assertIn("192.168.1.20", out)

    def test_6_host_summary(self):
        """Verify host statistics in multi-host summary panel."""
        report = ScanReport(
            hosts=[
                HostResult(address="192.168.1.10", status="up"),
                HostResult(address="192.168.1.20", status="down"),
            ]
        )
        out = self.renderer.render(report)
        self.assertIn("Hosts Discovered:", out)
        self.assertIn("Hosts UP:", out)

    def test_7_os_panel(self):
        """Verify OS detection best match name and accuracy display."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    ports=[PortResult(port=80, protocol="tcp", state="open")],
                    os=OSResult(matches=[OSMatch(name="Linux 5.4 - 5.15", accuracy=95)]),
                )
            ]
        )
        out = self.renderer.render(report)
        self.assertIn("OS Detection", out)
        self.assertIn("Linux 5.4 - 5.15 (95%)", out)

    def test_8_nse_scripts(self):
        """Verify NSE script IDs and outputs display in Rich renderer."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    ports=[
                        PortResult(
                            port=80,
                            protocol="tcp",
                            state="open",
                            scripts=[ScriptResult(script_id="http-title", output="Example Domain")],
                        )
                    ],
                )
            ]
        )
        out = self.renderer.render(report)
        self.assertIn("NSE Scripts", out)
        self.assertIn("http-title:", out)
        self.assertIn("Example Domain", out)

    def test_9_unicode(self):
        """Verify Unicode string rendering without crashing."""
        unicode_str = "タイトル: Example Page ✨"
        report = ScanReport(
            hosts=[
                HostResult(
                    address="10.0.0.1",
                    hostname="gäteway.lõcal",
                    status="up",
                    scripts=[ScriptResult(script_id="http-title", output=unicode_str)],
                )
            ]
        )
        out = self.renderer.render(report)
        self.assertIn("gäteway.lõcal", out)
        self.assertIn(unicode_str, out)

    def test_10_long_strings(self):
        """Verify very long product and version strings do not crash the renderer."""
        long_ver = "Super Long Product Name Version 1.2.3.4 Build 9999 (x86_64-pc-linux-gnu)"
        report = ScanReport(
            hosts=[
                HostResult(
                    address="10.0.0.1",
                    status="up",
                    ports=[
                        PortResult(
                            port=80,
                            protocol="tcp",
                            state="open",
                            service=ServiceResult(name="http", product=long_ver),
                        )
                    ],
                )
            ]
        )
        out = self.renderer.render(report)
        self.assertIn(long_ver, out)

    def test_11_untrusted_rich_markup(self):
        """Verify untrusted strings containing Rich markup tags render literally without interpretation."""
        markup_payload = "[bold red]FAKE INJECTED MARKUP[/bold red]"
        report = ScanReport(
            hosts=[
                HostResult(
                    address="10.0.0.1",
                    status="up",
                    ports=[
                        PortResult(
                            port=80,
                            protocol="tcp",
                            state="open",
                            service=ServiceResult(name="http", product=markup_payload),
                        )
                    ],
                )
            ]
        )
        out = self.renderer.render(report)
        self.assertIn("[bold red]FAKE INJECTED MARKUP[/bold red]", out)

    def test_12_shell_like_content(self):
        """Verify shell command metacharacters render as plain text."""
        shell_payload = "$(echo TEST)\n`echo TEST`\n&& echo TEST"
        report = ScanReport(
            hosts=[
                HostResult(
                    address="10.0.0.1",
                    status="up",
                    scripts=[ScriptResult(script_id="shell-test", output=shell_payload)],
                )
            ]
        )
        out = self.renderer.render(report)
        self.assertIn("$(echo TEST)", out)
        self.assertIn("`echo TEST`", out)

    def test_13_empty_report(self):
        """Verify empty report rendering."""
        report = ScanReport(hosts=[])
        out = self.renderer.render(report)
        self.assertIn("No targets scanned or scan report is empty.", out)

    def test_14_down_host(self):
        """Verify down host rendering in Rich renderer."""
        report = ScanReport(
            hosts=[HostResult(address="192.168.1.50", status="down", ports=[])]
        )
        out = self.renderer.render(report)
        self.assertIn("192.168.1.50", out)
        self.assertIn("DOWN", out)
        self.assertIn("No port information available.", out)

    def test_15_no_open_ports(self):
        """Verify host with no open ports rendering."""
        report = ScanReport(
            hosts=[HostResult(address="127.0.0.1", status="up", ports=[])]
        )
        out = self.renderer.render(report)
        self.assertIn("127.0.0.1", out)
        self.assertIn("UP", out)
        self.assertIn("No open ports detected.", out)


if __name__ == "__main__":
    unittest.main()
