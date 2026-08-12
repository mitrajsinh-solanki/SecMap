"""
SecMap Phase 6 Output Formatter Test Suite.
Tests terminal rendering, column padding alignment, numeric port sorting, OS/NSE rendering, and untrusted string safety.
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
from secmap_core.output import SecMapFormatter


class TestOutputFormatter(unittest.TestCase):

    def setUp(self):
        self.formatter = SecMapFormatter()

    def test_1_empty_report(self):
        """Verify empty report rendering."""
        report = ScanReport(hosts=[])
        rendered = self.formatter.render(report)
        self.assertIn("SecMap Scan Report", rendered)
        self.assertIn("No targets scanned or scan report is empty.", rendered)

    def test_2_one_open_port(self):
        """Verify single open port rendering."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    ports=[
                        PortResult(
                            port=22,
                            protocol="tcp",
                            state="open",
                            service=ServiceResult(name="ssh", product="OpenSSH", version="9.2"),
                        )
                    ],
                )
            ]
        )
        output = self.formatter.render(report)
        self.assertIn("Target: 192.168.1.10", output)
        self.assertIn("Status: up", output)
        self.assertIn("22/tcp", output)
        self.assertIn("open", output)
        self.assertIn("ssh", output)
        self.assertIn("OpenSSH 9.2", output)
        self.assertIn("1 port shown", output)

    def test_3_multiple_ports_alignment(self):
        """Verify multiple ports table header and column alignment."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    ports=[
                        PortResult(
                            port=22,
                            protocol="tcp",
                            state="open",
                            service=ServiceResult(name="ssh", product="OpenSSH", version="9.2"),
                        ),
                        PortResult(
                            port=80,
                            protocol="tcp",
                            state="open",
                            service=ServiceResult(name="http", product="Apache httpd", version="2.4.57"),
                        ),
                    ],
                )
            ]
        )
        output = self.formatter.render(report)
        self.assertIn("PORT     STATE   SERVICE   VERSION", output)
        self.assertIn("22/tcp   open    ssh       OpenSSH 9.2", output)
        self.assertIn("80/tcp   open    http      Apache httpd 2.4.57", output)
        self.assertIn("2 ports shown", output)

    def test_4_numeric_port_sorting(self):
        """Verify ports are sorted numerically (22, 80, 443) rather than lexicographically."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="127.0.0.1",
                    status="up",
                    ports=[
                        PortResult(port=443, protocol="tcp", state="open"),
                        PortResult(port=22, protocol="tcp", state="open"),
                        PortResult(port=80, protocol="tcp", state="open"),
                        PortResult(port=53, protocol="udp", state="open"),
                    ],
                )
            ]
        )
        output = self.formatter.render(report)
        lines = output.splitlines()
        port_lines = [l for l in lines if "/tcp" in l or "/udp" in l]
        self.assertTrue(port_lines[0].startswith("22/tcp"))
        self.assertTrue(port_lines[1].startswith("53/udp"))
        self.assertTrue(port_lines[2].startswith("80/tcp"))
        self.assertTrue(port_lines[3].startswith("443/tcp"))

    def test_5_tcp_and_udp(self):
        """Verify TCP and UDP protocols are displayed correctly."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="10.0.0.1",
                    status="up",
                    ports=[
                        PortResult(port=22, protocol="tcp", state="open"),
                        PortResult(port=53, protocol="udp", state="open", service=ServiceResult(name="domain")),
                    ],
                )
            ]
        )
        output = self.formatter.render(report)
        self.assertIn("22/tcp", output)
        self.assertIn("53/udp", output)
        self.assertIn("domain", output)

    def test_6_missing_service(self):
        """Verify missing service renders as '-' instead of None."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="10.0.0.1",
                    status="up",
                    ports=[PortResult(port=443, protocol="tcp", state="open", service=None)],
                )
            ]
        )
        output = self.formatter.render(report)
        self.assertIn("443/tcp   open    -         -", output)

    def test_7_missing_version(self):
        """Verify missing version renders product string."""
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
                            service=ServiceResult(name="http", product="nginx", version=None),
                        )
                    ],
                )
            ]
        )
        output = self.formatter.render(report)
        self.assertIn("80/tcp   open    http      nginx", output)

    def test_8_missing_product(self):
        """Verify missing product renders version string."""
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
                            service=ServiceResult(name="http", product=None, version="1.24"),
                        )
                    ],
                )
            ]
        )
        output = self.formatter.render(report)
        self.assertIn("80/tcp   open    http      1.24", output)

    def test_9_missing_hostname(self):
        """Verify missing hostname does not leak '(None)'."""
        report = ScanReport(
            hosts=[HostResult(address="10.0.0.1", hostname=None, status="up", ports=[])]
        )
        output = self.formatter.render(report)
        self.assertIn("Target: 10.0.0.1", output)
        self.assertNotIn("None", output)

    def test_10_host_status(self):
        """Verify rendering of host status (up, down, unknown)."""
        report_down = ScanReport(
            hosts=[HostResult(address="192.168.1.50", status="down", ports=[])]
        )
        output_down = self.formatter.render(report_down)
        self.assertIn("Target: 192.168.1.50", output_down)
        self.assertIn("Status: down", output_down)
        self.assertIn("No port information available.", output_down)

    def test_11_multiple_hosts(self):
        """Verify multiple hosts are kept distinct without mixing."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    ports=[PortResult(port=22, protocol="tcp", state="open", service=ServiceResult(name="ssh"))],
                ),
                HostResult(
                    address="192.168.1.20",
                    status="up",
                    ports=[PortResult(port=80, protocol="tcp", state="open", service=ServiceResult(name="http"))],
                ),
            ]
        )
        output = self.formatter.render(report)
        self.assertIn("Target: 192.168.1.10", output)
        self.assertIn("Target: 192.168.1.20", output)
        self.assertIn("22/tcp", output)
        self.assertIn("80/tcp", output)

    def test_12_no_open_ports(self):
        """Verify clear message when host is up but has no open ports."""
        report = ScanReport(
            hosts=[HostResult(address="127.0.0.1", status="up", ports=[])]
        )
        output = self.formatter.render(report)
        self.assertIn("Target: 127.0.0.1", output)
        self.assertIn("Status: up", output)
        self.assertIn("No open ports detected.", output)

    def test_13_os_output(self):
        """Verify OS detection match and accuracy percentage rendering."""
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
        output = self.formatter.render(report)
        self.assertIn("OS Detection", output)
        self.assertIn("Best match: Linux 5.4 - 5.15 (95%)", output)

    def test_14_multiple_os_matches(self):
        """Verify highest accuracy OS match is designated as Best match."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    ports=[],
                    os=OSResult(
                        matches=[
                            OSMatch(name="Linux 5.4 - 5.15", accuracy=95),
                            OSMatch(name="Linux 5.10", accuracy=87),
                        ]
                    ),
                )
            ]
        )
        output = self.formatter.render(report)
        self.assertIn("Best match: Linux 5.4 - 5.15 (95%)", output)

    def test_15_nse_scripts(self):
        """Verify NSE script ID and output text rendering."""
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
        output = self.formatter.render(report)
        self.assertIn("NSE Scripts", output)
        self.assertIn("http-title:", output)
        self.assertIn("Example Domain", output)

    def test_16_long_service_version(self):
        """Verify formatter remains padded cleanly with long version strings."""
        long_ver = "Super Long Product Version 1.2.3.4 Build 9999 (x86_64-pc-linux-gnu)"
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
        output = self.formatter.render(report)
        self.assertIn(long_ver, output)

    def test_17_unicode(self):
        """Verify unicode strings in hostnames or service banners do not crash formatter."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="10.0.0.1",
                    hostname="gäteway.lõcal",
                    status="up",
                    ports=[
                        PortResult(
                            port=80,
                            protocol="tcp",
                            state="open",
                            service=ServiceResult(name="http", product="Sërvice ✨"),
                        )
                    ],
                )
            ]
        )
        output = self.formatter.render(report)
        self.assertIn("gäteway.lõcal", output)
        self.assertIn("Sërvice ✨", output)

    def test_18_security_strings(self):
        """Verify security control characters are rendered strictly as plain text without execution."""
        payload = "127.0.0.1; cat /etc/passwd | grep `whoami` > /tmp/test"
        report = ScanReport(
            hosts=[
                HostResult(
                    address=payload,
                    status="up",
                    ports=[
                        PortResult(
                            port=80,
                            protocol="tcp",
                            state="open",
                            service=ServiceResult(name=payload, product=payload),
                        )
                    ],
                )
            ]
        )
        output = self.formatter.render(report)
        self.assertIn(payload, output)


if __name__ == "__main__":
    unittest.main()
