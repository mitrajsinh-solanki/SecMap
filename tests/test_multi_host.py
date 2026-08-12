"""
SecMap Phase 9 Multiple Hosts & CIDR Range Processing Test Suite.
Tests host aggregation, summary statistics, open port counting, down host representation, overview tables, and isolation safety.
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


class TestMultiHost(unittest.TestCase):

    def setUp(self):
        self.formatter = SecMapFormatter()

    def test_1_multiple_ip_targets(self):
        """Verify multiple targets remain separate in ScanReport."""
        report = ScanReport(
            targets=["192.168.1.10", "192.168.1.20"],
            hosts=[
                HostResult(address="192.168.1.10", status="up"),
                HostResult(address="192.168.1.20", status="up"),
            ],
        )
        self.assertEqual(report.discovered_hosts_count, 2)
        self.assertEqual(report.targets, ["192.168.1.10", "192.168.1.20"])

    def test_2_multiple_hosts_individual_isolation(self):
        """Verify each host retains its own ports, services, OS matches, and scripts."""
        host_a = HostResult(
            address="192.168.1.10",
            status="up",
            ports=[
                PortResult(
                    port=22,
                    protocol="tcp",
                    state="open",
                    service=ServiceResult(name="ssh"),
                    scripts=[ScriptResult(script_id="ssh-hostkey", output="Key A")],
                )
            ],
            os=OSResult(matches=[OSMatch(name="Linux 5.15", accuracy=95)]),
        )
        host_b = HostResult(
            address="192.168.1.20",
            status="up",
            ports=[
                PortResult(
                    port=80,
                    protocol="tcp",
                    state="open",
                    service=ServiceResult(name="http"),
                    scripts=[ScriptResult(script_id="http-title", output="Title B")],
                )
            ],
            os=OSResult(matches=[OSMatch(name="Windows 10", accuracy=92)]),
        )
        report = ScanReport(targets=["192.168.1.10", "192.168.1.20"], hosts=[host_a, host_b])
        output = self.formatter.render(report)

        self.assertIn("Target: 192.168.1.10", output)
        self.assertIn("22/tcp", output)
        self.assertIn("ssh-hostkey:", output)
        self.assertIn("Key A", output)
        self.assertIn("Linux 5.15 (95%)", output)

        self.assertIn("Target: 192.168.1.20", output)
        self.assertIn("80/tcp", output)
        self.assertIn("http-title:", output)
        self.assertIn("Title B", output)
        self.assertIn("Windows 10 (92%)", output)

    def test_3_host_summary_counts(self):
        """Verify report summary properties calculation."""
        report = ScanReport(
            hosts=[
                HostResult(address="192.168.1.10", status="up"),
                HostResult(address="192.168.1.20", status="up"),
                HostResult(address="192.168.1.30", status="down"),
            ]
        )
        self.assertEqual(report.discovered_hosts_count, 3)
        self.assertEqual(report.hosts_up_count, 2)
        self.assertEqual(report.hosts_down_count, 1)

    def test_4_open_port_counting(self):
        """Verify total open ports calculation (Host A: 2, Host B: 1 -> 3)."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    ports=[
                        PortResult(port=22, protocol="tcp", state="open"),
                        PortResult(port=80, protocol="tcp", state="open"),
                    ],
                ),
                HostResult(
                    address="192.168.1.20",
                    status="up",
                    ports=[PortResult(port=443, protocol="tcp", state="open")],
                ),
                HostResult(address="192.168.1.30", status="up", ports=[]),
            ]
        )
        self.assertEqual(report.total_open_ports_count, 3)

    def test_5_port_instances_double_count(self):
        """Verify same port on two hosts is counted twice in total open ports."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    ports=[PortResult(port=80, protocol="tcp", state="open")],
                ),
                HostResult(
                    address="192.168.1.20",
                    status="up",
                    ports=[PortResult(port=80, protocol="tcp", state="open")],
                ),
            ]
        )
        self.assertEqual(report.total_open_ports_count, 2)

    def test_6_service_counts(self):
        """Verify total service instances and unique service names count."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    ports=[
                        PortResult(port=22, protocol="tcp", state="open", service=ServiceResult(name="ssh")),
                        PortResult(port=80, protocol="tcp", state="open", service=ServiceResult(name="http")),
                    ],
                ),
                HostResult(
                    address="192.168.1.20",
                    status="up",
                    ports=[PortResult(port=80, protocol="tcp", state="open", service=ServiceResult(name="http"))],
                ),
            ]
        )
        self.assertEqual(report.total_service_instances_count, 3)
        self.assertEqual(report.unique_services_count, 2)

    def test_7_down_host_table_representation(self):
        """Verify down host renders '-' for ports and services in overview table."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    ports=[PortResult(port=80, protocol="tcp", state="open", service=ServiceResult(name="http"))],
                ),
                HostResult(address="192.168.1.50", status="down", ports=[]),
            ]
        )
        output = self.formatter.render(report)
        self.assertIn("192.168.1.50   down     -            -", output)

    def test_8_hostname_handling(self):
        """Verify host identity rendering with hostname."""
        report = ScanReport(
            hosts=[
                HostResult(address="192.168.1.10", hostname="gateway.local", status="up"),
                HostResult(address="192.168.1.20", hostname="server.local", status="up"),
            ]
        )
        output = self.formatter.render(report)
        self.assertIn("192.168.1.10 (gateway.local)", output)
        self.assertIn("192.168.1.20 (server.local)", output)

    def test_9_missing_hostname(self):
        """Verify missing hostname does not leak '(None)' or 'null'."""
        report = ScanReport(
            hosts=[
                HostResult(address="192.168.1.10", hostname=None, status="up"),
                HostResult(address="192.168.1.20", hostname=None, status="up"),
            ]
        )
        output = self.formatter.render(report)
        self.assertNotIn("None", output)
        self.assertNotIn("null", output)

    def test_10_single_host_regression(self):
        """Verify single host report preserves Phase 6/7/8 concise layout without overview table."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="127.0.0.1",
                    status="up",
                    ports=[PortResult(port=22, protocol="tcp", state="open", service=ServiceResult(name="ssh"))],
                )
            ]
        )
        output = self.formatter.render(report)
        self.assertNotIn("Hosts Overview", output)
        self.assertNotIn("Scan Summary", output)
        self.assertIn("Target: 127.0.0.1", output)

    def test_11_multihost_overview_table(self):
        """Verify multi-host report renders Scan Summary and Hosts Overview table."""
        report = ScanReport(
            targets=["192.168.1.0/24"],
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
            ],
        )
        output = self.formatter.render(report)
        self.assertIn("Scan Summary", output)
        self.assertIn("Hosts discovered: 2", output)
        self.assertIn("Hosts Overview", output)
        self.assertIn("HOST           STATUS   OPEN PORTS   SERVICES", output)
        self.assertIn("Host Details", output)

    def test_12_security_control_strings(self):
        """Verify shell metacharacters in target addresses render strictly as plain text."""
        payload = "192.168.1.10; cat /etc/passwd"
        report = ScanReport(
            hosts=[
                HostResult(address=payload, status="up"),
                HostResult(address="192.168.1.20", status="up"),
            ]
        )
        output = self.formatter.render(report)
        self.assertIn(payload, output)


if __name__ == "__main__":
    unittest.main()
