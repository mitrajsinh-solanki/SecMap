"""
SecMap Phase 15 Scan Difference Engine Test Suite.
Tests ScanDiffEngine comparison logic for host, port, service, OS, and NSE script changes, as well as IPv4/IPv6 and TCP/UDP isolation.
"""

import unittest

from secmap_core.diff import ScanDiffEngine
from secmap_core.normalize import (
    HostResult,
    OSMatch,
    OSResult,
    PortResult,
    ScanReport,
    ScriptResult,
    ServiceResult,
)


class TestDiffEngine(unittest.TestCase):

    def setUp(self):
        self.engine = ScanDiffEngine()

    def test_1_host_added(self):
        """Verify new host appearing in current scan is detected as host addition."""
        baseline = ScanReport(hosts=[HostResult(address="192.168.1.10", status="up")])
        current = ScanReport(
            hosts=[
                HostResult(address="192.168.1.10", status="up"),
                HostResult(address="192.168.1.20", status="up"),
            ]
        )
        diff = self.engine.compare(baseline, current)
        self.assertEqual(diff.summary.hosts_added, 1)
        self.assertEqual(len(diff.host_changes), 1)
        self.assertEqual(diff.host_changes[0].address, "192.168.1.20")
        self.assertEqual(diff.host_changes[0].change_type, "added")

    def test_2_host_removed(self):
        """Verify host absent in current scan is detected as host removal."""
        baseline = ScanReport(
            hosts=[
                HostResult(address="192.168.1.10", status="up"),
                HostResult(address="192.168.1.20", status="up"),
            ]
        )
        current = ScanReport(hosts=[HostResult(address="192.168.1.10", status="up")])
        diff = self.engine.compare(baseline, current)
        self.assertEqual(diff.summary.hosts_removed, 1)
        self.assertEqual(diff.host_changes[0].address, "192.168.1.20")
        self.assertEqual(diff.host_changes[0].change_type, "removed")

    def test_3_host_status_changed(self):
        """Verify host status changing from up to down is detected."""
        baseline = ScanReport(hosts=[HostResult(address="192.168.1.10", status="up")])
        current = ScanReport(hosts=[HostResult(address="192.168.1.10", status="down")])
        diff = self.engine.compare(baseline, current)
        self.assertEqual(diff.summary.hosts_changed, 1)
        self.assertEqual(diff.host_changes[0].old_status, "up")
        self.assertEqual(diff.host_changes[0].new_status, "down")

    def test_4_port_opened(self):
        """Verify new open port is detected as port opening."""
        baseline = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    ports=[PortResult(port=22, protocol="tcp", state="open")],
                )
            ]
        )
        current = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    ports=[
                        PortResult(port=22, protocol="tcp", state="open"),
                        PortResult(port=443, protocol="tcp", state="open"),
                    ],
                )
            ]
        )
        diff = self.engine.compare(baseline, current)
        self.assertEqual(diff.summary.ports_opened, 1)
        self.assertEqual(diff.port_changes[0].port, 443)
        self.assertEqual(diff.port_changes[0].change_type, "opened")

    def test_5_port_closed(self):
        """Verify port state changing from open to closed is detected."""
        baseline = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    ports=[PortResult(port=80, protocol="tcp", state="open")],
                )
            ]
        )
        current = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    ports=[PortResult(port=80, protocol="tcp", state="closed")],
                )
            ]
        )
        diff = self.engine.compare(baseline, current)
        self.assertEqual(diff.summary.ports_closed, 1)
        self.assertEqual(diff.port_changes[0].port, 80)
        self.assertEqual(diff.port_changes[0].change_type, "closed")

    def test_6_tcp_and_udp_separation(self):
        """Verify 53/tcp and 53/udp are treated as separate endpoints."""
        baseline = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    ports=[PortResult(port=53, protocol="tcp", state="open")],
                )
            ]
        )
        current = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    ports=[
                        PortResult(port=53, protocol="tcp", state="open"),
                        PortResult(port=53, protocol="udp", state="open"),
                    ],
                )
            ]
        )
        diff = self.engine.compare(baseline, current)
        self.assertEqual(diff.summary.ports_opened, 1)
        self.assertEqual(diff.port_changes[0].protocol, "udp")

    def test_7_service_and_version_changed(self):
        """Verify service version update is detected."""
        baseline = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    ports=[
                        PortResult(
                            port=80,
                            protocol="tcp",
                            state="open",
                            service=ServiceResult(name="http", product="Apache", version="2.4.50"),
                        )
                    ],
                )
            ]
        )
        current = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    ports=[
                        PortResult(
                            port=80,
                            protocol="tcp",
                            state="open",
                            service=ServiceResult(name="http", product="Apache", version="2.4.57"),
                        )
                    ],
                )
            ]
        )
        diff = self.engine.compare(baseline, current)
        self.assertEqual(diff.summary.services_changed, 1)
        self.assertIn("2.4.50", diff.service_changes[0].old_service)
        self.assertIn("2.4.57", diff.service_changes[0].new_service)

    def test_8_os_changed(self):
        """Verify OS match fingerprint modification is detected."""
        baseline = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    os=OSResult(matches=[OSMatch(name="Linux 5.4", accuracy=90)]),
                )
            ]
        )
        current = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    os=OSResult(matches=[OSMatch(name="Linux 5.15", accuracy=95)]),
                )
            ]
        )
        diff = self.engine.compare(baseline, current)
        self.assertEqual(diff.summary.os_changed, 1)
        self.assertIn("Linux 5.4", diff.os_changes[0].old_os)
        self.assertIn("Linux 5.15", diff.os_changes[0].new_os)

    def test_9_nse_script_output_changed(self):
        """Verify NSE script output modification is detected."""
        baseline = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    ports=[
                        PortResult(
                            port=80,
                            protocol="tcp",
                            state="open",
                            scripts=[ScriptResult(script_id="http-title", output="Old Title")],
                        )
                    ],
                )
            ]
        )
        current = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    ports=[
                        PortResult(
                            port=80,
                            protocol="tcp",
                            state="open",
                            scripts=[ScriptResult(script_id="http-title", output="New Title")],
                        )
                    ],
                )
            ]
        )
        diff = self.engine.compare(baseline, current)
        self.assertEqual(diff.summary.scripts_changed, 1)
        self.assertEqual(diff.script_changes[0].change_type, "output_changed")
        self.assertEqual(diff.script_changes[0].old_output, "Old Title")
        self.assertEqual(diff.script_changes[0].new_output, "New Title")

    def test_10_ipv6_host_diff(self):
        """Verify IPv6 address diff comparison."""
        baseline = ScanReport(hosts=[HostResult(address="2001:db8::1", status="up")])
        current = ScanReport(
            hosts=[
                HostResult(address="2001:db8::1", status="up"),
                HostResult(address="2001:db8::2", status="up"),
            ]
        )
        diff = self.engine.compare(baseline, current)
        self.assertEqual(diff.summary.hosts_added, 1)
        self.assertEqual(diff.host_changes[0].address, "2001:db8::2")

    def test_11_unchanged_report_zero_noise(self):
        """Verify comparing identical reports yields 0 changes in summary."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    ports=[PortResult(port=22, protocol="tcp", state="open")],
                )
            ]
        )
        diff = self.engine.compare(report, report)
        self.assertEqual(diff.summary.hosts_added, 0)
        self.assertEqual(diff.summary.hosts_removed, 0)
        self.assertEqual(diff.summary.ports_opened, 0)
        self.assertEqual(diff.summary.ports_closed, 0)
        self.assertEqual(diff.summary.services_changed, 0)


if __name__ == "__main__":
    unittest.main()
