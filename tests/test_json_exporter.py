"""
SecMap Phase 10 JSON Exporter Test Suite.
Tests JsonExporter output validity, type preservation (port int, accuracy int), Unicode, and schema structure.
"""

import json
import unittest

from secmap_core.normalize import (
    HostResult,
    OSClass,
    OSMatch,
    OSResult,
    PortResult,
    ScanReport,
    ScriptResult,
    ServiceResult,
)
from secmap_core.output import JsonExporter


class TestJsonExporter(unittest.TestCase):

    def setUp(self):
        self.exporter = JsonExporter()

    def test_1_empty_report_valid_json(self):
        """Verify empty scan report renders valid JSON structure."""
        report = ScanReport(targets=[], hosts=[])
        out = self.exporter.render(report)
        parsed = json.loads(out)
        self.assertIn("targets", parsed)
        self.assertIn("hosts", parsed)
        self.assertEqual(parsed["hosts"], [])

    def test_2_single_host_types(self):
        """Verify single host JSON maintains native integer types for port and accuracy."""
        report = ScanReport(
            targets=["192.168.1.10"],
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
                    os=OSResult(matches=[OSMatch(name="Linux 5.15", accuracy=95)]),
                )
            ],
        )
        out = self.exporter.render(report)
        parsed = json.loads(out)

        self.assertEqual(parsed["targets"], ["192.168.1.10"])
        host_dict = parsed["hosts"][0]
        self.assertEqual(host_dict["address"], "192.168.1.10")

        port_dict = host_dict["ports"][0]
        self.assertIsInstance(port_dict["port"], int)
        self.assertEqual(port_dict["port"], 22)
        self.assertEqual(port_dict["protocol"], "tcp")
        self.assertEqual(port_dict["service"]["product"], "OpenSSH")

        os_match = host_dict["os"]["matches"][0]
        self.assertIsInstance(os_match["accuracy"], int)
        self.assertEqual(os_match["accuracy"], 95)

    def test_3_multi_host_json(self):
        """Verify multi-host report JSON export."""
        report = ScanReport(
            targets=["192.168.1.0/24"],
            hosts=[
                HostResult(address="192.168.1.10", status="up"),
                HostResult(address="192.168.1.20", status="up"),
            ],
        )
        out = self.exporter.render(report)
        parsed = json.loads(out)

        self.assertEqual(parsed["summary"]["discovered_hosts"], 2)
        self.assertEqual(len(parsed["hosts"]), 2)
        self.assertEqual(parsed["hosts"][0]["address"], "192.168.1.10")
        self.assertEqual(parsed["hosts"][1]["address"], "192.168.1.20")

    def test_4_scripts_and_cpe_json(self):
        """Verify NSE scripts and CPE identifiers in JSON export."""
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
                    os=OSResult(
                        matches=[
                            OSMatch(
                                name="Linux 5.15",
                                accuracy=95,
                                cpes=["cpe:/o:linux:linux_kernel:5.15"],
                                osclasses=[OSClass(vendor="Linux", family="Linux")],
                            )
                        ]
                    ),
                )
            ]
        )
        out = self.exporter.render(report)
        parsed = json.loads(out)

        port_dict = parsed["hosts"][0]["ports"][0]
        self.assertEqual(port_dict["scripts"][0]["script_id"], "http-title")
        self.assertEqual(port_dict["scripts"][0]["output"], "Example Domain")

        os_match = parsed["hosts"][0]["os"]["matches"][0]
        self.assertEqual(os_match["cpes"], ["cpe:/o:linux:linux_kernel:5.15"])
        self.assertEqual(os_match["osclasses"][0]["vendor"], "Linux")

    def test_5_unicode_json(self):
        """Verify unicode string preservation in JSON export."""
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
        out = self.exporter.render(report)
        parsed = json.loads(out)
        self.assertEqual(parsed["hosts"][0]["hostname"], "gäteway.lõcal")
        self.assertEqual(parsed["hosts"][0]["scripts"][0]["output"], unicode_str)

    def test_6_ipv6_json(self):
        """Verify IPv6 address JSON export."""
        report = ScanReport(
            hosts=[HostResult(address="2001:db8::1", address_type="ipv6", status="up")]
        )
        out = self.exporter.render(report)
        parsed = json.loads(out)
        self.assertEqual(parsed["hosts"][0]["address"], "2001:db8::1")
        self.assertEqual(parsed["hosts"][0]["address_type"], "ipv6")


if __name__ == "__main__":
    unittest.main()
