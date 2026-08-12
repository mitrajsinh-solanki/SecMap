"""
SecMap Phase 10 CSV Exporter Test Suite.
Tests CsvExporter schema compliance, csv.reader parsing, CSV formula injection protection, down host handling, and multi-script rows.
"""

import csv
import io
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
from secmap_core.output import CsvExporter


class TestCsvExporter(unittest.TestCase):

    def setUp(self):
        self.exporter = CsvExporter()

    def test_1_empty_report_csv_header(self):
        """Verify empty report CSV output contains standard header line."""
        report = ScanReport(hosts=[])
        out = self.exporter.render(report)
        reader = list(csv.reader(io.StringIO(out)))
        self.assertEqual(len(reader), 1)
        self.assertEqual(reader[0], CsvExporter.HEADERS)

    def test_2_single_host_csv(self):
        """Verify single host port/service row parsing."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    hostname="gateway.local",
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
            ]
        )
        out = self.exporter.render(report)
        reader = list(csv.reader(io.StringIO(out)))
        self.assertEqual(len(reader), 2)
        row = reader[1]

        self.assertEqual(row[0], "192.168.1.10")  # HOST
        self.assertEqual(row[1], "gateway.local")  # HOSTNAME
        self.assertEqual(row[2], "up")             # STATUS
        self.assertEqual(row[3], "22")             # PORT
        self.assertEqual(row[4], "tcp")            # PROTOCOL
        self.assertEqual(row[5], "open")           # STATE
        self.assertEqual(row[6], "ssh")            # SERVICE
        self.assertEqual(row[7], "OpenSSH")        # PRODUCT
        self.assertEqual(row[8], "9.2")            # VERSION
        self.assertEqual(row[9], "Linux 5.15")     # OS
        self.assertEqual(row[10], "95")            # OS_ACCURACY

    def test_3_down_host_csv(self):
        """Verify down host renders row with down status and empty port fields."""
        report = ScanReport(
            hosts=[HostResult(address="192.168.1.50", status="down", ports=[])]
        )
        out = self.exporter.render(report)
        reader = list(csv.reader(io.StringIO(out)))
        self.assertEqual(len(reader), 2)
        row = reader[1]
        self.assertEqual(row[0], "192.168.1.50")
        self.assertEqual(row[2], "down")
        self.assertEqual(row[3], "")  # PORT empty

    def test_4_no_open_ports_host_csv(self):
        """Verify host with no open ports renders row with empty port fields."""
        report = ScanReport(
            hosts=[HostResult(address="127.0.0.1", status="up", ports=[])]
        )
        out = self.exporter.render(report)
        reader = list(csv.reader(io.StringIO(out)))
        self.assertEqual(len(reader), 2)
        row = reader[1]
        self.assertEqual(row[0], "127.0.0.1")
        self.assertEqual(row[2], "up")
        self.assertEqual(row[3], "")

    def test_5_formula_injection_protection(self):
        """Verify CSV formula injection characters (=, +, -, @) are safely escaped."""
        payload = "=1+1"
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
                            service=ServiceResult(name=payload, product="+cmd", version="-cmd"),
                        )
                    ],
                )
            ]
        )
        out = self.exporter.render(report)
        reader = list(csv.reader(io.StringIO(out)))
        row = reader[1]

        self.assertTrue(row[6].startswith("'="))
        self.assertTrue(row[7].startswith("'+"))
        self.assertTrue(row[8].startswith("'-"))

    def test_6_values_with_commas_and_quotes(self):
        """Verify string values containing commas and quotes are escaped correctly by csv.reader."""
        product_str = 'Apache "HTTPD", 2.4 (Ubuntu)'
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
                            service=ServiceResult(name="http", product=product_str),
                        )
                    ],
                )
            ]
        )
        out = self.exporter.render(report)
        reader = list(csv.reader(io.StringIO(out)))
        row = reader[1]
        self.assertEqual(row[7], product_str)

    def test_7_multiple_scripts_csv_rows(self):
        """Verify multiple scripts generate rows per script."""
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
                            service=ServiceResult(name="http"),
                            scripts=[
                                ScriptResult(script_id="http-title", output="Domain A"),
                                ScriptResult(script_id="http-server-header", output="Apache"),
                            ],
                        )
                    ],
                )
            ]
        )
        out = self.exporter.render(report)
        reader = list(csv.reader(io.StringIO(out)))
        self.assertEqual(len(reader), 3)  # Header + 2 script rows
        self.assertIn("http-title", reader[1][11])
        self.assertIn("http-server-header", reader[2][11])


if __name__ == "__main__":
    unittest.main()
