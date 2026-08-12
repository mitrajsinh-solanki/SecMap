"""
SecMap Phase 15 JSON Scan Report Importer Test Suite.
Tests load_scan_report() for loading historical JSON files, schema parsing, missing files, and malformed inputs.
"""

import json
import pathlib
import tempfile
import unittest

from secmap_core.cli import CLIError
from secmap_core.normalize import load_scan_report


class TestJSONImporter(unittest.TestCase):

    def test_1_missing_file_error(self):
        """Verify missing file raises CLIError."""
        with self.assertRaises(CLIError) as ctx:
            load_scan_report("/nonexistent/file.json")
        self.assertIn("does not exist", str(ctx.exception))

    def test_2_malformed_json_error(self):
        """Verify invalid JSON syntax raises CLIError."""
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            tf.write("{ invalid json syntax ")
            temp_path = pathlib.Path(tf.name)

        try:
            with self.assertRaises(CLIError) as ctx:
                load_scan_report(temp_path)
            self.assertIn("Failed to parse JSON report file", str(ctx.exception))
        finally:
            temp_path.unlink()

    def test_3_valid_json_report_import(self):
        """Verify parsing valid SecMap JSON report file into ScanReport model."""
        report_dict = {
            "targets": ["192.168.1.10"],
            "hosts": [
                {
                    "address": "192.168.1.10",
                    "address_type": "ipv4",
                    "status": "up",
                    "hostname": "gateway.local",
                    "ports": [
                        {
                            "port": 22,
                            "protocol": "tcp",
                            "state": "open",
                            "service": {"name": "ssh", "product": "OpenSSH", "version": "9.2"},
                        }
                    ],
                }
            ],
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tf:
            json.dump(report_dict, tf)
            temp_path = pathlib.Path(tf.name)

        try:
            report = load_scan_report(temp_path)
            self.assertEqual(report.targets, ["192.168.1.10"])
            self.assertEqual(len(report.hosts), 1)
            host = report.hosts[0]
            self.assertEqual(host.address, "192.168.1.10")
            self.assertEqual(host.hostname, "gateway.local")
            self.assertEqual(len(host.ports), 1)
            port = host.ports[0]
            self.assertEqual(port.port, 22)
            self.assertEqual(port.service.name, "ssh")
        finally:
            temp_path.unlink()


if __name__ == "__main__":
    unittest.main()
