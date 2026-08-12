"""
SecMap Phase 8 NSE / Script Output Presentation Test Suite.
Tests host-level and port-level script formatting, multi-line indentation, key-value rendering, and untrusted payload safety.
"""

import unittest
from unittest.mock import patch

from secmap_core.normalize import (
    HostResult,
    PortResult,
    ScanReport,
    ScriptResult,
    ServiceResult,
)
from secmap_core.output import SecMapFormatter


class TestNSEOutput(unittest.TestCase):

    def setUp(self):
        self.formatter = SecMapFormatter()

    def test_1_single_script(self):
        """Verify single script output formatting."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    scripts=[ScriptResult(script_id="http-title", output="Example Domain")],
                )
            ]
        )
        output = self.formatter.render(report)
        self.assertIn("Host Scripts", output)
        self.assertIn("http-title:", output)
        self.assertIn("  Example Domain", output)

    def test_2_multiple_scripts(self):
        """Verify rendering of multiple scripts."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    scripts=[
                        ScriptResult(script_id="http-title", output="Example Domain"),
                        ScriptResult(script_id="http-server-header", output="Apache/2.4.57"),
                    ],
                )
            ]
        )
        output = self.formatter.render(report)
        self.assertIn("http-title:", output)
        self.assertIn("  Example Domain", output)
        self.assertIn("http-server-header:", output)
        self.assertIn("  Apache/2.4.57", output)

    def test_3_multiline_output(self):
        """Verify multi-line script output indentation is preserved."""
        multiline = "Subject: CN=example.com\nIssuer: Example CA\nValidity: 2026"
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    scripts=[ScriptResult(script_id="ssl-cert", output=multiline)],
                )
            ]
        )
        output = self.formatter.render(report)
        self.assertIn("ssl-cert:", output)
        self.assertIn("  Subject: CN=example.com", output)
        self.assertIn("  Issuer: Example CA", output)
        self.assertIn("  Validity: 2026", output)

    def test_4_key_value_output(self):
        """Verify key-value formatted lines rendering."""
        kv_output = "Name: Example\nState: active\nVersion: 2.4.57"
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    scripts=[ScriptResult(script_id="script-info", output=kv_output)],
                )
            ]
        )
        output = self.formatter.render(report)
        self.assertIn("  Name: Example", output)
        self.assertIn("  State: active", output)
        self.assertIn("  Version: 2.4.57", output)

    def test_5_nested_output(self):
        """Verify nested hierarchy indentation preservation."""
        nested = "Headers:\n  Server: nginx\n  Content-Type: text/html"
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    scripts=[ScriptResult(script_id="http-headers", output=nested)],
                )
            ]
        )
        output = self.formatter.render(report)
        self.assertIn("  Headers:", output)
        self.assertIn("    Server: nginx", output)
        self.assertIn("    Content-Type: text/html", output)

    def test_6_empty_output(self):
        """Verify empty script output renders 'No output' without leaking None or null."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    scripts=[ScriptResult(script_id="http-enum", output=None)],
                )
            ]
        )
        output = self.formatter.render(report)
        self.assertIn("http-enum:", output)
        self.assertIn("  No output", output)
        self.assertNotIn("None", output)
        self.assertNotIn("null", output)

    def test_7_missing_script_id(self):
        """Verify missing script ID fallback 'Unknown script' without crashing."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    scripts=[ScriptResult(script_id="", output="Output data")],
                )
            ]
        )
        output = self.formatter.render(report)
        self.assertIn("Unknown script:", output)
        self.assertIn("  Output data", output)

    def test_8_multiple_hosts(self):
        """Verify scripts remain associated with their respective host."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    scripts=[ScriptResult(script_id="http-title", output="Host A Title")],
                ),
                HostResult(
                    address="192.168.1.20",
                    status="up",
                    scripts=[ScriptResult(script_id="http-title", output="Host B Title")],
                ),
            ]
        )
        output = self.formatter.render(report)
        self.assertIn("Target: 192.168.1.10", output)
        self.assertIn("Host A Title", output)
        self.assertIn("Target: 192.168.1.20", output)
        self.assertIn("Host B Title", output)

    def test_9_port_association(self):
        """Verify port-level script association under specific port block (e.g. 80/tcp)."""
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
                            scripts=[ScriptResult(script_id="http-title", output="Apache Domain")],
                        )
                    ],
                )
            ]
        )
        output = self.formatter.render(report)
        self.assertIn("NSE Scripts", output)
        self.assertIn("80/tcp", output)
        self.assertIn("  http-title:", output)
        self.assertIn("    Apache Domain", output)

    def test_10_host_level_script(self):
        """Verify host-level scripts render under 'Host Scripts' section."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    scripts=[ScriptResult(script_id="clock-skew", output="0s")],
                )
            ]
        )
        output = self.formatter.render(report)
        self.assertIn("Host Scripts", output)
        self.assertIn("  clock-skew:", output)
        self.assertIn("    0s", output)

    def test_11_script_error(self):
        """Verify script error message preservation."""
        error_output = "ERROR: Script execution failed"
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    scripts=[ScriptResult(script_id="broken-script", output=error_output)],
                )
            ]
        )
        output = self.formatter.render(report)
        self.assertIn("  ERROR: Script execution failed", output)

    def test_12_unicode_script_output(self):
        """Verify unicode script output rendering without crashing."""
        unicode_out = "タイトル: Example Web Page ✨"
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    scripts=[ScriptResult(script_id="http-title", output=unicode_out)],
                )
            ]
        )
        output = self.formatter.render(report)
        self.assertIn("タイトル: Example Web Page ✨", output)

    def test_13_security_strings(self):
        """Verify shell command metacharacters in script output render strictly as plain text."""
        sec_payload = "$(echo TEST)\n`echo TEST`\n; echo TEST\n&& echo TEST\n| echo TEST"
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    scripts=[ScriptResult(script_id="vuln-test", output=sec_payload)],
                )
            ]
        )
        output = self.formatter.render(report)
        self.assertIn("$(echo TEST)", output)
        self.assertIn("`echo TEST`", output)
        self.assertIn("; echo TEST", output)

    @patch("subprocess.run")
    def test_14_no_subprocess_execution(self, mock_run):
        """Verify formatting a ScriptResult triggers ZERO subprocess executions."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    scripts=[ScriptResult(script_id="test-script", output="Test")],
                )
            ]
        )
        self.formatter.render(report)
        mock_run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
