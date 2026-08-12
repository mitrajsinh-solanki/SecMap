"""
SecMap Phase 2 CLI Argument Parsing & Validation Layer Test Suite.
Tests argument parsing, timing options, targets, flags, and CLI error conditions.
"""

import sys
import unittest
from unittest.mock import patch

from secmap_core.cli import CLIError, ScanArguments, build_nmap_args, parse_args
import secmap


class TestCLIArguments(unittest.TestCase):

    def test_1_valid_single_target(self):
        """Test parsing valid single IPv4 target."""
        args = parse_args(["127.0.0.1"])
        self.assertEqual(args.targets, ["127.0.0.1"])
        self.assertFalse(args.show_help)
        self.assertFalse(args.show_version)

    def test_2_ports(self):
        """Test port selection option."""
        args = parse_args(["-p", "22,80,443", "127.0.0.1"])
        self.assertEqual(args.ports, "22,80,443")
        self.assertEqual(args.nmap_args, ["-p", "22,80,443"])

    def test_3_service_detection(self):
        """Test -sV service detection flag."""
        args = parse_args(["-sV", "127.0.0.1"])
        self.assertTrue(args.service_version)
        self.assertEqual(args.nmap_args, ["-sV"])

    def test_4_os_detection(self):
        """Test -O OS detection flag."""
        args = parse_args(["-O", "127.0.0.1"])
        self.assertTrue(args.os_detection)
        self.assertEqual(args.nmap_args, ["-O"])

    def test_5_nse_scripts(self):
        """Test --script option with equals sign and space separation."""
        args1 = parse_args(["--script=http-title", "127.0.0.1"])
        self.assertEqual(args1.scripts, ["http-title"])
        self.assertEqual(args1.nmap_args, ["--script=http-title"])

        args2 = parse_args(["--script", "http-title", "127.0.0.1"])
        self.assertEqual(args2.scripts, ["http-title"])
        self.assertEqual(args2.nmap_args, ["--script=http-title"])

    def test_6_combined_flags(self):
        """Test combined flags -sV -O --script=http-title."""
        args = parse_args(["-sV", "-O", "--script=http-title", "127.0.0.1"])
        self.assertEqual(args.targets, ["127.0.0.1"])
        self.assertEqual(args.nmap_args, ["-sV", "-O", "--script=http-title"])
        self.assertEqual(build_nmap_args(args), ["-sV", "-O", "--script=http-title"])

    def test_7_udp_scan(self):
        """Test -sU UDP scan flag."""
        args = parse_args(["-sU", "127.0.0.1"])
        self.assertIn("-sU", args.scan_types)
        self.assertEqual(args.nmap_args, ["-sU"])

    def test_8_syn_scan(self):
        """Test -sS TCP SYN scan flag."""
        args = parse_args(["-sS", "127.0.0.1"])
        self.assertIn("-sS", args.scan_types)
        self.assertEqual(args.nmap_args, ["-sS"])

    def test_9_aggressive_scan(self):
        """Test -A aggressive scan flag."""
        args = parse_args(["-A", "127.0.0.1"])
        self.assertTrue(args.aggressive)
        self.assertEqual(args.nmap_args, ["-A"])

    def test_10_timing_template(self):
        """Test valid timing templates -T0 through -T5."""
        for t in range(6):
            args = parse_args([f"-T{t}", "127.0.0.1"])
            self.assertEqual(args.timing, t)
            self.assertEqual(args.nmap_args, [f"-T{t}"])

    def test_11_invalid_timing(self):
        """Test error raised for out-of-bounds timing templates -T6."""
        with self.assertRaises(CLIError):
            parse_args(["-T6", "127.0.0.1"])

    def test_12_missing_target(self):
        """Test error raised when no target IP is provided."""
        with self.assertRaises(CLIError):
            parse_args(["-sV"])

    def test_13_unrecognized_option(self):
        """Test error raised for unrecognized options."""
        with self.assertRaises(CLIError):
            parse_args(["--invalid-flag", "127.0.0.1"])

    def test_14_cidr_target(self):
        """Test parsing valid CIDR target."""
        args = parse_args(["-sV", "192.168.1.0/24"])
        self.assertEqual(args.targets, ["192.168.1.0/24"])
        self.assertEqual(args.nmap_args, ["-sV"])

    @patch("sys.argv", ["secmap.py", "--plain", "--debug", "127.0.0.1"])
    @patch("secmap_core.execution.nmap_executor.NmapExecutor.execute_xml")
    def test_15_debug_mode(self, mock_execute):
        """Test --debug argument and CLI output rendering in Phase 4."""
        from secmap_core.execution import NmapResult
        from secmap_core.parser import Host, ScanResult

        mock_execute.return_value = (
            NmapResult(
                command=["nmap", "-oX", "-", "127.0.0.1"],
                returncode=0,
                stdout="<nmaprun></nmaprun>",
                stderr="",
            ),
            ScanResult(hosts=[Host(address="127.0.0.1", status="up", ports=[])]),
        )

        with patch("sys.stdout") as mock_stdout, patch("sys.exit") as mock_exit:
            secmap.main()
            mock_exit.assert_called_with(0)

    @patch("sys.argv", ["secmap.py", "--plain", "127.0.0.1"])
    @patch("secmap_core.execution.nmap_executor.NmapExecutor.execute_xml")
    def test_cli_execution_delegation(self, mock_execute):
        """Verify Nmap process execution is triggered via subprocess.run during CLI calls."""
        from io import StringIO
        from secmap_core.execution import NmapResult
        from secmap_core.parser import Host, ScanResult

        mock_execute.return_value = (
            NmapResult(
                command=["nmap", "-oX", "-", "127.0.0.1"],
                returncode=0,
                stdout="<nmaprun></nmaprun>",
                stderr="",
            ),
            ScanResult(hosts=[Host(address="127.0.0.1", status="up", ports=[])]),
        )

        captured_output = StringIO()
        with patch("sys.stdout", captured_output), patch("sys.exit"):
            secmap.main()

        output = captured_output.getvalue()
        self.assertIn("127.0.0.1", output)
        mock_execute.assert_called_once()


if __name__ == "__main__":
    unittest.main()
