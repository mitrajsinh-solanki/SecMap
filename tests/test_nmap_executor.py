"""
SecMap Phase 3 Nmap Executor Test Suite.
Tests command building, custom executable, process execution mocking, shell injection protection, and missing Nmap binary errors.
"""

import unittest
from unittest.mock import MagicMock, patch

from secmap_core.cli import ScanArguments
from secmap_core.execution import NmapExecutionError, NmapExecutor, NmapResult


class TestNmapExecutor(unittest.TestCase):

    def test_1_command_construction(self):
        """Test array-based command construction."""
        executor = NmapExecutor()
        command = executor.build_command(["-sV", "-p", "22,80"], ["127.0.0.1"])
        self.assertEqual(command, ["nmap", "-sV", "-p", "22,80", "127.0.0.1"])

    def test_2_custom_executable(self):
        """Test custom executable support in NmapExecutor."""
        executor = NmapExecutor(executable="custom-nmap")
        command = executor.build_command(["-sV"], ["127.0.0.1"])
        self.assertEqual(command, ["custom-nmap", "-sV", "127.0.0.1"])

    @patch("subprocess.run")
    def test_3_successful_execution(self, mock_run):
        """Test successful execution with returncode 0 and stdout capture."""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = "Nmap scan report for 127.0.0.1\nPORT STATE SERVICE\n80/tcp open http\n"
        mock_process.stderr = ""
        mock_run.return_value = mock_process

        executor = NmapExecutor()
        scan_args = ScanArguments(targets=["127.0.0.1"], nmap_args=["-p", "80"])
        result = executor.execute(scan_args)

        self.assertTrue(result.success)
        self.assertEqual(result.returncode, 0)
        self.assertIn("Nmap scan report for 127.0.0.1", result.stdout)
        self.assertEqual(result.command, ["nmap", "-p", "80", "127.0.0.1"])

    @patch("subprocess.run")
    def test_4_failed_execution(self, mock_run):
        """Test failed process execution with non-zero returncode and stderr capture."""
        mock_process = MagicMock()
        mock_process.returncode = 1
        mock_process.stdout = ""
        mock_process.stderr = "Failed to resolve target\n"
        mock_run.return_value = mock_process

        executor = NmapExecutor()
        scan_args = ScanArguments(targets=["invalid_host"], nmap_args=[])
        result = executor.execute(scan_args)

        self.assertFalse(result.success)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Failed to resolve target", result.stderr)

    @patch("subprocess.run")
    def test_5_shell_false_verification(self, mock_run):
        """Explicitly verify that shell=False is passed to subprocess.run."""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = "OK"
        mock_process.stderr = ""
        mock_run.return_value = mock_process

        executor = NmapExecutor()
        scan_args = ScanArguments(targets=["127.0.0.1"], nmap_args=["-sV"])
        executor.execute(scan_args)

        mock_run.assert_called_once()
        _, kwargs = mock_run.call_args
        self.assertFalse(kwargs.get("shell", True))

    @patch("subprocess.run")
    def test_6_argument_list_verification(self, mock_run):
        """Verify that the command argument passed to subprocess.run is a list, not a string."""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = "OK"
        mock_process.stderr = ""
        mock_run.return_value = mock_process

        executor = NmapExecutor()
        scan_args = ScanArguments(targets=["127.0.0.1"], nmap_args=["-sV", "-O"])
        executor.execute(scan_args)

        args, _ = mock_run.call_args
        command_arg = args[0]
        self.assertIsInstance(command_arg, list)
        self.assertEqual(command_arg, ["nmap", "-sV", "-O", "127.0.0.1"])

    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_7_nmap_missing_error(self, mock_run):
        """Test FileNotFoundError is caught and converted to NmapExecutionError."""
        executor = NmapExecutor()
        scan_args = ScanArguments(targets=["127.0.0.1"], nmap_args=[])

        with self.assertRaises(NmapExecutionError) as cm:
            executor.execute(scan_args)

        self.assertIn("Nmap executable was not found", str(cm.exception))

    @patch("subprocess.run")
    def test_8_security_command_injection_prevention(self, mock_run):
        """Verify shell command injection strings are safely kept as discrete list arguments."""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = "OK"
        mock_process.stderr = ""
        mock_run.return_value = mock_process

        executor = NmapExecutor()
        malicious_target = "127.0.0.1; malicious-command"
        scan_args = ScanArguments(targets=[malicious_target], nmap_args=["-sV"])
        result = executor.execute(scan_args)

        self.assertEqual(result.command, ["nmap", "-sV", "127.0.0.1; malicious-command"])
        args, _ = mock_run.call_args
        self.assertEqual(args[0], ["nmap", "-sV", "127.0.0.1; malicious-command"])


if __name__ == "__main__":
    unittest.main()
