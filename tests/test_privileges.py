"""
SecMap Phase 12 Privilege Handling & Raw Socket Safety Test Suite.
Tests platform-aware privilege detection, scan requirement analysis (-sS, -sU, -O, -sT), advisory warnings, and security isolation.
"""

import sys
import unittest
from unittest.mock import MagicMock, patch

from secmap_core.cli import ScanArguments
from secmap_core.security import check_scan_privileges, is_elevated


class TestPrivileges(unittest.TestCase):

    @patch("sys.platform", "linux")
    @patch("os.geteuid", create=True)
    def test_1_elevated_state_linux(self, mock_geteuid):
        """Verify elevated privilege state detection on Linux when euid is 0."""
        mock_geteuid.return_value = 0
        elevated, platform_name = is_elevated()
        self.assertTrue(elevated)
        self.assertEqual(platform_name, "linux")

    @patch("sys.platform", "linux")
    @patch("os.geteuid", create=True)
    def test_2_non_elevated_state_linux(self, mock_geteuid):
        """Verify non-elevated privilege state detection on Linux when euid is 1000."""
        mock_geteuid.return_value = 1000
        elevated, platform_name = is_elevated()
        self.assertFalse(elevated)
        self.assertEqual(platform_name, "linux")

    @patch("sys.platform", "unknown_os")
    def test_3_unknown_state(self):
        """Verify unknown platform privilege state (None) does not crash."""
        elevated, platform_name = is_elevated()
        self.assertIsNone(elevated)
        self.assertEqual(platform_name, "unknown_os")

    @patch("secmap_core.security.privileges.is_elevated")
    def test_4_syn_scan_requirement(self, mock_elevated):
        """Verify -sS SYN scan flag is identified as requiring raw socket privileges."""
        mock_elevated.return_value = (False, "linux")
        args = ScanArguments(scan_types=["-sS"], targets=["127.0.0.1"])
        req_raw, reason, warnings = check_scan_privileges(args)
        self.assertTrue(req_raw)
        self.assertIn("SYN scan", reason)
        self.assertEqual(len(warnings), 1)
        self.assertIn("administrator/root privileges", warnings[0])

    @patch("secmap_core.security.privileges.is_elevated")
    def test_5_udp_scan_requirement(self, mock_elevated):
        """Verify -sU UDP scan flag is identified as requiring raw socket privileges."""
        mock_elevated.return_value = (False, "linux")
        args = ScanArguments(scan_types=["-sU"], targets=["127.0.0.1"])
        req_raw, reason, warnings = check_scan_privileges(args)
        self.assertTrue(req_raw)
        self.assertIn("UDP scan", reason)
        self.assertEqual(len(warnings), 1)

    @patch("secmap_core.security.privileges.is_elevated")
    def test_6_os_detection_requirement(self, mock_elevated):
        """Verify -O OS detection flag is identified as requiring raw socket privileges."""
        mock_elevated.return_value = (False, "windows")
        args = ScanArguments(os_detection=True, targets=["127.0.0.1"])
        req_raw, reason, warnings = check_scan_privileges(args)
        self.assertTrue(req_raw)
        self.assertIn("OS detection", reason)
        self.assertEqual(len(warnings), 1)

    @patch("secmap_core.security.privileges.is_elevated")
    def test_7_tcp_connect_unprivileged(self, mock_elevated):
        """Verify -sT TCP Connect scan is NOT marked as requiring raw sockets or generating warnings."""
        mock_elevated.return_value = (False, "linux")
        args = ScanArguments(scan_types=["-sT"], targets=["127.0.0.1"])
        req_raw, reason, warnings = check_scan_privileges(args)
        self.assertFalse(req_raw)
        self.assertEqual(len(warnings), 0)

    @patch("secmap_core.security.privileges.is_elevated")
    def test_8_version_scan_unprivileged(self, mock_elevated):
        """Verify -sV version detection flag alone does NOT generate raw socket warnings."""
        mock_elevated.return_value = (False, "linux")
        args = ScanArguments(service_version=True, targets=["127.0.0.1"])
        req_raw, reason, warnings = check_scan_privileges(args)
        self.assertFalse(req_raw)
        self.assertEqual(len(warnings), 0)

    @patch("secmap_core.security.privileges.is_elevated")
    def test_9_multiple_arguments_analysis(self, mock_elevated):
        """Verify combined flags (-sV -O -p 22,80) are analyzed correctly."""
        mock_elevated.return_value = (False, "linux")
        args = ScanArguments(service_version=True, os_detection=True, ports="22,80", targets=["127.0.0.1"])
        req_raw, reason, warnings = check_scan_privileges(args)
        self.assertTrue(req_raw)
        self.assertIn("OS detection", reason)

    def test_10_malformed_arguments_safety(self):
        """Verify malformed ScanArguments object does not crash privilege analysis."""
        args = ScanArguments(targets=[])
        req_raw, reason, warnings = check_scan_privileges(args)
        self.assertFalse(req_raw)
        self.assertEqual(len(warnings), 0)

    @patch("subprocess.run")
    @patch("subprocess.Popen")
    def test_11_no_subprocess_in_privileges(self, mock_popen, mock_run):
        """Verify privilege detection uses standard library calls without spawning subprocesses."""
        is_elevated()
        mock_run.assert_not_called()
        mock_popen.assert_not_called()

    def test_12_no_shell_true_in_security_module(self):
        """Verify no shell=True or string commands exist in privileges module."""
        import secmap_core.security.privileges as priv_mod
        import inspect

        source = inspect.getsource(priv_mod)
        self.assertNotIn("shell=True", source)
        self.assertNotIn("os.system", source)
        self.assertNotIn("os.popen", source)


if __name__ == "__main__":
    unittest.main()
