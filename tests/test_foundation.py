"""
SecMap Phase 1 Foundation Test Suite.
Tests version string, CLI help, config constants, and Nmap availability detection (with mocking).
"""

import io
import sys
import unittest
from unittest.mock import MagicMock, patch

from secmap_core.config import SECMAP_NAME, SECMAP_VERSION
import secmap


class TestSecMapFoundation(unittest.TestCase):

    def test_config_constants(self):
        """Verify centralized configuration constants."""
        self.assertEqual(SECMAP_NAME, "SecMap")
        self.assertEqual(SECMAP_VERSION, "1.0.0")

    @patch("shutil.which")
    @patch("subprocess.Popen")
    def test_check_nmap_available(self, mock_popen, mock_which):
        """Test Nmap availability check when Nmap is installed on PATH."""
        mock_which.return_value = "/usr/bin/nmap"
        mock_process = MagicMock()
        mock_process.communicate.return_value = ("Nmap version 7.94 ( https://nmap.org )\n", "")
        mock_process.returncode = 0
        mock_popen.return_value = mock_process

        available, msg = secmap.check_nmap()

        self.assertTrue(available)
        self.assertIn("Nmap: available", msg)
        mock_which.assert_called_once_with("nmap")
        # Ensure shell=False was explicitly used
        mock_popen.assert_called_once()
        _, kwargs = mock_popen.call_args
        self.assertFalse(kwargs.get("shell", True))

    @patch("shutil.which")
    def test_check_nmap_missing(self, mock_which):
        """Test Nmap availability check when Nmap is missing from PATH."""
        mock_which.return_value = None

        available, msg = secmap.check_nmap()

        self.assertFalse(available)
        self.assertEqual(msg, "SecMap Error: Nmap was not found in PATH.")

    def test_cli_version_output(self):
        """Test secmap.py --version output."""
        with patch.object(sys, "argv", ["secmap", "--version"]):
            with patch("sys.stdout", new=io.StringIO()) as fake_out:
                with self.assertRaises(SystemExit) as cm:
                    secmap.main()
                self.assertEqual(cm.exception.code, 0)
                self.assertEqual(fake_out.getvalue().strip(), "SecMap 1.0.0")

    def test_cli_help_output(self):
        """Test secmap.py --help output."""
        with patch.object(sys, "argv", ["secmap", "--help"]):
            with patch("sys.stdout", new=io.StringIO()) as fake_out:
                with self.assertRaises(SystemExit) as cm:
                    secmap.main()
                self.assertEqual(cm.exception.code, 0)
                output = fake_out.getvalue()
                self.assertIn("SecMap 1.0.0", output)
                self.assertIn("Usage:", output)
                self.assertIn("--help", output)


if __name__ == "__main__":
    unittest.main()
