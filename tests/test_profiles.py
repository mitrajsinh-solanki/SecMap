"""
SecMap Phase 14 Scan Profiles Test Suite.
Tests built-in profiles, profile lookup, argument merging precedence, conflict detection, profile name validation, and path traversal rejection.
"""

import unittest

from secmap_core.cli import CLIError, ScanArguments
from secmap_core.profiles import BUILTIN_PROFILES, ProfileConfigError, get_all_profiles, get_profile, resolve_profile, validate_profile_name


class TestProfiles(unittest.TestCase):

    def test_1_builtin_profiles_exist(self):
        """Verify all standard built-in profiles (quick, service, web, full) exist."""
        all_profs = get_all_profiles()
        self.assertIn("quick", all_profs)
        self.assertIn("service", all_profs)
        self.assertIn("web", all_profs)
        self.assertIn("full", all_profs)

    def test_2_profile_lookup_valid(self):
        """Verify get_profile returns requested ScanProfile instance."""
        prof = get_profile("quick")
        self.assertEqual(prof.name, "quick")
        self.assertEqual(prof.nmap_args, ("-p", "22,80,443"))
        self.assertEqual(prof.source, "built-in")

    def test_3_unknown_profile_error(self):
        """Verify get_profile raises clean CLIError for unknown profile names."""
        with self.assertRaises(CLIError) as ctx:
            get_profile("nonexistent_profile_xyz")
        self.assertIn("Unknown scan profile", str(ctx.exception))

    def test_4_cli_arguments_override_profile_ports(self):
        """Verify explicit CLI port arguments (-p 80,443) override profile default ports."""
        prof = get_profile("quick")  # default -p 22,80,443
        cli_args = ScanArguments(ports="80,443", nmap_args=["-p", "80,443"])
        resolved = resolve_profile(prof, cli_args)

        self.assertIn("-p", resolved.nmap_args)
        self.assertIn("80,443", resolved.nmap_args)
        self.assertNotIn("22,80,443", resolved.nmap_args)

    def test_5_scan_type_conflict_detection(self):
        """Verify conflicting scan flags (-sS and -sT) raise a clean CLIError."""
        prof = get_profile("quick")
        cli_args = ScanArguments(scan_types=["-sS", "-sT"], nmap_args=["-sS", "-sT"])
        with self.assertRaises(CLIError) as ctx:
            resolve_profile(prof, cli_args)
        self.assertIn("Conflicting scan types", str(ctx.exception))

    def test_6_profile_name_validation(self):
        """Verify profile identifier names are validated against regex rules."""
        validate_profile_name("valid_profile-123")
        with self.assertRaises(ProfileConfigError):
            validate_profile_name("invalid profile name!")

    def test_7_path_traversal_rejection(self):
        """Verify profile names containing path traversal characters are rejected."""
        with self.assertRaises(ProfileConfigError) as ctx:
            validate_profile_name("../evil")
        self.assertIn("Path traversal", str(ctx.exception))

    def test_8_profile_immutability(self):
        """Verify ScanProfile objects are frozen dataclasses."""
        prof = get_profile("quick")
        with self.assertRaises(Exception):
            prof.name = "modified_name"


if __name__ == "__main__":
    unittest.main()
