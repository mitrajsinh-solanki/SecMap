"""
SecMap Phase 14 Custom TOML Profile Configuration Test Suite.
Tests loading custom TOML profiles, missing config file safety, custom profile overrides, TOML parsing errors, and argument type validation.
"""

import pathlib
import tempfile
import unittest

from secmap_core.profiles import ProfileConfigError, get_all_profiles, load_custom_profiles


class TestProfileConfig(unittest.TestCase):

    def test_1_missing_config_file_returns_empty_dict(self):
        """Verify missing configuration file returns empty dict without crashing."""
        nonexistent = pathlib.Path("/nonexistent/path/config.toml")
        result = load_custom_profiles(nonexistent)
        self.assertEqual(result, {})

    def test_2_valid_custom_toml_loading(self):
        """Verify parsing valid custom profiles from TOML file."""
        toml_content = """
[profiles.lab]
description = "Authorized local lab scan"
args = ["-sT", "-sV", "-p", "22,80,443"]
"""
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False, encoding="utf-8") as tf:
            tf.write(toml_content)
            temp_path = pathlib.Path(tf.name)

        try:
            customs = load_custom_profiles(temp_path)
            self.assertIn("lab", customs)
            prof = customs["lab"]
            self.assertEqual(prof.name, "lab")
            self.assertEqual(prof.description, "Authorized local lab scan")
            self.assertEqual(prof.nmap_args, ("-sT", "-sV", "-p", "22,80,443"))
            self.assertIn("custom", prof.source)
        finally:
            temp_path.unlink()

    def test_3_custom_profile_overrides_builtin(self):
        """Verify custom profile definition overrides built-in profile of same name."""
        toml_content = """
[profiles.quick]
description = "Custom quick override"
args = ["-p", "80,443"]
"""
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False, encoding="utf-8") as tf:
            tf.write(toml_content)
            temp_path = pathlib.Path(tf.name)

        try:
            all_profs = get_all_profiles(temp_path)
            self.assertEqual(all_profs["quick"].description, "Custom quick override")
            self.assertEqual(all_profs["quick"].nmap_args, ("-p", "80,443"))
        finally:
            temp_path.unlink()

    def test_4_invalid_toml_syntax_error(self):
        """Verify invalid TOML syntax raises ProfileConfigError."""
        invalid_toml = "[profiles.broken\n description = invalid toml syntax"
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False, encoding="utf-8") as tf:
            tf.write(invalid_toml)
            temp_path = pathlib.Path(tf.name)

        try:
            with self.assertRaises(ProfileConfigError) as ctx:
                load_custom_profiles(temp_path)
            self.assertIn("Failed to parse configuration file", str(ctx.exception))
        finally:
            temp_path.unlink()

    def test_5_invalid_args_type_error(self):
        """Verify non-list 'args' entry in TOML raises ProfileConfigError."""
        invalid_toml = """
[profiles.bad_args]
description = "Bad args format"
args = "-p 22,80"
"""
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False, encoding="utf-8") as tf:
            tf.write(invalid_toml)
            temp_path = pathlib.Path(tf.name)

        try:
            with self.assertRaises(ProfileConfigError) as ctx:
                load_custom_profiles(temp_path)
            self.assertIn("must be a list of string flags", str(ctx.exception))
        finally:
            temp_path.unlink()


if __name__ == "__main__":
    unittest.main()
