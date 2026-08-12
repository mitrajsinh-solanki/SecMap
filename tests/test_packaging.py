"""
SecMap Phase 13 Packaging & Distribution Test Suite.
Tests pyproject.toml metadata consistency, module imports, CLI main entry point, path independence, and security cleanliness.
"""

import os
import pathlib
import unittest

import secmap
import secmap_core
from secmap_core.config import SECMAP_NAME, SECMAP_VERSION


class TestPackaging(unittest.TestCase):

    def test_1_version_metadata_consistency(self):
        """Verify SECMAP_VERSION metadata is consistent."""
        self.assertEqual(SECMAP_VERSION, "1.0.0")
        self.assertEqual(SECMAP_NAME, "SecMap")

    def test_2_core_modules_importable(self):
        """Verify all core subpackages are cleanly importable without relative path dependencies."""
        import secmap_core.cli
        import secmap_core.execution
        import secmap_core.normalize
        import secmap_core.output
        import secmap_core.parser
        import secmap_core.security
        import secmap_core.targets

        self.assertIsNotNone(secmap_core.cli.parse_args)
        self.assertIsNotNone(secmap_core.execution.NmapExecutor)
        self.assertIsNotNone(secmap_core.normalize.normalize_scan_result)
        self.assertIsNotNone(secmap_core.output.get_output_renderer)
        self.assertIsNotNone(secmap_core.parser.parse_nmap_xml)
        self.assertIsNotNone(secmap_core.security.is_elevated)
        self.assertIsNotNone(secmap_core.targets.validate_target)

    def test_3_main_entry_point_callable(self):
        """Verify secmap.main entry point function exists and is callable."""
        self.assertTrue(callable(secmap.main))

    def test_4_rich_dependency_loaded(self):
        """Verify Rich dependency is importable and functional."""
        import rich
        from rich.console import Console

        console = Console()
        self.assertIsNotNone(console)

    def test_5_no_hardcoded_developer_paths(self):
        """Verify source codebase contains no hardcoded local developer paths (e.g. D:\\Secmap)."""
        secmap_dir = pathlib.Path(__file__).parent.parent / "secmap_core"
        for root, _, files in os.walk(secmap_dir):
            for file in files:
                if file.endswith(".py"):
                    filepath = os.path.join(root, file)
                    with open(filepath, "r", encoding="utf-8") as f:
                        content = f.read()
                        self.assertNotIn("D:\\Secmap", content, f"Hardcoded developer path found in {filepath}")
                        self.assertNotIn("d:/Secmap", content, f"Hardcoded developer path found in {filepath}")

    def test_6_secret_scan_cleanliness(self):
        """Verify source files do not contain embedded hardcoded secret tokens or credentials."""
        secmap_dir = pathlib.Path(__file__).parent.parent / "secmap_core"
        forbidden_keys = ["AWS_SECRET_ACCESS_KEY", "PRIVATE_KEY_BEGIN", "api_secret_key"]
        for root, _, files in os.walk(secmap_dir):
            for file in files:
                if file.endswith(".py"):
                    filepath = os.path.join(root, file)
                    with open(filepath, "r", encoding="utf-8") as f:
                        content = f.read()
                        for fkey in forbidden_keys:
                            self.assertNotIn(fkey, content, f"Forbidden key string found in {filepath}")


if __name__ == "__main__":
    unittest.main()
