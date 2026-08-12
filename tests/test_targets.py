"""
SecMap Phase 9 Target & Network Processing Test Suite.
Tests IPv4, IPv6, Hostname, CIDR syntax validation and safe host expansion caps.
"""

import unittest
from secmap_core.targets import expand_network, validate_target


class TestTargets(unittest.TestCase):

    def test_1_valid_ipv4(self):
        """Verify IPv4 address validation."""
        is_valid, ttype = validate_target("192.168.1.10")
        self.assertTrue(is_valid)
        self.assertEqual(ttype, "ipv4")

    def test_2_valid_ipv6(self):
        """Verify IPv6 address validation."""
        is_valid, ttype = validate_target("2001:db8::1")
        self.assertTrue(is_valid)
        self.assertEqual(ttype, "ipv6")

    def test_3_valid_hostname(self):
        """Verify hostname validation."""
        is_valid, ttype = validate_target("gateway.local")
        self.assertTrue(is_valid)
        self.assertEqual(ttype, "hostname")

    def test_4_valid_localhost(self):
        """Verify localhost validation."""
        is_valid, ttype = validate_target("localhost")
        self.assertTrue(is_valid)
        self.assertEqual(ttype, "hostname")

    def test_5_valid_cidr_ipv4(self):
        """Verify IPv4 CIDR target validation."""
        is_valid, ttype = validate_target("192.168.1.0/24")
        self.assertTrue(is_valid)
        self.assertEqual(ttype, "cidr")

    def test_6_valid_cidr_ipv6(self):
        """Verify IPv6 CIDR target validation."""
        is_valid, ttype = validate_target("2001:db8::/64")
        self.assertTrue(is_valid)
        self.assertEqual(ttype, "cidr")

    def test_7_invalid_cidr(self):
        """Verify invalid CIDR syntax validation."""
        is_valid, ttype = validate_target("192.168.1.0/999")
        self.assertFalse(is_valid)
        self.assertEqual(ttype, "invalid")

    def test_8_invalid_target_strings(self):
        """Verify malformed target strings are marked invalid."""
        for bad_tgt in ["", "   ", "not-a-network/24/99", "192.168.1.0/"]:
            is_valid, ttype = validate_target(bad_tgt)
            self.assertFalse(is_valid, f"Target '{bad_tgt}' should be invalid.")
            self.assertEqual(ttype, "invalid")

    def test_9_expand_small_network(self):
        """Verify safe expansion of small CIDR range."""
        hosts = expand_network("192.168.1.0/30", max_hosts=256)
        self.assertEqual(len(hosts), 2)
        self.assertEqual(hosts, ["192.168.1.1", "192.168.1.2"])

    def test_10_large_cidr_protection_cap(self):
        """Verify protection cap raises ValueError when network exceeds max_hosts limit."""
        with self.assertRaises(ValueError) as ctx:
            expand_network("0.0.0.0/0", max_hosts=4096)
        self.assertIn("exceeds the safe expansion limit", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
