"""
SecMap Phase 7 Advanced OS Detection Presentation Test Suite.
Tests OS match accuracy sorting, CPE rendering, OS class formatting, and untrusted string safety.
"""

import unittest

from secmap_core.normalize import (
    HostResult,
    OSClass,
    OSMatch,
    OSResult,
    PortResult,
    ScanReport,
    normalize_scan_result,
)
from secmap_core.output import SecMapFormatter
from secmap_core.parser import (
    Host as ParserHost,
    OSClassNode as ParserOSClassNode,
    OSMatchNode as ParserOSMatchNode,
    ScanResult as ParserScanResult,
)


class TestOSOutput(unittest.TestCase):

    def setUp(self):
        self.formatter = SecMapFormatter()

    def test_1_single_os_match(self):
        """Verify single OS match presentation."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    os=OSResult(matches=[OSMatch(name="Linux 5.4 - 5.15", accuracy=95)]),
                )
            ]
        )
        output = self.formatter.render(report)
        self.assertIn("OS Detection", output)
        self.assertIn("Best match: Linux 5.4 - 5.15 (95%)", output)

    def test_2_multiple_matches(self):
        """Verify highest confidence OS match is listed as Best match followed by Other matches."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    os=OSResult(
                        matches=[
                            OSMatch(name="Linux 5.4 - 5.15", accuracy=95),
                            OSMatch(name="Linux 5.10", accuracy=87),
                            OSMatch(name="Linux 5.15", accuracy=82),
                        ]
                    ),
                )
            ]
        )
        output = self.formatter.render(report)
        self.assertIn("Best match: Linux 5.4 - 5.15 (95%)", output)
        self.assertIn("Other matches:", output)
        self.assertIn("- Linux 5.10 (87%)", output)
        self.assertIn("- Linux 5.15 (82%)", output)

    def test_3_numeric_sorting(self):
        """Verify OS matches are sorted numerically by accuracy (95%, 82%, 75%)."""
        parsed = ParserScanResult(
            hosts=[
                ParserHost(
                    address="192.168.1.10",
                    status="up",
                    os_matches=[
                        ParserOSMatchNode(name="Linux A", accuracy=75),
                        ParserOSMatchNode(name="Linux B", accuracy=95),
                        ParserOSMatchNode(name="Linux C", accuracy=82),
                    ],
                )
            ]
        )
        report = normalize_scan_result(parsed)
        output = self.formatter.render(report)
        self.assertIn("Best match: Linux B (95%)", output)
        self.assertIn("- Linux C (82%)", output)
        self.assertIn("- Linux A (75%)", output)

    def test_4_missing_accuracy(self):
        """Verify OS match without accuracy score renders name without '(None%)'."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    os=OSResult(matches=[OSMatch(name="Linux Kernel", accuracy=None)]),
                )
            ]
        )
        output = self.formatter.render(report)
        self.assertIn("Best match: Linux Kernel", output)
        self.assertNotIn("None", output)

    def test_5_missing_os_name(self):
        """Verify missing OS match name uses fallback 'Unknown OS fingerprint' without crashing."""
        parsed = ParserScanResult(
            hosts=[
                ParserHost(
                    address="192.168.1.10",
                    status="up",
                    os_matches=[ParserOSMatchNode(name="", accuracy=90)],
                )
            ]
        )
        report = normalize_scan_result(parsed)
        output = self.formatter.render(report)
        self.assertIn("Best match: Unknown OS fingerprint (90%)", output)

    def test_6_no_os_result(self):
        """Verify host without OS result cleanly omits OS Detection section."""
        report = ScanReport(
            hosts=[HostResult(address="192.168.1.10", status="up", os=None)]
        )
        output = self.formatter.render(report)
        self.assertNotIn("OS Detection", output)

    def test_7_os_cpe(self):
        """Verify OS CPE tag rendering."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    os=OSResult(
                        matches=[
                            OSMatch(
                                name="Linux 5.15",
                                accuracy=94,
                                cpes=["cpe:/o:linux:linux_kernel:5.15"],
                            )
                        ]
                    ),
                )
            ]
        )
        output = self.formatter.render(report)
        self.assertIn("Best match: Linux 5.15 (94%)", output)
        self.assertIn("CPE: cpe:/o:linux:linux_kernel:5.15", output)

    def test_8_os_class(self):
        """Verify OS class attributes rendering without leaking empty None fields."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    os=OSResult(
                        matches=[
                            OSMatch(
                                name="Linux 5.4 - 5.15",
                                accuracy=95,
                                osclasses=[
                                    OSClass(
                                        vendor="Linux",
                                        family="Linux",
                                        generation="5.X",
                                        type="general purpose",
                                    )
                                ],
                            )
                        ]
                    ),
                )
            ]
        )
        output = self.formatter.render(report)
        self.assertIn("OS Class: Vendor: Linux, Family: Linux, Gen: 5.X, Type: general purpose", output)
        self.assertNotIn("None", output)

    def test_9_multiple_hosts(self):
        """Verify OS detection info stays correctly attributed to each host."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="192.168.1.10",
                    status="up",
                    os=OSResult(matches=[OSMatch(name="Linux 5.15", accuracy=95)]),
                ),
                HostResult(
                    address="192.168.1.20",
                    status="up",
                    os=OSResult(matches=[OSMatch(name="Microsoft Windows 10", accuracy=92)]),
                ),
            ]
        )
        output = self.formatter.render(report)
        self.assertIn("Target: 192.168.1.10", output)
        self.assertIn("Best match: Linux 5.15 (95%)", output)
        self.assertIn("Target: 192.168.1.20", output)
        self.assertIn("Best match: Microsoft Windows 10 (92%)", output)

    def test_10_unicode_os_strings(self):
        """Verify unicode OS strings do not crash the formatter."""
        report = ScanReport(
            hosts=[
                HostResult(
                    address="10.0.0.1",
                    status="up",
                    os=OSResult(matches=[OSMatch(name="Système Linux 🐧", accuracy=99)]),
                )
            ]
        )
        output = self.formatter.render(report)
        self.assertIn("Best match: Système Linux 🐧 (99%)", output)

    def test_11_untrusted_strings(self):
        """Verify security control characters in OS names render as plain text without execution."""
        payload = "Linux; rm -rf / | cat `whoami` > /tmp/os"
        report = ScanReport(
            hosts=[
                HostResult(
                    address="10.0.0.1",
                    status="up",
                    os=OSResult(matches=[OSMatch(name=payload, accuracy=90)]),
                )
            ]
        )
        output = self.formatter.render(report)
        self.assertIn(payload, output)


if __name__ == "__main__":
    unittest.main()
