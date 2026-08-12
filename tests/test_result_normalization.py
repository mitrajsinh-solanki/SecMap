"""
SecMap Phase 5 Data Model Normalization Test Suite.
Tests conversion of raw parser structures to backend-independent SecMap data models.
"""

import unittest

from secmap_core.normalize import (
    HostResult,
    PortResult,
    ResultNormalizationError,
    ScanReport,
    ScriptResult,
    ServiceResult,
    get_open_ports,
    get_services,
    get_up_hosts,
    normalize_scan_result,
)
from secmap_core.parser import (
    Host as ParserHost,
    OSMatchNode,
    Port as ParserPort,
    ScanResult as ParserScanResult,
    ScriptNode,
    Service as ParserService,
)


class TestResultNormalization(unittest.TestCase):

    def setUp(self):
        """Build sample parsed data structure."""
        self.sample_parsed = ParserScanResult(
            scanner="nmap",
            scanner_version="7.95",
            args="nmap -sV -O 192.168.1.10",
            hosts=[
                ParserHost(
                    address="192.168.1.10",
                    address_type="ipv4",
                    status="UP",
                    hostname="gateway.local",
                    ports=[
                        ParserPort(
                            portid=22,
                            protocol="TCP",
                            state="OPEN",
                            reason="syn-ack",
                            service=ParserService(
                                name="SSH",
                                product="OpenSSH",
                                version="9.2",
                                extrainfo="protocol 2.0",
                            ),
                            scripts=[
                                ScriptNode(id="ssh-hostkey", output="2048 ssh-rsa aaa..."),
                            ],
                        ),
                        ParserPort(
                            portid=80,
                            protocol="TCP",
                            state="OPEN",
                            reason="syn-ack",
                            service=ParserService(
                                name="HTTP",
                                product="Apache httpd",
                                version="2.4.57",
                            ),
                            scripts=[],
                        ),
                    ],
                    os_matches=[
                        OSMatchNode(name="Linux 5.4 - 5.15", accuracy=95),
                    ],
                    scripts=[
                        ScriptNode(id="http-title", output="Example Domain"),
                    ],
                )
            ],
        )

    def test_1_basic_normalization(self):
        """Verify conversion from ParserScanResult to ScanReport."""
        report = normalize_scan_result(self.sample_parsed, targets=["192.168.1.10"])
        self.assertIsInstance(report, ScanReport)
        self.assertEqual(report.scanner, "nmap")
        self.assertEqual(report.scanner_version, "7.95")
        self.assertEqual(report.targets, ["192.168.1.10"])

    def test_2_host_normalization(self):
        """Verify host address, status, and hostname normalization."""
        report = normalize_scan_result(self.sample_parsed)
        self.assertEqual(len(report.hosts), 1)
        host = report.hosts[0]
        self.assertEqual(host.address, "192.168.1.10")
        self.assertEqual(host.address_type, "ipv4")
        self.assertEqual(host.status, "up")  # Case normalized to lowercase
        self.assertEqual(host.hostname, "gateway.local")

    def test_3_port_normalization(self):
        """Verify port ID integer conversion, protocol/state lowercase normalization."""
        report = normalize_scan_result(self.sample_parsed)
        port22 = report.hosts[0].ports[0]
        self.assertEqual(port22.port, 22)
        self.assertEqual(port22.protocol, "tcp")  # TCP -> tcp
        self.assertEqual(port22.state, "open")  # OPEN -> open
        self.assertEqual(port22.reason, "syn-ack")

    def test_4_service_normalization(self):
        """Verify service name normalization while preserving product and version strings."""
        report = normalize_scan_result(self.sample_parsed)
        svc = report.hosts[0].ports[0].service
        self.assertIsNotNone(svc)
        self.assertEqual(svc.name, "ssh")  # SSH -> ssh
        self.assertEqual(svc.product, "OpenSSH")  # Mixed case preserved
        self.assertEqual(svc.version, "9.2")

    def test_5_missing_service(self):
        """Verify ports without service details normalize gracefully."""
        parsed = ParserScanResult(
            hosts=[
                ParserHost(
                    address="10.0.0.1",
                    status="up",
                    ports=[ParserPort(portid=443, protocol="tcp", state="open", service=None)],
                )
            ]
        )
        report = normalize_scan_result(parsed)
        port = report.hosts[0].ports[0]
        self.assertEqual(port.port, 443)
        self.assertIsNone(port.service)

    def test_6_os_normalization(self):
        """Verify OS match name and accuracy preservation."""
        report = normalize_scan_result(self.sample_parsed)
        os_info = report.hosts[0].os
        self.assertIsNotNone(os_info)
        self.assertEqual(len(os_info.matches), 1)
        self.assertEqual(os_info.best_match.name, "Linux 5.4 - 5.15")
        self.assertEqual(os_info.best_match.accuracy, 95)

    def test_7_nse_scripts(self):
        """Verify host and port level NSE script preservation."""
        report = normalize_scan_result(self.sample_parsed)
        host_scripts = report.hosts[0].scripts
        self.assertEqual(len(host_scripts), 1)
        self.assertEqual(host_scripts[0].script_id, "http-title")
        self.assertEqual(host_scripts[0].output, "Example Domain")

        port_scripts = report.hosts[0].ports[0].scripts
        self.assertEqual(len(port_scripts), 1)
        self.assertEqual(port_scripts[0].script_id, "ssh-hostkey")

    def test_8_ipv6(self):
        """Verify IPv6 address and address_type preservation."""
        parsed = ParserScanResult(
            hosts=[
                ParserHost(
                    address="::1",
                    address_type="ipv6",
                    status="up",
                    ports=[],
                )
            ]
        )
        report = normalize_scan_result(parsed)
        host = report.hosts[0]
        self.assertEqual(host.address, "::1")
        self.assertEqual(host.address_type, "ipv6")

    def test_9_multiple_hosts(self):
        """Verify multiple hosts remain separate and distinct."""
        parsed = ParserScanResult(
            hosts=[
                ParserHost(address="192.168.1.1", status="up"),
                ParserHost(address="192.168.1.2", status="up"),
            ]
        )
        report = normalize_scan_result(parsed)
        self.assertEqual(len(report.hosts), 2)
        self.assertEqual(report.hosts[0].address, "192.168.1.1")
        self.assertEqual(report.hosts[1].address, "192.168.1.2")

    def test_10_multiple_ports(self):
        """Verify multiple ports map to the correct host."""
        report = normalize_scan_result(self.sample_parsed)
        ports = report.hosts[0].ports
        self.assertEqual(len(ports), 2)
        self.assertEqual(ports[0].port, 22)
        self.assertEqual(ports[1].port, 80)

    def test_11_invalid_port(self):
        """Verify invalid or out-of-range port numbers raise ResultNormalizationError."""
        invalid_parsed = ParserScanResult(
            hosts=[
                ParserHost(
                    address="10.0.0.1",
                    ports=[ParserPort(portid=70000, protocol="tcp", state="open")],
                )
            ]
        )
        with self.assertRaises(ResultNormalizationError):
            normalize_scan_result(invalid_parsed)

    def test_12_helper_functions(self):
        """Test get_up_hosts(), get_open_ports(), and get_services()."""
        report = normalize_scan_result(self.sample_parsed)

        up_hosts = get_up_hosts(report)
        self.assertEqual(len(up_hosts), 1)

        open_ports = get_open_ports(up_hosts[0])
        self.assertEqual(len(open_ports), 2)

        services = get_services(up_hosts[0])
        self.assertEqual(len(services), 2)
        self.assertEqual(services[0].name, "ssh")
        self.assertEqual(services[1].name, "http")

    def test_13_no_data_loss(self):
        """Verify all critical information elements survive normalization intact."""
        report = normalize_scan_result(self.sample_parsed)
        host = report.hosts[0]
        self.assertEqual(host.address, "192.168.1.10")
        self.assertEqual(host.hostname, "gateway.local")
        self.assertEqual(host.status, "up")
        self.assertEqual(host.os.best_match.name, "Linux 5.4 - 5.15")
        self.assertEqual(host.scripts[0].script_id, "http-title")
        self.assertEqual(host.ports[0].port, 22)
        self.assertEqual(host.ports[0].service.product, "OpenSSH")
        self.assertEqual(host.ports[0].scripts[0].script_id, "ssh-hostkey")


if __name__ == "__main__":
    unittest.main()
