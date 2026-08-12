"""
SecMap Phase 4 Nmap XML Engine & Parser Test Suite.
Tests XML parsing, host/port/service data models, error handling, multiple targets, and execution stream isolation.
"""

import unittest
from unittest.mock import MagicMock, patch

from secmap_core.cli import ScanArguments
from secmap_core.execution import NmapExecutor
from secmap_core.parser import (
    Host,
    NmapXMLParseError,
    Port,
    ScanResult,
    Service,
    parse_nmap_xml,
)


SAMPLE_XML_SINGLE_HOST = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.95" args="nmap -sV -p 22,80 127.0.0.1">
    <host>
        <status state="up" reason="syn-ack"/>
        <address addr="127.0.0.1" addrtype="ipv4"/>
        <hostnames>
            <hostname name="localhost" type="PTR"/>
        </hostnames>
        <ports>
            <port protocol="tcp" portid="22">
                <state state="open" reason="syn-ack"/>
                <service name="ssh" product="OpenSSH" version="9.2" extrainfo="protocol 2.0"/>
            </port>
            <port protocol="tcp" portid="80">
                <state state="open" reason="syn-ack"/>
                <service name="http" product="Apache httpd" version="2.4.57"/>
            </port>
        </ports>
    </host>
</nmaprun>
"""

SAMPLE_XML_MULTI_HOST = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.95" args="nmap -sV 192.168.1.1 192.168.1.2">
    <host>
        <status state="up"/>
        <address addr="192.168.1.1" addrtype="ipv4"/>
        <ports>
            <port protocol="tcp" portid="80">
                <state state="open"/>
                <service name="http"/>
            </port>
        </ports>
    </host>
    <host>
        <status state="up"/>
        <address addr="192.168.1.2" addrtype="ipv4"/>
        <ports>
            <port protocol="tcp" portid="443">
                <state state="open"/>
                <service name="https"/>
            </port>
        </ports>
    </host>
</nmaprun>
"""

SAMPLE_XML_MISSING_SERVICE = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.95">
    <host>
        <status state="up"/>
        <address addr="10.0.0.1" addrtype="ipv4"/>
        <ports>
            <port protocol="tcp" portid="443">
                <state state="open"/>
            </port>
        </ports>
    </host>
</nmaprun>
"""

SAMPLE_XML_EMPTY_HOSTS = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.95">
</nmaprun>
"""


class TestNmapXMLParser(unittest.TestCase):

    def test_1_basic_xml_metadata(self):
        """Verify root <nmaprun> metadata extraction."""
        result = parse_nmap_xml(SAMPLE_XML_SINGLE_HOST)
        self.assertEqual(result.scanner, "nmap")
        self.assertEqual(result.scanner_version, "7.95")
        self.assertIn("nmap -sV", result.args)

    def test_2_host_parsing(self):
        """Verify host IP, status, and hostname extraction."""
        result = parse_nmap_xml(SAMPLE_XML_SINGLE_HOST)
        self.assertEqual(len(result.hosts), 1)
        host = result.hosts[0]
        self.assertEqual(host.address, "127.0.0.1")
        self.assertEqual(host.address_type, "ipv4")
        self.assertEqual(host.status, "up")
        self.assertEqual(host.hostname, "localhost")

    def test_3_port_parsing(self):
        """Verify portid, protocol, state, and reason extraction."""
        result = parse_nmap_xml(SAMPLE_XML_SINGLE_HOST)
        ports = result.hosts[0].ports
        self.assertEqual(len(ports), 2)
        port22 = ports[0]
        self.assertEqual(port22.portid, 22)
        self.assertEqual(port22.protocol, "tcp")
        self.assertEqual(port22.state, "open")
        self.assertEqual(port22.reason, "syn-ack")

    def test_4_service_parsing(self):
        """Verify service details (name, product, version, extrainfo)."""
        result = parse_nmap_xml(SAMPLE_XML_SINGLE_HOST)
        service = result.hosts[0].ports[0].service
        self.assertIsNotNone(service)
        self.assertEqual(service.name, "ssh")
        self.assertEqual(service.product, "OpenSSH")
        self.assertEqual(service.version, "9.2")
        self.assertEqual(service.extrainfo, "protocol 2.0")

    def test_5_multiple_ports(self):
        """Verify parsing of multiple port elements on a single host."""
        result = parse_nmap_xml(SAMPLE_XML_SINGLE_HOST)
        portids = [p.portid for p in result.hosts[0].ports]
        self.assertEqual(portids, [22, 80])

    def test_6_multiple_hosts(self):
        """Verify parsing of multiple <host> tags."""
        result = parse_nmap_xml(SAMPLE_XML_MULTI_HOST)
        self.assertEqual(len(result.hosts), 2)
        self.assertEqual(result.hosts[0].address, "192.168.1.1")
        self.assertEqual(result.hosts[1].address, "192.168.1.2")

    def test_7_missing_service(self):
        """Verify a port without a <service> tag parses without crashing."""
        result = parse_nmap_xml(SAMPLE_XML_MISSING_SERVICE)
        port = result.hosts[0].ports[0]
        self.assertEqual(port.portid, 443)
        self.assertIsNone(port.service)

    def test_8_missing_optional_service_attributes(self):
        """Verify missing product/version/extrainfo default to None."""
        result = parse_nmap_xml(SAMPLE_XML_MULTI_HOST)
        service = result.hosts[0].ports[0].service
        self.assertEqual(service.name, "http")
        self.assertIsNone(service.product)
        self.assertIsNone(service.version)

    def test_9_empty_host_list(self):
        """Verify <nmaprun> with zero hosts returns ScanResult(hosts=[])."""
        result = parse_nmap_xml(SAMPLE_XML_EMPTY_HOSTS)
        self.assertEqual(result.hosts, [])

    def test_10_invalid_xml(self):
        """Verify malformed XML raises NmapXMLParseError."""
        with self.assertRaises(NmapXMLParseError):
            parse_nmap_xml("<nmaprun><unclosed>")

    def test_11_empty_xml(self):
        """Verify empty string input raises NmapXMLParseError."""
        with self.assertRaises(NmapXMLParseError):
            parse_nmap_xml("")

    @patch("subprocess.run")
    def test_12_xml_execution_flag_injection(self, mock_run):
        """Verify execute_xml injects '-oX' and '-' into the subprocess command array."""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = SAMPLE_XML_SINGLE_HOST
        mock_process.stderr = ""
        mock_run.return_value = mock_process

        executor = NmapExecutor()
        scan_args = ScanArguments(targets=["127.0.0.1"], nmap_args=["-sV", "-p", "22,80"])
        nmap_res, scan_res = executor.execute_xml(scan_args)

        self.assertIn("-oX", nmap_res.command)
        self.assertIn("-", nmap_res.command)
        self.assertEqual(nmap_res.command, ["nmap", "-sV", "-p", "22,80", "-oX", "-", "127.0.0.1"])
        self.assertEqual(len(scan_res.hosts), 1)

    @patch("subprocess.run")
    def test_13_stdout_stderr_separation(self, mock_run):
        """Verify XML is parsed exclusively from stdout while stderr contains diagnostic logs."""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = SAMPLE_XML_SINGLE_HOST
        mock_process.stderr = "Nmap diagnostic message: Warning: -sV is enabled\n"
        mock_run.return_value = mock_process

        executor = NmapExecutor()
        scan_args = ScanArguments(targets=["127.0.0.1"], nmap_args=["-sV"])
        nmap_res, scan_res = executor.execute_xml(scan_args)

        self.assertEqual(nmap_res.stderr, "Nmap diagnostic message: Warning: -sV is enabled\n")
        self.assertEqual(scan_res.hosts[0].address, "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
