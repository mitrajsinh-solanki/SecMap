"""
SecMap XML Parser Engine
Parses Nmap XML stdout payloads into structured Python data models using xml.etree.ElementTree.
Phase 4, 5 & 7 implementation.
"""

import xml.etree.ElementTree as ET
from secmap_core.parser.models import (
    Host,
    OSClassNode,
    OSMatchNode,
    Port,
    ScanResult,
    ScriptNode,
    Service,
)


class NmapXMLParseError(ValueError):
    """Raised when Nmap XML stream cannot be parsed or is malformed."""

    pass


def parse_nmap_xml(xml_text: str) -> ScanResult:
    """
    Parse an Nmap raw XML string into a structured ScanResult object.

    Args:
        xml_text (str): Raw XML payload captured from Nmap stdout.

    Returns:
        ScanResult: Structured data model containing parsed hosts, ports, services, OS, and scripts.

    Raises:
        NmapXMLParseError: If xml_text is empty or contains malformed XML syntax.
    """
    if not xml_text or not xml_text.strip():
        raise NmapXMLParseError("SecMap Error: Empty Nmap XML output received.")

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        raise NmapXMLParseError(f"SecMap Error: Failed to parse Nmap XML output: {str(e)}")

    if root.tag != "nmaprun":
        raise NmapXMLParseError(f"SecMap Error: Expected root element <nmaprun>, got <{root.tag}>.")

    scanner = root.get("scanner")
    scanner_version = root.get("version")
    args = root.get("args")

    hosts: list[Host] = []

    for host_elem in root.findall("host"):
        # Extract status
        status_elem = host_elem.find("status")
        status = status_elem.get("state") if status_elem is not None else None

        # Extract address
        address = None
        address_type = "ipv4"
        for addr_elem in host_elem.findall("address"):
            curr_type = addr_elem.get("addrtype", "ipv4")
            if curr_type in ("ipv4", "ipv6") or address is None:
                address = addr_elem.get("addr")
                address_type = curr_type

        # Extract hostname
        hostname = None
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            hostname_elem = hostnames_elem.find("hostname")
            if hostname_elem is not None:
                hostname = hostname_elem.get("name")

        # Extract OS matches, OS classes, and CPEs
        os_matches: list[OSMatchNode] = []
        os_elem = host_elem.find("os")
        if os_elem is not None:
            for osmatch_elem in os_elem.findall("osmatch"):
                name = osmatch_elem.get("name")
                if name:
                    acc_str = osmatch_elem.get("accuracy")
                    acc = int(acc_str) if acc_str and acc_str.isdigit() else None

                    match_cpes = [cpe_e.text.strip() for cpe_e in osmatch_elem.findall("cpe") if cpe_e.text]
                    osclasses: list[OSClassNode] = []

                    for osclass_elem in osmatch_elem.findall("osclass"):
                        cls_acc_str = osclass_elem.get("accuracy")
                        cls_acc = int(cls_acc_str) if cls_acc_str and cls_acc_str.isdigit() else None
                        cls_cpes = [cpe_e.text.strip() for cpe_e in osclass_elem.findall("cpe") if cpe_e.text]

                        # Accumulate CPEs to match level as well
                        for c in cls_cpes:
                            if c not in match_cpes:
                                match_cpes.append(c)

                        osclasses.append(
                            OSClassNode(
                                type=osclass_elem.get("type"),
                                vendor=osclass_elem.get("vendor"),
                                osfamily=osclass_elem.get("osfamily"),
                                osgen=osclass_elem.get("osgen"),
                                accuracy=cls_acc,
                                cpe=cls_cpes,
                            )
                        )

                    os_matches.append(
                        OSMatchNode(
                            name=name,
                            accuracy=acc,
                            line=osmatch_elem.get("line"),
                            osclasses=osclasses,
                            cpes=match_cpes,
                        )
                    )

        # Extract host-level script outputs
        host_scripts: list[ScriptNode] = []
        hostscript_elem = host_elem.find("hostscript")
        if hostscript_elem is not None:
            for script_elem in hostscript_elem.findall("script"):
                script_id = script_elem.get("id")
                if script_id:
                    host_scripts.append(ScriptNode(id=script_id, output=script_elem.get("output")))

        # Extract ports
        ports: list[Port] = []
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                try:
                    portid = int(port_elem.get("portid"))
                except (TypeError, ValueError):
                    continue

                protocol = port_elem.get("protocol", "tcp")

                state_elem = port_elem.find("state")
                state = state_elem.get("state") if state_elem is not None else None
                reason = state_elem.get("reason") if state_elem is not None else None

                service = None
                service_elem = port_elem.find("service")
                if service_elem is not None:
                    service = Service(
                        name=service_elem.get("name"),
                        product=service_elem.get("product"),
                        version=service_elem.get("version"),
                        extrainfo=service_elem.get("extrainfo"),
                    )

                port_scripts: list[ScriptNode] = []
                for script_elem in port_elem.findall("script"):
                    script_id = script_elem.get("id")
                    if script_id:
                        port_scripts.append(ScriptNode(id=script_id, output=script_elem.get("output")))

                ports.append(
                    Port(
                        portid=portid,
                        protocol=protocol,
                        state=state,
                        reason=reason,
                        service=service,
                        scripts=port_scripts,
                    )
                )

        hosts.append(
            Host(
                address=address,
                address_type=address_type,
                status=status,
                hostname=hostname,
                ports=ports,
                os_matches=os_matches,
                scripts=host_scripts,
            )
        )

    return ScanResult(
        hosts=hosts,
        scanner=scanner,
        scanner_version=scanner_version,
        args=args,
    )
