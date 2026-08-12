"""
SecMap JSON Scan Report Importer Module
Parses historical SecMap JSON report files into typed ScanReport domain objects.
Phase 15 implementation.
"""

import json
import pathlib
from secmap_core.cli import CLIError
from secmap_core.normalize.results import (
    AddressResult,
    HostResult,
    OSClass,
    OSMatch,
    OSResult,
    PortResult,
    ScanReport,
    ScriptResult,
    ServiceResult,
)


def load_scan_report(path: pathlib.Path | str) -> ScanReport:
    """
    Load and parse a SecMap JSON report file into a ScanReport domain object.

    Args:
        path (pathlib.Path | str): Path to SecMap JSON scan report file.

    Returns:
        ScanReport: Reconstructed ScanReport model.

    Raises:
        CLIError: If file is missing, invalid JSON, or malformed schema.
    """
    file_path = pathlib.Path(path)
    if not file_path.exists():
        raise CLIError(f"SecMap Error: Report file '{file_path}' does not exist.")

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        raise CLIError(f"SecMap Error: Failed to parse JSON report file '{file_path}': {str(e)}")

    if not isinstance(data, dict):
        raise CLIError(f"SecMap Error: Invalid scan report schema in '{file_path}'. Root element must be a JSON object.")

    targets = data.get("targets", [])
    if not isinstance(targets, list):
        targets = []

    hosts_raw = data.get("hosts", [])
    if not isinstance(hosts_raw, list):
        raise CLIError(f"SecMap Error: Invalid scan report schema in '{file_path}'. 'hosts' must be a JSON array.")

    hosts = []
    for h_dict in hosts_raw:
        if not isinstance(h_dict, dict):
            continue

        addr = h_dict.get("address", "")
        addr_type = h_dict.get("address_type", "ipv4")
        status = h_dict.get("status", "unknown")
        hostname = h_dict.get("hostname")

        ports = []
        for p_dict in h_dict.get("ports", []):
            if not isinstance(p_dict, dict):
                continue

            port_num = p_dict.get("port")
            if not isinstance(port_num, int):
                try:
                    port_num = int(port_num)
                except (ValueError, TypeError):
                    continue

            proto = p_dict.get("protocol", "tcp")
            state = p_dict.get("state", "closed")
            reason = p_dict.get("reason")

            svc = None
            svc_dict = p_dict.get("service")
            if isinstance(svc_dict, dict):
                svc = ServiceResult(
                    name=svc_dict.get("name"),
                    product=svc_dict.get("product"),
                    version=svc_dict.get("version"),
                    extra_info=svc_dict.get("extra_info"),
                )

            port_scripts = []
            for s_dict in p_dict.get("scripts", []):
                if isinstance(s_dict, dict) and s_dict.get("script_id"):
                    port_scripts.append(
                        ScriptResult(
                            script_id=str(s_dict.get("script_id")),
                            output=str(s_dict.get("output", "")),
                        )
                    )

            ports.append(
                PortResult(
                    port=port_num,
                    protocol=proto,
                    state=state,
                    reason=reason,
                    service=svc,
                    scripts=port_scripts,
                )
            )

        os_result = None
        os_dict = h_dict.get("os")
        if isinstance(os_dict, dict) and os_dict.get("matches"):
            matches = []
            for m_dict in os_dict.get("matches", []):
                if not isinstance(m_dict, dict):
                    continue
                acc = m_dict.get("accuracy")
                if acc is not None:
                    try:
                        acc = int(acc)
                    except (ValueError, TypeError):
                        acc = None

                cpes = list(m_dict.get("cpes", []))
                osclasses = []
                for c_dict in m_dict.get("osclasses", []):
                    if isinstance(c_dict, dict):
                        osclasses.append(
                            OSClass(
                                vendor=c_dict.get("vendor"),
                                family=c_dict.get("family"),
                                generation=c_dict.get("generation"),
                                type=c_dict.get("type"),
                                accuracy=c_dict.get("accuracy"),
                                cpes=list(c_dict.get("cpes", [])),
                            )
                        )

                matches.append(
                    OSMatch(
                        name=str(m_dict.get("name", "Unknown OS")),
                        accuracy=acc,
                        cpes=cpes,
                        osclasses=osclasses,
                    )
                )

            if matches:
                os_result = OSResult(matches=matches)

        host_scripts = []
        for s_dict in h_dict.get("scripts", []):
            if isinstance(s_dict, dict) and s_dict.get("script_id"):
                host_scripts.append(
                    ScriptResult(
                        script_id=str(s_dict.get("script_id")),
                        output=str(s_dict.get("output", "")),
                    )
                )

        hosts.append(
            HostResult(
                address=addr,
                address_type=addr_type,
                status=status,
                hostname=hostname,
                ports=ports,
                os=os_result,
                scripts=host_scripts,
            )
        )

    return ScanReport(targets=targets, hosts=hosts)
