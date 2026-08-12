"""
SecMap JSON Exporter Module
Serializes normalized ScanReport domain models into valid JSON string output.
Phase 10 implementation.
"""

import json
from secmap_core.normalize.results import HostResult, ScanReport


class JsonExporter:
    """Renders ScanReport models into formatted JSON strings."""

    def render(self, report: ScanReport) -> str:
        """
        Render a ScanReport into a formatted JSON string.

        Args:
            report (ScanReport): SecMap backend-independent scan report.

        Returns:
            str: Pretty-printed JSON string.
        """
        if not report:
            return json.dumps({"targets": [], "hosts": []}, indent=2)

        data = {
            "targets": list(report.targets),
            "summary": {
                "discovered_hosts": report.discovered_hosts_count,
                "hosts_up": report.hosts_up_count,
                "hosts_down": report.hosts_down_count,
                "total_open_ports": report.total_open_ports_count,
                "total_service_instances": report.total_service_instances_count,
                "unique_services": report.unique_services_count,
            },
            "hosts": [self._format_host_dict(host) for host in report.hosts],
        }

        return json.dumps(data, indent=2, ensure_ascii=False)

    def _format_host_dict(self, host: HostResult) -> dict:
        """Convert a HostResult into a JSON-compatible dictionary."""
        host_dict = {
            "address": host.address,
            "address_type": host.address_type,
            "status": host.status,
            "hostname": host.hostname,
            "ports": [],
            "os": None,
            "scripts": [],
        }

        for p in host.ports:
            port_dict = {
                "port": int(p.port),
                "protocol": p.protocol,
                "state": p.state,
                "reason": p.reason,
                "service": None,
                "scripts": [],
            }

            if p.service:
                port_dict["service"] = {
                    "name": p.service.name,
                    "product": p.service.product,
                    "version": p.service.version,
                    "extra_info": p.service.extra_info,
                }

            if p.scripts:
                port_dict["scripts"] = [
                    {"script_id": s.script_id, "output": s.output} for s in p.scripts
                ]

            host_dict["ports"].append(port_dict)

        if host.os and host.os.matches:
            matches_list = []
            for m in host.os.matches:
                m_dict = {
                    "name": m.name,
                    "accuracy": int(m.accuracy) if m.accuracy is not None else None,
                    "cpes": list(m.cpes),
                    "osclasses": [
                        {
                            "vendor": c.vendor,
                            "family": c.family,
                            "generation": c.generation,
                            "type": c.type,
                            "accuracy": int(c.accuracy) if c.accuracy is not None else None,
                            "cpes": list(c.cpes),
                        }
                        for c in m.osclasses
                    ],
                }
                matches_list.append(m_dict)

            host_dict["os"] = {"matches": matches_list}

        if host.scripts:
            host_dict["scripts"] = [
                {"script_id": s.script_id, "output": s.output} for s in host.scripts
            ]

        return host_dict
