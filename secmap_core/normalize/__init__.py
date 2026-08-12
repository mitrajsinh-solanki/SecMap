"""
SecMap Normalization Package
Normalizes raw XML parse models and JSON reports into backend-independent domain objects.
"""

from .json_importer import load_scan_report
from .results import (
    AddressResult,
    HostResult,
    OSClass,
    OSMatch,
    OSResult,
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

__all__ = [
    "ScanReport",
    "HostResult",
    "PortResult",
    "ServiceResult",
    "OSResult",
    "OSMatch",
    "OSClass",
    "ScriptResult",
    "AddressResult",
    "ResultNormalizationError",
    "normalize_scan_result",
    "load_scan_report",
    "get_open_ports",
    "get_services",
    "get_up_hosts",
]
