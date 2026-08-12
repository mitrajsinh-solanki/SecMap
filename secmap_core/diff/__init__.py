"""
SecMap Diff Package
Scan report differencing engine, domain models, and diff renderers.
"""

from .engine import ScanDiffEngine
from .models import (
    DiffSummary,
    HostChange,
    OSChange,
    PortChange,
    ScanDiff,
    ScriptChange,
    ServiceChange,
)
from .renderer import render_diff

__all__ = [
    "ScanDiffEngine",
    "ScanDiff",
    "DiffSummary",
    "HostChange",
    "PortChange",
    "ServiceChange",
    "OSChange",
    "ScriptChange",
    "render_diff",
]
