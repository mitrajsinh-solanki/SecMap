"""
SecMap Output Renderer Factory Module
Provides output renderer instances based on requested mode (normal, json, csv) and plain flag.
Phase 10 & Phase 11 implementation.
"""

from typing import Protocol
from secmap_core.normalize.results import ScanReport
from secmap_core.output.csv_exporter import CsvExporter
from secmap_core.output.formatter import SecMapFormatter
from secmap_core.output.json_exporter import JsonExporter
from secmap_core.output.rich_renderer import RichRenderer


class OutputRenderer(Protocol):
    """Protocol interface for all SecMap output renderers and exporters."""

    def render(self, report: ScanReport) -> str:
        ...


def get_output_renderer(mode: str = "normal", plain: bool = False) -> OutputRenderer:
    """
    Factory function returning the appropriate output renderer for a given mode.

    Args:
        mode (str): Output mode string ('normal', 'json', 'csv').
        plain (bool): If True, use plain text SecMapFormatter instead of RichRenderer.

    Returns:
        OutputRenderer: Configured exporter or renderer instance.

    Raises:
        ValueError: If mode is unsupported.
    """
    mode_clean = mode.strip().lower() if mode else "normal"

    if mode_clean in ("normal", "text", "terminal"):
        if plain:
            return SecMapFormatter()
        else:
            return RichRenderer()
    elif mode_clean == "json":
        return JsonExporter()
    elif mode_clean == "csv":
        return CsvExporter()
    else:
        raise ValueError(
            f"SecMap Error: Unsupported output format '{mode}'. Supported formats: normal, json, csv."
        )
