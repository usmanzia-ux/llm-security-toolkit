"""Reporter registry + factory. Add an output format = add one module here."""

from __future__ import annotations

from ..models import ScanReport
from . import json_report, markdown

FORMATS = ("markdown", "json")
_EXT = {"markdown": ".md", "json": ".json"}


def extension(fmt: str) -> str:
    return _EXT[fmt]


def render(report: ScanReport, fmt: str, output: str) -> str:
    if fmt == "markdown":
        return markdown.render(report, output)
    if fmt == "json":
        return json_report.render(report, output)
    raise ValueError(f"unknown format '{fmt}'. Choose from: {', '.join(FORMATS)}")


__all__ = ["FORMATS", "render", "extension"]
