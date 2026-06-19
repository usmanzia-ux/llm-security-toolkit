"""JSON reporter — machine-readable output for pipelines and diffing."""

from __future__ import annotations

import json

from ..models import ScanReport


def render(report: ScanReport, output: str) -> str:
    with open(output, "w", encoding="utf-8") as fh:
        json.dump(report.to_dict(), fh, indent=2, ensure_ascii=False)
    return output
