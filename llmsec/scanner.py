"""Scan orchestration: run a set of probes against a target into a ScanReport."""

from __future__ import annotations

from typing import Callable, List, Optional

from .models import ScanReport
from .probes import Probe
from .targets.base import Target


def scan(
    target: Target,
    probes: List[Probe],
    on_probe: Optional[Callable[[Probe], None]] = None,
) -> ScanReport:
    """Run each probe against ``target`` and collect the results.

    ``on_probe`` is an optional progress callback invoked before each probe so a
    CLI can show live status without the scanner depending on any UI library.
    """
    report = ScanReport(target=target.label)
    for probe in probes:
        if on_probe:
            on_probe(probe)
        report.probes.append(probe.run(target))
    report.sort_probes()
    return report
