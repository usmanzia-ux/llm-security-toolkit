"""Probe registry. Importing a probe here makes it available to the scanner.

To add a new attack: create ``probes/your_probe.py`` with a Probe subclass and
register its class in ``ALL_PROBES`` below.
"""

from __future__ import annotations

from typing import Dict, List, Type

from .base import Probe
from .insecure_output import InsecureOutputProbe
from .jailbreak import JailbreakProbe
from .prompt_injection import PromptInjectionProbe
from .sensitive_disclosure import SensitiveDisclosureProbe
from .system_prompt_leak import SystemPromptLeakProbe

ALL_PROBES: List[Type[Probe]] = [
    PromptInjectionProbe,
    JailbreakProbe,
    SystemPromptLeakProbe,
    SensitiveDisclosureProbe,
    InsecureOutputProbe,
]

#: probe_id -> Probe class, for selecting a subset on the CLI
REGISTRY: Dict[str, Type[Probe]] = {p.probe_id: p for p in ALL_PROBES}


def select(ids: List[str] | None) -> List[Probe]:
    """Instantiate probes by id, or all of them when ``ids`` is falsy."""
    if not ids:
        return [p() for p in ALL_PROBES]
    chosen: List[Probe] = []
    for pid in ids:
        key = pid.strip().upper()
        if key not in REGISTRY:
            raise KeyError(pid)
        chosen.append(REGISTRY[key]())
    return chosen


__all__ = ["Probe", "ALL_PROBES", "REGISTRY", "select"]
