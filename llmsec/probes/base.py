"""Probe base class. Add an attack = add one Probe subclass in this package.

A probe owns a set of attack prompts and the logic to judge, per prompt,
whether the target was compromised. ``run`` sends each prompt and returns a
single ``ProbeResult`` aggregating the attempts.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from ..models import Attempt, Owasp, ProbeResult, Severity
from ..targets.base import Target, TargetError


class Probe(ABC):
    #: short stable identifier, e.g. "LLM01-PI"
    probe_id: str = "PROBE"
    name: str = "Unnamed probe"
    owasp: Owasp = Owasp.LLM01
    severity: Severity = Severity.MEDIUM
    description: str = ""
    remediation: str = ""
    references: List[str] = []

    @abstractmethod
    def attack_prompts(self) -> List[str]:
        """The prompts this probe will send to the target."""
        raise NotImplementedError

    @abstractmethod
    def judge(self, prompt: str, response: str) -> tuple[bool, str]:
        """Return ``(vulnerable, note)`` for one prompt/response pair."""
        raise NotImplementedError

    def run(self, target: Target) -> ProbeResult:
        attempts: List[Attempt] = []
        for prompt in self.attack_prompts():
            try:
                response = target.ask(prompt)
            except TargetError as exc:
                attempts.append(Attempt(prompt, f"[target error: {exc}]", False, "request failed"))
                continue
            vulnerable, note = self.judge(prompt, response)
            attempts.append(Attempt(prompt, response, vulnerable, note))
        return ProbeResult(
            probe_id=self.probe_id,
            name=self.name,
            owasp=self.owasp,
            severity=self.severity,
            description=self.description,
            remediation=self.remediation,
            references=list(self.references),
            attempts=attempts,
        )
