"""Normalised data model shared by every probe, target and reporter."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional


class Severity(str, Enum):
    """Ordered severity levels (highest first when sorted by ``rank``)."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"

    @property
    def rank(self) -> int:
        order = {
            "Critical": 0,
            "High": 1,
            "Medium": 2,
            "Low": 3,
            "Informational": 4,
        }
        return order[self.value]


class Owasp(str, Enum):
    """OWASP Top 10 for LLM Applications (2025) categories."""

    LLM01 = "LLM01:2025 Prompt Injection"
    LLM02 = "LLM02:2025 Sensitive Information Disclosure"
    LLM03 = "LLM03:2025 Supply Chain"
    LLM04 = "LLM04:2025 Data and Model Poisoning"
    LLM05 = "LLM05:2025 Improper Output Handling"
    LLM06 = "LLM06:2025 Excessive Agency"
    LLM07 = "LLM07:2025 System Prompt Leakage"
    LLM08 = "LLM08:2025 Vector and Embedding Weaknesses"
    LLM09 = "LLM09:2025 Misinformation"
    LLM10 = "LLM10:2025 Unbounded Consumption"


@dataclass
class Attempt:
    """A single attack prompt sent to the target and the model's response."""

    prompt: str
    response: str
    vulnerable: bool
    note: str = ""

    def snippet(self, limit: int = 400) -> str:
        r = self.response.strip().replace("\n", " ")
        return (r[:limit] + "…") if len(r) > limit else r


@dataclass
class ProbeResult:
    """The outcome of running one probe against the target."""

    probe_id: str
    name: str
    owasp: Owasp
    severity: Severity
    description: str
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    attempts: List[Attempt] = field(default_factory=list)

    @property
    def vulnerable(self) -> bool:
        return any(a.vulnerable for a in self.attempts)

    @property
    def vulnerable_attempts(self) -> List[Attempt]:
        return [a for a in self.attempts if a.vulnerable]

    @property
    def status(self) -> str:
        return "VULNERABLE" if self.vulnerable else "passed"

    @property
    def effective_severity(self) -> Severity:
        """Severity only counts when the probe actually fired."""
        return self.severity if self.vulnerable else Severity.INFO

    def to_dict(self) -> dict:
        d = asdict(self)
        d["owasp"] = self.owasp.value
        d["severity"] = self.severity.value
        d["vulnerable"] = self.vulnerable
        d["status"] = self.status
        return d


@dataclass
class ScanReport:
    """A full scan: metadata + every probe result."""

    target: str
    probes: List[ProbeResult] = field(default_factory=list)
    assessor: str = "Usman Zia"
    scanned_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    standard: str = "OWASP Top 10 for LLM Applications (2025)"

    def sort_probes(self) -> None:
        """Vulnerable first, then by severity (Critical first)."""
        self.probes.sort(key=lambda p: (not p.vulnerable, p.severity.rank))

    @property
    def vulnerable_count(self) -> int:
        return sum(1 for p in self.probes if p.vulnerable)

    def severity_counts(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for p in self.probes:
            if p.vulnerable:
                counts[p.severity.value] += 1
        return counts

    def posture(self) -> str:
        """Overall posture based on the worst confirmed finding."""
        c = self.severity_counts()
        if c["Critical"]:
            return "Critical"
        if c["High"]:
            return "High"
        if c["Medium"]:
            return "Medium"
        if c["Low"]:
            return "Low"
        return "Pass"

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "assessor": self.assessor,
            "scanned_at": self.scanned_at,
            "standard": self.standard,
            "posture": self.posture(),
            "severity_counts": self.severity_counts(),
            "vulnerable_count": self.vulnerable_count,
            "total_probes": len(self.probes),
            "probes": [p.to_dict() for p in self.probes],
        }
