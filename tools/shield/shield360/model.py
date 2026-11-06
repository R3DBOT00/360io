"""Result model shared by auditors and reporters."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

EVIDENCE_LIMIT = 200


class Status(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


# Documented process exit codes (see docs/shield.md).
EXIT_PASS = 0          # every finding is PASS
EXIT_WARN = 1          # worst finding is WARN
EXIT_FAIL = 2          # at least one FAIL
EXIT_UNKNOWN = 3       # no WARN/FAIL, but at least one UNKNOWN
EXIT_USAGE = 64        # invalid command line (EX_USAGE)
EXIT_INTERNAL = 70     # internal error (EX_SOFTWARE)


def short(text: object, limit: int = EVIDENCE_LIMIT) -> str:
    """Single-line, printable, bounded evidence string."""
    value = "".join(ch if ch.isprintable() else " " for ch in str(text))
    value = " ".join(value.split())
    if len(value) > limit:
        value = value[: limit - 3] + "..."
    return value


@dataclass
class Finding:
    id: str
    category: str
    title: str
    status: Status
    evidence: str
    note: str = ""
    data: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.status = Status(self.status)
        self.evidence = short(self.evidence)
        self.note = short(self.note, 400)

    def to_dict(self) -> dict:
        out = {
            "id": self.id,
            "category": self.category,
            "title": self.title,
            "status": self.status.value,
            "evidence": self.evidence,
        }
        if self.note:
            out["note"] = self.note
        if self.data:
            out["data"] = self.data
        return out


def exit_code_for(findings: list[Finding]) -> int:
    statuses = {f.status for f in findings}
    if Status.FAIL in statuses:
        return EXIT_FAIL
    if Status.WARN in statuses:
        return EXIT_WARN
    if Status.UNKNOWN in statuses:
        return EXIT_UNKNOWN
    return EXIT_PASS


def summarize(findings: list[Finding]) -> dict:
    counts = {s.value: 0 for s in Status}
    for f in findings:
        counts[f.status.value] += 1
    return counts
