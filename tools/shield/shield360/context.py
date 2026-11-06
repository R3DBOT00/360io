"""Audit context: filesystem root and command runner injection point."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .utils.fs import read_text
from .utils.proc import CommandRunner


@dataclass
class Context:
    root: Path = Path("/")
    runner: CommandRunner = field(default_factory=CommandRunner)

    def path(self, absolute: str) -> Path:
        return self.root / absolute.lstrip("/")

    def read(self, absolute: str) -> str | None:
        return read_text(self.path(absolute))

    def cpu_vendor(self) -> str | None:
        text = self.read("/proc/cpuinfo")
        if not text:
            return None
        for line in text.splitlines():
            key, _, value = line.partition(":")
            if key.strip() == "vendor_id":
                return value.strip()
        return None

    def cpu_flags(self) -> set[str]:
        text = self.read("/proc/cpuinfo") or ""
        for line in text.splitlines():
            key, _, value = line.partition(":")
            if key.strip() == "flags":
                return set(value.split())
        return set()

    def loaded_modules(self) -> set[str] | None:
        text = self.read("/proc/modules")
        if text is None:
            return None
        return {line.split()[0] for line in text.splitlines() if line.strip()}
