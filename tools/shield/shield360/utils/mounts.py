"""Parser for /proc/self/mountinfo (proc(5))."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_ESCAPE = re.compile(r"\\([0-7]{3})")


def unescape(value: str) -> str:
    return _ESCAPE.sub(lambda m: chr(int(m.group(1), 8)), value)


@dataclass
class Mount:
    mount_id: int
    parent_id: int
    major_minor: str
    mountpoint: str
    options: set[str]
    fstype: str
    source: str
    super_options: set[str] = field(default_factory=set)

    @property
    def all_options(self) -> set[str]:
        return self.options | self.super_options


def parse_mountinfo(text: str) -> list[Mount]:
    mounts: list[Mount] = []
    for line in text.splitlines():
        left, sep, right = line.partition(" - ")
        if not sep:
            continue
        lf = left.split()
        rf = right.split()
        if len(lf) < 6 or len(rf) < 2:
            continue
        try:
            mount_id, parent_id = int(lf[0]), int(lf[1])
        except ValueError:
            continue
        mounts.append(Mount(
            mount_id=mount_id,
            parent_id=parent_id,
            major_minor=lf[2],
            mountpoint=unescape(lf[4]),
            options=set(lf[5].split(",")),
            fstype=rf[0],
            source=unescape(rf[1]),
            super_options=set(rf[2].split(",")) if len(rf) > 2 else set(),
        ))
    return mounts


def effective_mounts(mounts: list[Mount]) -> dict[str, Mount]:
    """Map each mountpoint to its visible (top-most) mount."""
    by_point: dict[str, list[Mount]] = {}
    for m in mounts:
        by_point.setdefault(m.mountpoint, []).append(m)
    result: dict[str, Mount] = {}
    for point, stack in by_point.items():
        ids = {m.mount_id for m in stack}
        # A mount stacked over another at the same point has it as parent.
        covered = {m.parent_id for m in stack if m.parent_id in ids}
        top = [m for m in stack if m.mount_id not in covered]
        result[point] = top[-1] if top else stack[-1]
    return result
