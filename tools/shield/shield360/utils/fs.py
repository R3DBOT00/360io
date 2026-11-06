"""Read-only filesystem helpers rooted at an overridable prefix.

Every host path is resolved through ``Context.path`` so tests can point the
auditors at a fixture tree. Nothing in this module opens files for writing.
"""
from __future__ import annotations

import os
from pathlib import Path

MAX_READ = 256 * 1024


def read_text(path: Path, limit: int = MAX_READ) -> str | None:
    """Return up to ``limit`` bytes decoded as UTF-8, or None when unreadable."""
    try:
        with open(path, "rb") as handle:
            data = handle.read(limit)
    except (OSError, ValueError):
        return None
    return data.decode("utf-8", errors="replace")


def read_bytes(path: Path, limit: int = MAX_READ) -> bytes | None:
    """Return up to ``limit`` raw bytes, or None when unreadable."""
    try:
        with open(path, "rb") as handle:
            return handle.read(limit)
    except (OSError, ValueError):
        return None


def read_first_line(path: Path) -> str | None:
    text = read_text(path, 4096)
    if text is None:
        return None
    return text.strip().splitlines()[0].strip() if text.strip() else ""


def list_dir(path: Path) -> list[str]:
    try:
        return sorted(os.listdir(path))
    except OSError:
        return []


def read_link_name(path: Path) -> str | None:
    try:
        return os.path.basename(os.readlink(path))
    except OSError:
        return None


def parse_key_values(text: str, sep: str = "=") -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        if sep not in line:
            continue
        key, _, value = line.partition(sep)
        out[key.strip()] = value.strip()
    return out


def parse_int(text: str | None) -> int | None:
    if text is None:
        return None
    try:
        return int(text.split()[0])
    except (ValueError, IndexError):
        return None
