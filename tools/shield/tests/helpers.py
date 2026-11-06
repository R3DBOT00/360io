"""Fixture-tree builder and fake command runner for Shield tests."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
sys.path.insert(0, str(HERE.parent))

from shield360.context import Context  # noqa: E402
from shield360.utils.proc import ALLOWED_COMMANDS, CommandNotAllowed, CommandResult  # noqa: E402


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


class FakeRunner:
    """Mimics CommandRunner without spawning processes."""

    def __init__(self, programs: dict[str, CommandResult] | None = None):
        self.programs = programs or {}
        self.calls: list[tuple[str, ...]] = []

    def which(self, program: str) -> str | None:
        return f"/fake/bin/{program}" if program in self.programs else None

    def run(self, *argv: str) -> CommandResult:
        if tuple(argv) not in ALLOWED_COMMANDS:
            raise CommandNotAllowed(" ".join(argv))
        self.calls.append(tuple(argv))
        return self.programs[argv[0]]


def ok(stdout: str) -> CommandResult:
    return CommandResult(("x",), 0, stdout)


class TreeCase(unittest.TestCase):
    """Each test gets an empty fake root; ``put`` populates it."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="shield-test-")
        self.root = Path(self._tmp.name)
        self.runner = FakeRunner()
        self.ctx = Context(root=self.root, runner=self.runner)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def put(self, path: str, content: str = "") -> Path:
        target = self.root / path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        return target

    def mkdir(self, path: str) -> Path:
        target = self.root / path.lstrip("/")
        target.mkdir(parents=True, exist_ok=True)
        return target

    def block(self, name: str, dev: str, dm_name: str | None = None, dm_uuid: str | None = None,
              slaves: tuple[str, ...] = ()) -> None:
        base = f"/sys/class/block/{name}"
        self.put(f"{base}/dev", dev + "\n")
        if dm_name is not None:
            self.put(f"{base}/dm/name", dm_name + "\n")
            self.put(f"{base}/dm/uuid", (dm_uuid or "") + "\n")
        self.mkdir(f"{base}/slaves")
        for slave in slaves:
            self.mkdir(f"{base}/slaves/{slave}")
