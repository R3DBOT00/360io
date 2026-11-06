"""Allowlisted, time-bounded execution of read-only commands.

Only the exact argument vectors in ``ALLOWED_COMMANDS`` may run. There is no
shell, stdin is closed and the locale is fixed, so output parsing is stable.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass

DEFAULT_TIMEOUT = 5.0

# (program, *args) tuples. Each one only prints version information.
ALLOWED_COMMANDS = frozenset({
    ("bwrap", "--version"),
    ("mat2", "--version"),
})


class CommandNotAllowed(Exception):
    pass


@dataclass
class CommandResult:
    argv: tuple[str, ...]
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.error


class CommandRunner:
    def __init__(self, path_env: str | None = None, timeout: float = DEFAULT_TIMEOUT):
        self.path_env = path_env if path_env is not None else os.environ.get("PATH", "")
        self.timeout = timeout

    def which(self, program: str) -> str | None:
        return shutil.which(program, path=self.path_env)

    def run(self, *argv: str) -> CommandResult:
        if tuple(argv) not in ALLOWED_COMMANDS:
            raise CommandNotAllowed(" ".join(argv))
        exe = self.which(argv[0])
        if exe is None:
            return CommandResult(tuple(argv), None, error="not found")
        env = {"PATH": self.path_env, "LC_ALL": "C", "LANG": "C"}
        try:
            proc = subprocess.run(
                [exe, *argv[1:]],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=self.timeout,
                env=env,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            return CommandResult(tuple(argv), None, timed_out=True, error="timeout")
        except OSError as exc:
            return CommandResult(tuple(argv), None, error=str(exc))
        return CommandResult(
            tuple(argv),
            proc.returncode,
            proc.stdout.decode("utf-8", "replace")[:8192],
            proc.stderr.decode("utf-8", "replace")[:8192],
        )
