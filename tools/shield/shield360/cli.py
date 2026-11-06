"""Command line entry point for 360io Shield."""
from __future__ import annotations

import argparse
import datetime
import os
import platform
import sys
from pathlib import Path

from . import __version__
from .auditors import AUDITORS, run_all
from .context import Context
from .model import EXIT_INTERNAL, EXIT_USAGE, exit_code_for
from .reporters import RENDERERS
from .utils.proc import CommandRunner

FORBIDDEN_OUTPUT_PREFIXES = ("/etc", "/proc", "/sys", "/dev", "/boot", "/usr", "/run")

EPILOG = """exit codes:
  0   all findings PASS
  1   worst finding is WARN
  2   at least one FAIL
  3   no WARN/FAIL, at least one UNKNOWN
  64  usage error
  70  internal error
"""


class UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):  # argparse would exit 2, which means FAIL here
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(prog="360io-shield",
                description="Read-only, unprivileged security audit of the 360io host.",
                epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--format", choices=sorted(RENDERERS), default="text")
    p.add_argument("--output", "-o", help="write the report to this file instead of stdout")
    p.add_argument("--only", action="append", choices=sorted(AUDITORS), metavar="AUDITOR",
                   help="run only this auditor (repeatable): " + ", ".join(AUDITORS))
    p.add_argument("--timeout", type=float, default=10.0,
                   help="per-auditor timeout in seconds (default 10)")
    p.add_argument("--command-timeout", type=float, default=5.0,
                   help="timeout for each allowlisted version probe (default 5)")
    p.add_argument("--root", default="/", help=argparse.SUPPRESS)  # fixture trees in tests
    p.add_argument("--list", action="store_true", help="list auditors and exit")
    p.add_argument("--version", action="version", version=f"360io-shield {__version__}")
    return p


def check_output_path(raw: str) -> Path:
    path = Path(os.path.abspath(raw))
    real = Path(os.path.realpath(path))
    for candidate in (str(path), str(real)):
        for prefix in FORBIDDEN_OUTPUT_PREFIXES:
            if candidate == prefix or candidate.startswith(prefix + "/"):
                raise UsageError(f"refusing to write report under {prefix}")
    if real.is_dir():
        raise UsageError(f"{raw} is a directory")
    return path


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list:
        print("\n".join(AUDITORS))
        return 0
    if args.timeout <= 0 or args.command_timeout <= 0:
        print("360io-shield: error: timeouts must be positive", file=sys.stderr)
        return EXIT_USAGE
    try:
        output = check_output_path(args.output) if args.output else None
    except UsageError as exc:
        print(f"360io-shield: error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    if os.geteuid() == 0:
        print("360io-shield: note: root is not required; results are identical unprivileged",
              file=sys.stderr)

    try:
        ctx = Context(root=Path(args.root), runner=CommandRunner(timeout=args.command_timeout))
        findings = run_all(ctx, args.only, args.timeout)
        meta = {
            "version": __version__,
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "host": {"kernel": platform.release(), "uid": os.geteuid()},
        }
        report = RENDERERS[args.format](findings, meta)
    except Exception as exc:  # noqa: BLE001
        print(f"360io-shield: internal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_INTERNAL

    if output is None:
        sys.stdout.write(report)
    else:
        try:
            with open(output, "w", encoding="utf-8") as handle:
                handle.write(report)
        except OSError as exc:
            print(f"360io-shield: error: cannot write {output}: {exc}", file=sys.stderr)
            return EXIT_INTERNAL
    return exit_code_for(findings)
