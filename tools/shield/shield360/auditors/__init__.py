"""Auditor registry. Each auditor is ``audit(ctx) -> list[Finding]``."""
from __future__ import annotations

import threading
from typing import Callable

from ..context import Context
from ..model import Finding, Status, short
from . import firmware, luks, mounts, native, sandbox, sysctl, tpm

AUDITORS: dict[str, Callable[[Context], list[Finding]]] = {
    "firmware": firmware.audit,
    "tpm": tpm.audit,
    "luks": luks.audit,
    "sysctl": sysctl.audit,
    "mounts": mounts.audit,
    "sandbox": sandbox.audit,
    "native": native.audit,
}


def run_auditor(name: str, ctx: Context, timeout: float) -> list[Finding]:
    """Run one auditor in a daemon thread; errors and timeouts become UNKNOWN."""
    box: dict = {}

    def target() -> None:
        try:
            box["result"] = AUDITORS[name](ctx)
        except Exception as exc:  # noqa: BLE001 - reported as UNKNOWN
            box["error"] = f"{type(exc).__name__}: {exc}"

    worker = threading.Thread(target=target, name=f"shield-{name}", daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        return [Finding(f"{name}.timeout", name, f"{name} auditor", Status.UNKNOWN,
                        f"auditor exceeded {timeout:g}s timeout")]
    if "error" in box:
        return [Finding(f"{name}.error", name, f"{name} auditor", Status.UNKNOWN,
                        short("auditor error: " + box["error"]))]
    return box["result"]


def run_all(ctx: Context, names: list[str] | None = None, timeout: float = 10.0) -> list[Finding]:
    findings: list[Finding] = []
    for name in names or list(AUDITORS):
        findings += run_auditor(name, ctx, timeout)
    return findings
