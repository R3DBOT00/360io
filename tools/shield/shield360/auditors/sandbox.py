"""Availability of bubblewrap, seccomp and mat2 (never executes a sandbox)."""
from __future__ import annotations

import os
import stat

from ..context import Context
from ..model import Finding, Status
from ..utils.fs import parse_int, parse_key_values, read_first_line

CATEGORY = "sandbox"


def userns_state(ctx: Context) -> tuple[bool | None, str]:
    max_ns = parse_int(read_first_line(ctx.path("/proc/sys/user/max_user_namespaces")))
    clone = parse_int(read_first_line(ctx.path("/proc/sys/kernel/unprivileged_userns_clone")))
    apparmor = parse_int(read_first_line(
        ctx.path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")))
    parts = [f"max_user_namespaces={max_ns}"]
    if clone is not None:
        parts.append(f"unprivileged_userns_clone={clone}")
    if apparmor is not None:
        parts.append(f"apparmor_restrict_unprivileged_userns={apparmor}")
    if max_ns is None:
        return None, ",".join(parts)
    enabled = max_ns > 0 and clone != 0 and apparmor != 1
    return enabled, ",".join(parts)


def audit_bwrap(ctx: Context) -> Finding:
    fid, title = "sandbox.bubblewrap", "bubblewrap availability"
    exe = ctx.runner.which("bwrap")
    if exe is None:
        return Finding(fid, CATEGORY, title, Status.WARN, "bwrap not found in PATH",
                       "Install bubblewrap to sandbox helpers and untrusted media parsers.")
    try:
        setuid = bool(os.stat(exe).st_mode & stat.S_ISUID)
    except OSError:
        setuid = False
    result = ctx.runner.run("bwrap", "--version")
    version = result.stdout.strip() if result.ok else f"version probe failed ({result.error or result.returncode})"
    userns, userns_ev = userns_state(ctx)
    ev = f"{exe} {version}; setuid={setuid}; {userns_ev}"
    data = {"path": exe, "setuid": setuid, "userns": userns}
    if not result.ok:
        return Finding(fid, CATEGORY, title, Status.UNKNOWN, ev, data=data)
    if setuid or userns:
        return Finding(fid, CATEGORY, title, Status.PASS, ev,
                       "setuid bwrap widens the local attack surface." if setuid else "", data)
    if userns is None:
        return Finding(fid, CATEGORY, title, Status.UNKNOWN, ev, data=data)
    return Finding(fid, CATEGORY, title, Status.WARN, ev,
                   "Unprivileged user namespaces disabled and bwrap is not setuid.", data)


def audit_seccomp(ctx: Context) -> Finding:
    fid, title = "sandbox.seccomp", "seccomp filter support"
    status_text = ctx.read("/proc/self/status")
    if status_text is None:
        return Finding(fid, CATEGORY, title, Status.UNKNOWN, "/proc/self/status unreadable")
    fields = parse_key_values(status_text, ":")
    if "Seccomp" not in fields:
        return Finding(fid, CATEGORY, title, Status.FAIL, "kernel built without CONFIG_SECCOMP")
    actions = read_first_line(ctx.path("/proc/sys/kernel/seccomp/actions_avail"))
    if not actions:
        return Finding(fid, CATEGORY, title, Status.WARN,
                       f"Seccomp={fields['Seccomp']}; actions_avail missing (no filter mode?)")
    needed = {"errno", "kill_process"}
    have = set(actions.split())
    ev = f"Seccomp mode field present; actions: {actions}"
    if needed <= have:
        return Finding(fid, CATEGORY, title, Status.PASS, ev)
    return Finding(fid, CATEGORY, title, Status.WARN, ev + "; missing " + ",".join(sorted(needed - have)))


def audit_mat2(ctx: Context) -> Finding:
    fid, title = "sandbox.mat2", "mat2 metadata removal tool"
    exe = ctx.runner.which("mat2")
    if exe is None:
        return Finding(fid, CATEGORY, title, Status.WARN, "mat2 not found in PATH",
                       "Install mat2 to strip metadata from exported media/screenshots.")
    result = ctx.runner.run("mat2", "--version")
    if not result.ok:
        return Finding(fid, CATEGORY, title, Status.UNKNOWN,
                       f"{exe} version probe failed ({result.error or result.returncode})")
    return Finding(fid, CATEGORY, title, Status.PASS, f"{exe} {result.stdout.strip()}")


def audit(ctx: Context) -> list[Finding]:
    return [audit_bwrap(ctx), audit_seccomp(ctx), audit_mat2(ctx)]
