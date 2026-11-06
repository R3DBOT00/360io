"""Kernel hardening sysctls, read from /proc/sys."""
from __future__ import annotations

from dataclasses import dataclass

from ..context import Context
from ..model import Finding, Status
from ..utils.fs import parse_int, read_first_line

CATEGORY = "sysctl"


@dataclass(frozen=True)
class Rule:
    key: str
    minimum: int
    recommended: int
    severity: Status  # status when below minimum
    title: str
    exact: bool = False  # value must equal recommended (e.g. suid_dumpable=0)
    optional: bool = False  # key may legitimately be absent


RULES = (
    Rule("kernel.kptr_restrict", 1, 2, Status.FAIL, "Hide kernel pointers"),
    Rule("kernel.dmesg_restrict", 1, 1, Status.WARN, "Restrict dmesg to privileged users"),
    Rule("kernel.unprivileged_bpf_disabled", 1, 2, Status.FAIL, "Disable unprivileged eBPF"),
    Rule("net.core.bpf_jit_harden", 1, 2, Status.WARN, "Harden BPF JIT"),
    Rule("kernel.yama.ptrace_scope", 1, 2, Status.WARN, "Restrict ptrace (Yama)", optional=True),
    Rule("kernel.kexec_load_disabled", 1, 1, Status.WARN, "Disable kexec_load"),
    Rule("kernel.randomize_va_space", 2, 2, Status.FAIL, "Full ASLR"),
    Rule("kernel.perf_event_paranoid", 2, 3, Status.WARN, "Restrict perf events"),
    Rule("fs.protected_symlinks", 1, 1, Status.FAIL, "Protected symlinks"),
    Rule("fs.protected_hardlinks", 1, 1, Status.FAIL, "Protected hardlinks"),
    Rule("fs.protected_fifos", 1, 2, Status.WARN, "Protected FIFOs"),
    Rule("fs.protected_regular", 1, 2, Status.WARN, "Protected regular files"),
    Rule("fs.suid_dumpable", 0, 0, Status.WARN, "No core dumps of setuid processes", exact=True),
    Rule("net.ipv4.tcp_syncookies", 1, 1, Status.WARN, "TCP SYN cookies"),
    Rule("net.ipv4.conf.all.rp_filter", 1, 1, Status.WARN, "Reverse path filtering"),
    Rule("net.ipv4.conf.all.accept_redirects", 0, 0, Status.WARN, "Ignore ICMP redirects", exact=True),
    Rule("net.ipv4.conf.all.send_redirects", 0, 0, Status.WARN, "Do not send ICMP redirects", exact=True),
    Rule("net.ipv4.conf.all.accept_source_route", 0, 0, Status.WARN, "Reject source routing", exact=True),
)


def read_sysctl(ctx: Context, key: str) -> str | None:
    return read_first_line(ctx.path("/proc/sys/" + key.replace(".", "/")))


def evaluate(rule: Rule, raw: str | None) -> tuple[Status, str]:
    if raw is None:
        if rule.optional:
            return Status.WARN, f"{rule.key} absent (feature not built or LSM disabled)"
        return Status.UNKNOWN, f"{rule.key} unreadable"
    value = parse_int(raw)
    if value is None:
        return Status.UNKNOWN, f"{rule.key}={raw!r} not an integer"
    ev = f"{rule.key}={value} (recommended {rule.recommended})"
    if rule.exact:
        return (Status.PASS if value == rule.recommended else rule.severity), ev
    if value < rule.minimum:
        return rule.severity, ev
    if value < rule.recommended:
        return Status.PASS, ev + "; acceptable"
    return Status.PASS, ev


def audit(ctx: Context) -> list[Finding]:
    findings = []
    for rule in RULES:
        raw = read_sysctl(ctx, rule.key)
        status, ev = evaluate(rule, raw)
        if raw is None and ctx.path("/proc/sys/" + rule.key.replace(".", "/")).exists():
            status, ev = Status.UNKNOWN, f"{rule.key} exists but is not readable unprivileged"
        findings.append(Finding(f"sysctl.{rule.key}", CATEGORY, rule.title, status, ev))
    return findings
