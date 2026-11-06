"""Explicit native (unsandboxed) exceptions: 360io-desktop and recovery mode.

A native exception is declared by a JSON manifest installed under
``share/360io/shield/native-exceptions/``. The audit is static only: it proves
from installed files that the desktop entry, scripts and systemd units run
the declared programs directly (no bwrap, flatpak, container, namespace or VM
layer). It never inspects or reports whether anything is running.
"""
from __future__ import annotations

import json
import os
import re
import shlex

from ..context import Context
from ..model import Finding, Status, short
from ..utils.fs import list_dir, read_bytes

CATEGORY = "native"
MANIFEST_DIRS = ("/usr/share/360io/shield/native-exceptions",
                 "/usr/local/share/360io/shield/native-exceptions")
APPLICATION_DIRS = ("/usr/share/applications", "/usr/local/share/applications")
EXCEPTION_KEY = "X-360io-Shield-Exception"
MAX_ENTRIES = 4096
MAX_LISTED = 32
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
FIELD_CODE_RE = re.compile(r"^%[fFuUdDnNickvm]$")
COMMENT_RE = re.compile(r"(^|\s)#.*$")
RUNTIME_NOTE = "static check, runtime state not inspected"

# Programs that confine, relocate or re-namespace a child process, or run it
# in a container/VM.
SANDBOX_WRAPPERS = frozenset({
    "bwrap", "bubblewrap", "flatpak", "flatpak-spawn", "firejail", "nsjail", "minijail0",
    "unshare", "nsenter", "systemd-nspawn", "systemd-run", "podman", "docker", "toolbox",
    "distrobox", "distrobox-enter", "distrobox-host-exec", "host-spawn", "apptainer",
    "singularity", "snap", "lxc-execute", "chroot", "proot", "sandbox-exec", "aa-exec",
    "qemu-system-x86_64", "qemu-kvm", "virsh", "vmrun", "VBoxManage", "crosvm", "firecracker",
})
SANDBOX_KEYS = ("X-Flatpak", "X-Flatpak-RenamedFrom", "X-SnapInstanceName")
# systemd directives that put the service into its own namespace(s) or root.
UNIT_ISOLATION = frozenset({
    "PrivateTmp", "PrivateDevices", "PrivateNetwork", "PrivateUsers", "PrivateIPC",
    "PrivateMounts", "ProtectSystem", "ProtectHome", "ProtectHostname", "ProtectKernelTunables",
    "ProtectKernelModules", "ProtectKernelLogs", "ProtectControlGroups", "ProtectClock",
    "ProtectProc", "RootDirectory", "RootImage", "MountAPIVFS", "NetworkNamespacePath",
    "IPCNamespacePath", "TemporaryFileSystem", "BindPaths", "BindReadOnlyPaths",
    "ReadOnlyPaths", "InaccessiblePaths", "ReadWritePaths", "DynamicUser",
})
EXEC_KEYS = ("ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost",
             "ExecReload", "ExecCondition")


def parse_desktop_entry(text: str) -> dict[str, str]:
    """Unlocalized keys of the [Desktop Entry] group (first value wins)."""
    values: dict[str, str] = {}
    in_main = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            in_main = line == "[Desktop Entry]"
            continue
        if in_main and "=" in line:
            key, _, value = line.partition("=")
            values.setdefault(key.strip(), value.strip())
    return values


def parse_action_execs(text: str) -> dict[str, str]:
    """Exec values of the [Desktop Action *] groups (first value wins)."""
    execs: dict[str, str] = {}
    group = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            group = line[16:-1] if line.startswith("[Desktop Action ") else None
            continue
        if group is not None and "=" in line:
            key, _, value = line.partition("=")
            if key.strip() == "Exec":
                execs.setdefault(group, value.strip())
    return execs


def exec_argv(exec_value: str) -> list[str] | None:
    """Tokenize Exec per the Desktop Entry quoting rules; field codes dropped."""
    try:
        argv = shlex.split(exec_value.replace("%%", "%"), posix=True)
    except ValueError:
        return None
    return [arg for arg in argv if not FIELD_CODE_RE.match(arg)]


def wrapper_tokens(argv: list[str]) -> list[str]:
    return sorted({os.path.basename(arg) for arg in argv} & SANDBOX_WRAPPERS)


def script_wrappers(text: str) -> list[str]:
    """Wrapper names used as words on non-comment lines of a shell script."""
    found: set[str] = set()
    for line in text.splitlines():
        code = COMMENT_RE.sub("", line)
        words = re.findall(r"(?<![\w$./-])[A-Za-z0-9_.-]+(?![\w-])",
                           code.replace("/", " "))
        found |= set(words) & SANDBOX_WRAPPERS
    return sorted(found)


def unit_problems(text: str) -> list[str]:
    problems: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#;[" or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if key in UNIT_ISOLATION and value.lower() not in ("", "no", "false", "0", "off"):
            problems.add(f"{key}=")
        if key in EXEC_KEYS:
            try:
                argv = shlex.split(value.lstrip("-+!@:|"), posix=True)
            except ValueError:
                problems.add(f"unparseable {key}")
                continue
            problems.update(wrapper_tokens(argv))
    return sorted(problems)


def load_manifests(ctx: Context) -> tuple[list[tuple[str, dict]], list[Finding]]:
    manifests: list[tuple[str, dict]] = []
    problems: list[Finding] = []
    for directory in MANIFEST_DIRS:
        for name in list_dir(ctx.path(directory))[:MAX_ENTRIES]:
            if not name.endswith(".json"):
                continue
            path = f"{directory}/{name}"
            text = ctx.read(path)
            try:
                data = json.loads(text) if text is not None else None
            except ValueError:
                data = None
            if not isinstance(data, dict):
                problems.append(Finding(f"native.manifest.{name[:-5]}", CATEGORY,
                                        f"native exception manifest {name}", Status.UNKNOWN,
                                        f"{path}: unreadable or not a JSON object"))
                continue
            manifests.append((path, data))
    return manifests, problems


def find_desktop_entry(ctx: Context, entry_id: str) -> tuple[str, str] | None:
    for directory in APPLICATION_DIRS:
        path = f"{directory}/{entry_id}"
        text = ctx.read(path)
        if text is not None:
            return path, text
    return None


def path_list(manifest: dict, key: str) -> list[str] | None:
    value = manifest.get(key, [])
    if (not isinstance(value, list) or len(value) > MAX_LISTED
            or not all(isinstance(p, str) and os.path.isabs(p) for p in value)):
        return None
    return value


def manifest_problems(manifest: dict, exc_id: str, raw_id: str) -> list[str]:
    problems = []
    if exc_id == "invalid":
        problems.append(f"invalid id {short(raw_id, 40)!r}")
    if manifest.get("kind") != "native-exception":
        problems.append("kind is not native-exception")
    if manifest.get("sandbox") != "none":
        problems.append(f"sandbox={manifest.get('sandbox')!r}, expected 'none'")
    binary = manifest.get("binary")
    if not isinstance(binary, str) or not os.path.isabs(binary):
        problems.append("binary is not an absolute path")
    entry_id = manifest.get("desktop_entry")
    if entry_id is not None and (not isinstance(entry_id, str) or "/" in entry_id
                                 or not entry_id.endswith(".desktop")):
        problems.append("desktop_entry is not a desktop-file ID")
    for key in ("scripts", "units"):
        if path_list(manifest, key) is None:
            problems.append(f"{key} is not a list of absolute paths")
    return problems


def check_desktop_entry(ctx: Context, exc_id: str, entry_id: str, binary: str,
                        data: dict, fails: list[str], warns: list[str]) -> str:
    found = find_desktop_entry(ctx, entry_id)
    if found is None:
        warns.append(f"{entry_id} not installed in {', '.join(APPLICATION_DIRS)}")
        return f"{entry_id} missing"
    entry_path, entry_text = found
    entry = parse_desktop_entry(entry_text)
    exec_value = entry.get("Exec", "")
    data.update(desktop_entry_path=entry_path, exec=exec_value)
    argv = exec_argv(exec_value)
    if not argv:
        fails.append("Exec missing or unparseable")
    else:
        wrappers = wrapper_tokens(argv)
        if wrappers:
            fails.append("Exec uses sandbox wrapper " + ",".join(wrappers))
        if argv[0] != binary:
            fails.append(f"Exec runs {short(argv[0], 60)} instead of {binary}")
    for action, action_exec in parse_action_execs(entry_text).items():
        action_argv = exec_argv(action_exec)
        if not action_argv:
            fails.append(f"action {action} Exec unparseable")
            continue
        wrappers = wrapper_tokens(action_argv)
        if wrappers:
            fails.append(f"action {action} Exec uses sandbox wrapper " + ",".join(wrappers))
        if action_argv[0] != binary:
            fails.append(f"action {action} Exec runs {short(action_argv[0], 60)} instead of {binary}")
    sandbox_keys = [key for key in SANDBOX_KEYS if key in entry]
    if sandbox_keys:
        fails.append("sandboxed-app keys " + ",".join(sandbox_keys))
    if entry.get(EXCEPTION_KEY) != exc_id:
        warns.append(f"{EXCEPTION_KEY} does not reference {exc_id}")
    return f"{entry_path} Exec={short(exec_value, 60)}"


def check_program(ctx: Context, path: str, fails: list[str], warns: list[str]) -> str:
    """Classifies a declared program and scans scripts for wrapper use."""
    header = read_bytes(ctx.path(path), 256 * 1024)
    if header is None:
        warns.append(f"{path} not installed or unreadable")
        return "missing"
    if header.startswith(b"\x7fELF"):
        return "elf"
    if header.startswith(b"#!"):
        wrappers = script_wrappers(header.decode("utf-8", "replace"))
        if wrappers:
            fails.append(f"{path} invokes " + ",".join(wrappers))
        return "script"
    warns.append(f"{path} is neither ELF nor a script")
    return "other"


def audit_exception(ctx: Context, manifest_path: str, manifest: dict) -> Finding:
    raw_id = str(manifest.get("id", ""))
    exc_id = raw_id if ID_RE.match(raw_id) else "invalid"
    fid, title = f"native.{exc_id}", f"native exception {exc_id}"
    binary = manifest.get("binary")
    entry_id = manifest.get("desktop_entry")
    data: dict = {"manifest": manifest_path, "binary": binary, "desktop_entry": entry_id,
                  "runtime": "not inspected"}

    problems = manifest_problems(manifest, exc_id, raw_id)
    if problems:
        return Finding(fid, CATEGORY, title, Status.FAIL,
                       f"{manifest_path}: " + "; ".join(problems), data=data)

    fails: list[str] = []
    warns: list[str] = []
    parts = []
    if entry_id is not None:
        parts.append(check_desktop_entry(ctx, exc_id, entry_id, binary, data, fails, warns))

    formats = {binary: check_program(ctx, binary, fails, warns)}
    for script in path_list(manifest, "scripts") or []:
        if script not in formats:
            formats[script] = check_program(ctx, script, fails, warns)
    data["formats"] = formats

    units = path_list(manifest, "units") or []
    for unit in units:
        text = ctx.read(unit)
        if text is None:
            warns.append(f"{unit} not installed")
            continue
        for problem in unit_problems(text):
            fails.append(f"{os.path.basename(unit)} uses {problem}")
    parts.append(f"{len(formats)} program(s), {len(units)} unit(s)")

    # Issues first: evidence is truncated to a bounded length.
    static_ev = "; ".join(parts)
    if fails:
        return Finding(fid, CATEGORY, title, Status.FAIL,
                       "; ".join(fails) + f"; {static_ev}", data=data)
    evidence = f"{RUNTIME_NOTE}; {static_ev}: direct exec, no sandbox wrapper or namespace"
    note = ("Declared native exception: runs unsandboxed with the invoking user's "
            "privileges by design (" + short(manifest.get("reason", "no reason given"), 200) + ").")
    if warns:
        return Finding(fid, CATEGORY, title, Status.WARN,
                       "; ".join(warns) + f"; {evidence}", note, data)
    return Finding(fid, CATEGORY, title, Status.PASS, evidence, note, data)


def undeclared_entries(ctx: Context, declared: set[str]) -> list[Finding]:
    findings = []
    for directory in APPLICATION_DIRS:
        for name in list_dir(ctx.path(directory))[:MAX_ENTRIES]:
            if not name.endswith(".desktop"):
                continue
            text = ctx.read(f"{directory}/{name}")
            if not text or EXCEPTION_KEY not in text:
                continue
            claimed = parse_desktop_entry(text).get(EXCEPTION_KEY, "")
            if claimed and claimed not in declared:
                safe = claimed if ID_RE.match(claimed) else "invalid"
                findings.append(Finding(
                    f"native.{safe}.manifest", CATEGORY, f"native exception {safe}", Status.WARN,
                    f"{directory}/{name} claims {EXCEPTION_KEY}={short(claimed, 40)} "
                    "but no manifest declares it"))
    return findings


def audit(ctx: Context) -> list[Finding]:
    manifests, findings = load_manifests(ctx)
    declared = set()
    for path, manifest in manifests:
        findings.append(audit_exception(ctx, path, manifest))
        declared.add(str(manifest.get("id", "")))
    findings += undeclared_entries(ctx, declared)
    if not findings:
        findings.append(Finding("native.exceptions", CATEGORY, "native (unsandboxed) exceptions",
                                Status.PASS, "no native exception manifests installed in "
                                + ", ".join(MANIFEST_DIRS)))
    return findings
