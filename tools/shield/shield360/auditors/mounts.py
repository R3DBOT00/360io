"""Hardening options on sensitive mountpoints, from /proc/self/mountinfo."""
from __future__ import annotations

from ..context import Context
from ..model import Finding, Status
from ..utils.mounts import effective_mounts, parse_mountinfo

CATEGORY = "mounts"

# mountpoint -> (required options, recommended options, status if absent mount)
POLICY = {
    "/tmp": ({"nosuid", "nodev"}, {"noexec"}, Status.WARN),
    "/dev/shm": ({"nosuid", "nodev"}, {"noexec"}, Status.WARN),
    "/var/tmp": ({"nosuid", "nodev"}, set(), None),
    "/home": ({"nodev"}, {"nosuid"}, None),
    "/boot": ({"nosuid", "nodev"}, {"noexec"}, None),
    "/efi": ({"nosuid", "nodev"}, {"noexec"}, None),
}
HIDEPID_OK = {"hidepid=2", "hidepid=invisible", "hidepid=4", "hidepid=ptraceable"}


def audit(ctx: Context) -> list[Finding]:
    text = ctx.read("/proc/self/mountinfo")
    if not text:
        return [Finding("mounts.mountinfo", CATEGORY, "Mount table", Status.UNKNOWN,
                        "/proc/self/mountinfo unreadable")]
    table = effective_mounts(parse_mountinfo(text))
    findings = []
    for point, (required, recommended, absent_status) in POLICY.items():
        fid, title = f"mounts.{point.strip('/').replace('/', '_')}", f"Mount options for {point}"
        mount = table.get(point)
        if mount is None:
            if absent_status is not None:
                findings.append(Finding(fid, CATEGORY, title, absent_status,
                                        f"{point} is not a separate mount (inherits parent options)"))
            continue
        opts = mount.options
        missing = sorted(required - opts)
        soft = sorted(recommended - opts)
        ev = f"{point} {mount.fstype} {','.join(sorted(opts & (required | recommended | {'ro'}))) or '-'}"
        if missing:
            findings.append(Finding(fid, CATEGORY, title, Status.FAIL,
                                    ev + "; missing " + ",".join(missing)))
        elif soft:
            findings.append(Finding(fid, CATEGORY, title, Status.WARN,
                                    ev + "; recommended " + ",".join(soft)))
        else:
            findings.append(Finding(fid, CATEGORY, title, Status.PASS, ev))

    proc = table.get("/proc")
    fid, title = "mounts.proc_hidepid", "/proc hidepid"
    if proc is None:
        findings.append(Finding(fid, CATEGORY, title, Status.UNKNOWN, "/proc mount not found"))
    else:
        hide = sorted(o for o in proc.all_options if o.startswith("hidepid="))
        if HIDEPID_OK & set(hide):
            findings.append(Finding(fid, CATEGORY, title, Status.PASS, "/proc " + ",".join(hide)))
        else:
            findings.append(Finding(fid, CATEGORY, title, Status.WARN,
                                    "/proc " + (",".join(hide) or "no hidepid"),
                                    "Other users' processes are visible; hidepid can break "
                                    "polkit/systemd-logind without a gid= exemption."))
    return findings
