"""Intel ME / AMD PSP (ccp) host interfaces, reported as OS driver state only.

The management engines run from platform firmware independently of Linux.
Unloading or blacklisting the host driver only removes the OS-side channel;
it never disables the engine. Findings are worded accordingly.
"""
from __future__ import annotations

from ..context import Context
from ..model import Finding, Status
from ..utils.fs import list_dir, read_text

CATEGORY = "firmware"
MODPROBE_DIRS = ("/etc/modprobe.d", "/run/modprobe.d", "/usr/lib/modprobe.d")
NOT_A_DISABLE_CLAIM = ("Reflects the Linux driver state only; the engine firmware keeps "
                       "running and this tool never claims it is disabled.")

ENGINES = {
    "GenuineIntel": {
        "id": "firmware.intel_me_interface",
        "title": "Intel ME host interface (MEI) driver state",
        "modules": ("mei", "mei_me", "mei_txe", "mei_hdcp", "mei_pxp", "mei_gsc"),
        "pci_drivers": ("mei_me", "mei_txe"),
        "class_dir": "/sys/class/mei",
    },
    "AuthenticAMD": {
        "id": "firmware.amd_psp_interface",
        "title": "AMD PSP/CCP host interface driver state",
        "modules": ("ccp", "kvm_amd_sev"),
        "pci_drivers": ("ccp",),
        "class_dir": None,
    },
}


def _normalize(name: str) -> str:
    return name.replace("-", "_")


def blacklisted_modules(ctx: Context) -> dict[str, str]:
    """Module -> config file for `blacklist X` or `install X /bin/false|true`."""
    found: dict[str, str] = {}
    for directory in MODPROBE_DIRS:
        base = ctx.path(directory)
        for name in list_dir(base):
            if not name.endswith(".conf"):
                continue
            text = read_text(base / name) or ""
            for raw in text.splitlines():
                words = raw.split("#", 1)[0].split()
                if len(words) >= 2 and words[0] == "blacklist":
                    found.setdefault(_normalize(words[1]), f"{directory}/{name}")
                elif (len(words) >= 3 and words[0] == "install"
                      and words[2] in ("/bin/false", "/bin/true", "/usr/bin/false", "/usr/bin/true")):
                    found.setdefault(_normalize(words[1]), f"{directory}/{name}")
    return found


def audit(ctx: Context) -> list[Finding]:
    vendor = ctx.cpu_vendor()
    spec = ENGINES.get(vendor or "")
    if spec is None:
        return [Finding("firmware.mgmt_engine_interface", CATEGORY,
                        "Management engine host interface driver state", Status.UNKNOWN,
                        f"cpu vendor {vendor or 'unreadable'} not covered", NOT_A_DISABLE_CLAIM)]

    modules = ctx.loaded_modules()
    loaded = sorted(m for m in spec["modules"] if modules and m in modules)
    bound: list[str] = []
    for drv in spec["pci_drivers"]:
        bound += [f"{drv}:{e}" for e in list_dir(ctx.path(f"/sys/bus/pci/drivers/{drv}"))
                  if e.count(":") == 2]
    nodes = list_dir(ctx.path(spec["class_dir"])) if spec["class_dir"] else []
    blacklist = blacklisted_modules(ctx)
    listed = sorted(f"{m}({blacklist[m]})" for m in spec["modules"] if m in blacklist)

    data = {"vendor": vendor, "loaded_modules": loaded, "bound_devices": bound,
            "device_nodes": nodes, "blacklisted": listed}
    if bound or nodes or loaded:
        parts = []
        if bound:
            parts.append("bound " + ",".join(bound))
        if nodes:
            parts.append("nodes " + ",".join(nodes))
        if loaded:
            parts.append("modules " + ",".join(loaded))
        return [Finding(spec["id"], CATEGORY, spec["title"], Status.WARN,
                        "OS interface exposed: " + "; ".join(parts),
                        NOT_A_DISABLE_CLAIM + " Blacklisting may break HDCP, firmware "
                        "updates or fTPM-adjacent features.", data)]
    if modules is None:
        return [Finding(spec["id"], CATEGORY, spec["title"], Status.UNKNOWN,
                        "/proc/modules unreadable", NOT_A_DISABLE_CLAIM, data)]
    evidence = "no driver bound or loaded"
    if listed:
        evidence += "; blacklisted: " + ",".join(listed)
    return [Finding(spec["id"], CATEGORY, spec["title"], Status.PASS, evidence,
                    NOT_A_DISABLE_CLAIM, data)]
