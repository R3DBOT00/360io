"""TPM presence, version, and physical versus virtual classification."""
from __future__ import annotations

import os

from ..context import Context
from ..model import Finding, Status
from ..utils.fs import list_dir, parse_int, parse_key_values, read_first_line, read_link_name, read_text

CATEGORY = "tpm"
VIRTUAL_DRIVERS = {"tpm_vtpm_proxy", "tpm_ibmvtpm", "tpm_svsm", "xen-tpmfront", "tpm_xen"}
HARDWARE_DRIVERS = {"tpm_tis", "tpm_crb", "tpm_tis_spi", "tpm_tis_i2c", "tpm_tis_i2c_cr50",
                    "tpm_i2c_infineon", "tpm_i2c_nuvoton", "tpm_i2c_atmel", "tpm_ftpm_tee",
                    "tpm_tis_synquacer", "tpm_atmel", "tpm_infineon", "tpm_nsc"}
VM_VENDORS = ("qemu", "kvm", "vmware", "virtualbox", "innotek", "xen", "bochs", "parallels",
              "bhyve", "cloud hypervisor")


def detect_hypervisor(ctx: Context) -> str | None:
    for field in ("sys_vendor", "product_name", "bios_vendor"):
        value = (read_first_line(ctx.path(f"/sys/class/dmi/id/{field}")) or "").lower()
        for vm in VM_VENDORS:
            if vm in value:
                return value
        if field == "product_name" and value == "virtual machine":
            return "hyper-v"
    if "hypervisor" in ctx.cpu_flags():
        return "cpu hypervisor flag"
    return None


def classify(ctx: Context) -> dict:
    """Return a dict describing tpm0 (or the first TPM) without touching /dev."""
    names = [n for n in list_dir(ctx.path("/sys/class/tpm")) if n.startswith("tpm")]
    info: dict = {"present": bool(names), "device": None, "version": None,
                  "driver": None, "kind": "none", "hypervisor": detect_hypervisor(ctx)}
    if not names:
        return info
    name = names[0]
    base = ctx.path(f"/sys/class/tpm/{name}")
    info["device"] = name
    info["version"] = parse_int(read_first_line(base / "tpm_version_major"))
    if info["version"] is None and read_text(base / "caps") is not None:
        info["version"] = 1
    uevent = parse_key_values(read_text(base / "device" / "uevent") or "")
    info["driver"] = uevent.get("DRIVER") or read_link_name(base / "device" / "driver")
    info["modalias"] = uevent.get("MODALIAS")
    try:
        real = os.readlink(base)
    except OSError:
        real = ""
    driver = info["driver"] or ""
    if driver in VIRTUAL_DRIVERS or "/devices/virtual/" in real:
        info["kind"] = "virtual"
    elif info["hypervisor"]:
        # tpm_tis/tpm_crb inside a VM are emulated (typically swtpm via QEMU).
        info["kind"] = "virtual"
    elif driver in HARDWARE_DRIVERS:
        info["kind"] = "hardware"
    else:
        info["kind"] = "unknown"
    return info


def audit(ctx: Context) -> list[Finding]:
    fid, title = "tpm.device", "TPM presence and physical/virtual classification"
    if not ctx.path("/sys/class").exists():
        return [Finding(fid, CATEGORY, title, Status.UNKNOWN, "/sys/class not readable")]
    info = classify(ctx)
    swtpm = sorted(_swtpm_processes(ctx))
    if swtpm:
        info["swtpm_processes"] = swtpm
    if not info["present"]:
        return [Finding(fid, CATEGORY, title, Status.WARN, "no TPM exposed in /sys/class/tpm",
                        "Disk unlock must rely on passphrase/keyfile only.", info)]
    ev = (f"{info['device']} TPM{info['version'] or '?'} driver={info['driver'] or '?'} "
          f"kind={info['kind']}")
    if info["hypervisor"]:
        ev += f" hypervisor={info['hypervisor']}"
    if info["kind"] == "virtual":
        return [Finding(fid, CATEGORY, title, Status.WARN, ev,
                        "Virtual TPM (e.g. swtpm): its secrets live in host-side state files; "
                        "no hardware protection. See docs/shield.md.", info)]
    if info["kind"] == "unknown":
        return [Finding(fid, CATEGORY, title, Status.UNKNOWN, ev, "Unrecognized TPM driver.", info)]
    if info["version"] != 2:
        return [Finding(fid, CATEGORY, title, Status.WARN, ev,
                        "TPM 1.2 or unknown version; systemd-cryptenroll requires TPM 2.0.", info)]
    return [Finding(fid, CATEGORY, title, Status.PASS, ev,
                    "Hardware-backed (discrete or firmware TPM such as PTT/fTPM).", info)]


def _swtpm_processes(ctx: Context) -> set[str]:
    found = set()
    for pid in list_dir(ctx.path("/proc")):
        if not pid.isdigit():
            continue
        comm = read_first_line(ctx.path(f"/proc/{pid}/comm"))
        if comm and comm.startswith("swtpm"):
            found.add(f"{pid}:{comm}")
    return found
