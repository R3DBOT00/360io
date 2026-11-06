"""LUKS2 detection through device-mapper metadata in sysfs (no root needed).

The dm UUID of an opened LUKS mapping is ``CRYPT-LUKS2-<uuid>-<name>``, so
the version is known without reading the on-disk header from /dev.
"""
from __future__ import annotations

from ..context import Context
from ..model import Finding, Status
from ..utils.fs import list_dir, read_first_line
from ..utils.mounts import effective_mounts, parse_mountinfo
from . import tpm as tpm_auditor

CATEGORY = "luks"
MAX_DEPTH = 8


def crypt_type(ctx: Context, block: str) -> str | None:
    uuid = read_first_line(ctx.path(f"/sys/class/block/{block}/dm/uuid")) or ""
    if uuid.startswith("CRYPT-"):
        return uuid.split("-")[1]
    return None


def crypt_devices(ctx: Context) -> dict[str, str]:
    out = {}
    for block in list_dir(ctx.path("/sys/class/block")):
        kind = crypt_type(ctx, block)
        if kind:
            name = read_first_line(ctx.path(f"/sys/class/block/{block}/dm/name")) or block
            out[f"{block}({name})"] = kind
    return out


def block_for_source(ctx: Context, source: str, major_minor: str) -> str | None:
    blocks = list_dir(ctx.path("/sys/class/block"))
    if source.startswith("/dev/mapper/"):
        wanted = source[len("/dev/mapper/"):]
        for block in blocks:
            if read_first_line(ctx.path(f"/sys/class/block/{block}/dm/name")) == wanted:
                return block
    if source.startswith("/dev/"):
        name = source[len("/dev/"):]
        if name in blocks:
            return name
    if major_minor and not major_minor.startswith("0:"):
        for block in blocks:
            if read_first_line(ctx.path(f"/sys/class/block/{block}/dev")) == major_minor:
                return block
    return None


def crypt_chain(ctx: Context, block: str, depth: int = 0) -> list[tuple[str, str]]:
    """Return (block, CRYPT-type) pairs found in the stack below ``block``."""
    if depth > MAX_DEPTH:
        return []
    found = []
    kind = crypt_type(ctx, block)
    if kind:
        found.append((block, kind))
    for slave in list_dir(ctx.path(f"/sys/class/block/{block}/slaves")):
        found += crypt_chain(ctx, slave, depth + 1)
    return found


def crypttab_tpm_entries(ctx: Context) -> list[str]:
    text = ctx.read("/etc/crypttab") or ""
    names = []
    for raw in text.splitlines():
        words = raw.split("#", 1)[0].split()
        if len(words) >= 4 and any(o.startswith("tpm2-device") for o in words[3].split(",")):
            names.append(words[0])
    return names


def installer_declined_encryption(ctx: Context) -> bool:
    """True when the 360io installer recorded that the user chose no encryption."""
    text = ctx.read("/var/lib/360io/install-profile") or ""
    return "encryption=none" in (line.strip() for line in text.splitlines())


def audit(ctx: Context) -> list[Finding]:
    findings = []
    fid, title = "luks.root", "Root filesystem on LUKS2"
    mountinfo = ctx.read("/proc/self/mountinfo")
    root = effective_mounts(parse_mountinfo(mountinfo)).get("/") if mountinfo else None
    devices = crypt_devices(ctx)
    data = {"crypt_devices": devices}
    if root is None:
        findings.append(Finding(fid, CATEGORY, title, Status.UNKNOWN,
                                "root mount not found in mountinfo", data=data))
    else:
        block = block_for_source(ctx, root.source, root.major_minor)
        data.update(root_source=root.source, root_fstype=root.fstype, root_block=block)
        if block is None:
            note = ("Running inside a container or overlay root; audit the host."
                    if root.fstype in ("overlay", "tmpfs", "fuse-overlayfs") else "")
            findings.append(Finding(fid, CATEGORY, title, Status.UNKNOWN,
                                    f"cannot map root source {root.source} ({root.fstype}) "
                                    f"to a block device; crypt mappings: {len(devices)}", note, data))
        else:
            chain = crypt_chain(ctx, block)
            data["root_crypt_chain"] = chain
            kinds = {k for _, k in chain}
            ev = f"/ on {block} via {root.source}; chain: " + (
                ",".join(f"{b}={k}" for b, k in chain) or "no dm-crypt")
            if "LUKS2" in kinds:
                findings.append(Finding(fid, CATEGORY, title, Status.PASS, ev, data=data))
            elif kinds:
                findings.append(Finding(fid, CATEGORY, title, Status.WARN, ev,
                                        "Encrypted, but not LUKS2 (no Argon2id/tokens).", data))
            elif installer_declined_encryption(ctx):
                findings.append(Finding(fid, CATEGORY, title, Status.WARN,
                                        ev + "; installer: encryption=none",
                                        "Root filesystem is not encrypted: encryption was not "
                                        "selected at install time. Reinstall with \"Encrypt "
                                        "system\" to protect data at rest.", data))
            else:
                findings.append(Finding(fid, CATEGORY, title, Status.FAIL, ev,
                                        "Root filesystem is not encrypted.", data))

    tpm_names = crypttab_tpm_entries(ctx)
    if tpm_names:
        info = tpm_auditor.classify(ctx)
        ev = f"crypttab tpm2-device for {','.join(tpm_names)}; tpm kind={info['kind']}"
        if info["kind"] == "virtual":
            findings.append(Finding("luks.tpm_binding", CATEGORY, "LUKS TPM2 unlock binding",
                                    Status.WARN, ev,
                                    "Unlock bound to a virtual TPM (swtpm): whoever reads its "
                                    "state files can unseal the key. Keep a passphrase slot.", info))
        elif info["kind"] == "hardware":
            findings.append(Finding("luks.tpm_binding", CATEGORY, "LUKS TPM2 unlock binding",
                                    Status.PASS, ev,
                                    "Keep a passphrase or recovery key slot; PCR changes break unlock.",
                                    info))
        else:
            findings.append(Finding("luks.tpm_binding", CATEGORY, "LUKS TPM2 unlock binding",
                                    Status.WARN, ev, "tpm2-device configured but no usable TPM found.",
                                    info))
    return findings
