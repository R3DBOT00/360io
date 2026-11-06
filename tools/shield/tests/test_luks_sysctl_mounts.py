import os
import unittest

from helpers import TreeCase, fixture

from shield360.auditors import luks, mounts, sysctl
from shield360.model import Status


def by_id(findings):
    return {f.id: f for f in findings}


class LuksTest(TreeCase):
    def root_mount(self, source, fstype="btrfs", majmin="0:31"):
        self.put("/proc/self/mountinfo",
                 f"22 1 {majmin} / / rw,relatime shared:1 - {fstype} {source} rw\n")

    def test_btrfs_on_luks2_via_mapper(self):
        self.root_mount("/dev/mapper/root")
        self.block("dm-0", "254:0", "root", "CRYPT-LUKS2-0123abcd-root", slaves=("nvme0n1p2",))
        self.block("nvme0n1p2", "259:2")
        f = by_id(luks.audit(self.ctx))["luks.root"]
        self.assertEqual(f.status, Status.PASS)
        self.assertIn("dm-0=LUKS2", f.evidence)

    def test_lvm_on_luks2_by_majmin(self):
        self.root_mount("/dev/vg/root", "ext4", "254:1")
        self.block("dm-1", "254:1", "vg-root", "LVM-abc", slaves=("dm-0",))
        self.block("dm-0", "254:0", "cryptlvm", "CRYPT-LUKS2-0123-cryptlvm", slaves=("sda2",))
        self.block("sda2", "8:2")
        f = by_id(luks.audit(self.ctx))["luks.root"]
        self.assertEqual(f.status, Status.PASS)
        self.assertEqual(f.data["root_block"], "dm-1")

    def test_luks1_is_warn(self):
        self.root_mount("/dev/dm-0", "ext4", "254:0")
        self.block("dm-0", "254:0", "root", "CRYPT-LUKS1-0123-root")
        self.assertEqual(by_id(luks.audit(self.ctx))["luks.root"].status, Status.WARN)

    def test_plain_partition_is_fail(self):
        self.put("/proc/self/mountinfo", fixture("mountinfo_weak.txt"))
        self.block("nvme0n1p2", "259:2")
        f = by_id(luks.audit(self.ctx))["luks.root"]
        self.assertEqual(f.status, Status.FAIL)

    def test_overlay_root_is_unknown(self):
        self.root_mount("overlay", "overlay", "0:88")
        f = by_id(luks.audit(self.ctx))["luks.root"]
        self.assertEqual(f.status, Status.UNKNOWN)
        self.assertIn("container", f.note)

    def test_missing_mountinfo_is_unknown(self):
        self.assertEqual(by_id(luks.audit(self.ctx))["luks.root"].status, Status.UNKNOWN)

    def test_slave_cycle_is_bounded(self):
        self.root_mount("/dev/dm-0", "ext4", "254:0")
        self.block("dm-0", "254:0", "a", "LVM-a", slaves=("dm-1",))
        self.block("dm-1", "254:1", "b", "LVM-b", slaves=("dm-0",))
        self.assertEqual(by_id(luks.audit(self.ctx))["luks.root"].status, Status.FAIL)

    def test_unencrypted_root_declined_in_installer_warns(self):
        self.root_mount("/dev/vda2", "ext4", "253:2")
        self.block("vda2", "253:2")
        self.put("/var/lib/360io/install-profile", "profile=xfce-preview\nencryption=none\n")
        self.assertEqual(by_id(luks.audit(self.ctx))["luks.root"].status, Status.WARN)

    def test_unencrypted_root_with_luks_record_still_fails(self):
        self.root_mount("/dev/vda2", "ext4", "253:2")
        self.block("vda2", "253:2")
        self.put("/var/lib/360io/install-profile", "profile=xfce-preview\nencryption=luks2\n")
        self.assertEqual(by_id(luks.audit(self.ctx))["luks.root"].status, Status.FAIL)

    def test_crypttab_tpm_binding_on_virtual_tpm_warns(self):
        self.root_mount("/dev/mapper/root")
        self.block("dm-0", "254:0", "root", "CRYPT-LUKS2-0123-root")
        self.put("/etc/crypttab", "# name dev key opts\nroot UUID=abc none tpm2-device=auto,discard\n")
        self.put("/sys/class/tpm/tpm0/device/uevent", "DRIVER=tpm_vtpm_proxy\n")
        self.put("/sys/class/tpm/tpm0/tpm_version_major", "2\n")
        f = by_id(luks.audit(self.ctx))["luks.tpm_binding"]
        self.assertEqual(f.status, Status.WARN)
        self.assertIn("swtpm", f.note)

    def test_crypttab_tpm_binding_on_hardware_passes(self):
        self.put("/etc/crypttab", "root UUID=abc - tpm2-device=auto\n")
        self.put("/sys/class/tpm/tpm0/device/uevent", "DRIVER=tpm_crb\n")
        self.put("/proc/cpuinfo", fixture("cpuinfo_intel.txt"))
        self.assertEqual(by_id(luks.audit(self.ctx))["luks.tpm_binding"].status, Status.PASS)


class SysctlTest(TreeCase):
    def set(self, key, value):
        self.put("/proc/sys/" + key.replace(".", "/"), f"{value}\n")

    def test_evaluate_rules(self):
        rule = next(r for r in sysctl.RULES if r.key == "kernel.kptr_restrict")
        self.assertEqual(sysctl.evaluate(rule, "0")[0], Status.FAIL)
        self.assertEqual(sysctl.evaluate(rule, "1")[0], Status.PASS)
        self.assertEqual(sysctl.evaluate(rule, "2")[0], Status.PASS)
        self.assertEqual(sysctl.evaluate(rule, "junk")[0], Status.UNKNOWN)
        self.assertEqual(sysctl.evaluate(rule, None)[0], Status.UNKNOWN)
        exact = next(r for r in sysctl.RULES if r.key == "fs.suid_dumpable")
        self.assertEqual(sysctl.evaluate(exact, "2")[0], Status.WARN)
        self.assertEqual(sysctl.evaluate(exact, "0")[0], Status.PASS)
        yama = next(r for r in sysctl.RULES if r.key == "kernel.yama.ptrace_scope")
        self.assertEqual(sysctl.evaluate(yama, None)[0], Status.WARN)

    def test_audit_from_fixture_tree(self):
        for rule in sysctl.RULES:
            self.set(rule.key, rule.recommended)
        self.set("kernel.randomize_va_space", 1)
        results = by_id(sysctl.audit(self.ctx))
        self.assertEqual(len(results), len(sysctl.RULES))
        self.assertEqual(results["sysctl.kernel.randomize_va_space"].status, Status.FAIL)
        others = [f for k, f in results.items() if k != "sysctl.kernel.randomize_va_space"]
        self.assertTrue(all(f.status == Status.PASS for f in others))

    @unittest.skipIf(os.geteuid() == 0, "root can read mode-000 files")
    def test_root_only_sysctl_is_unknown(self):
        path = self.put("/proc/sys/net/core/bpf_jit_harden", "2\n")
        path.chmod(0)
        try:
            f = by_id(sysctl.audit(self.ctx))["sysctl.net.core.bpf_jit_harden"]
            self.assertEqual(f.status, Status.UNKNOWN)
            self.assertIn("not readable unprivileged", f.evidence)
        finally:
            path.chmod(0o600)


class MountsTest(TreeCase):
    def test_hardened_layout(self):
        self.put("/proc/self/mountinfo", fixture("mountinfo_hardened.txt"))
        r = by_id(mounts.audit(self.ctx))
        for fid in ("mounts.tmp", "mounts.dev_shm", "mounts.home", "mounts.boot", "mounts.proc_hidepid"):
            self.assertEqual(r[fid].status, Status.PASS, fid)
        self.assertNotIn("mounts.var_tmp", r)  # optional mount absent

    def test_weak_layout(self):
        self.put("/proc/self/mountinfo", fixture("mountinfo_weak.txt"))
        r = by_id(mounts.audit(self.ctx))
        self.assertEqual(r["mounts.tmp"].status, Status.WARN)
        self.assertEqual(r["mounts.dev_shm"].status, Status.FAIL)
        self.assertIn("missing nodev,nosuid", r["mounts.dev_shm"].evidence)
        self.assertEqual(r["mounts.proc_hidepid"].status, Status.WARN)

    def test_unreadable(self):
        [f] = mounts.audit(self.ctx)
        self.assertEqual(f.status, Status.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
