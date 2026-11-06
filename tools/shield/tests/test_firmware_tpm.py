import os
import unittest

from helpers import TreeCase, fixture

from shield360.auditors import firmware, tpm
from shield360.model import Status

FORBIDDEN_CLAIMS = ("is disabled", "has been disabled", "neutralized", "physically disabled")


class FirmwareTest(TreeCase):
    def intel(self):
        self.put("/proc/cpuinfo", fixture("cpuinfo_intel.txt"))

    def assert_no_disable_claim(self, finding):
        text = (finding.evidence + " " + finding.note).lower()
        for claim in FORBIDDEN_CLAIMS:
            self.assertNotIn(claim, text.replace("never claims it is disabled", ""))
        self.assertIn("driver state only", finding.note.lower())

    def test_intel_mei_bound_is_warn(self):
        self.intel()
        self.put("/proc/modules", "mei_me 53248 1 - Live 0x0\nmei 180224 3 mei_me, Live 0x0\n")
        self.mkdir("/sys/bus/pci/drivers/mei_me/0000:00:16.0")
        self.mkdir("/sys/bus/pci/drivers/mei_me/module")
        self.mkdir("/sys/class/mei/mei0")
        [finding] = firmware.audit(self.ctx)
        self.assertEqual(finding.id, "firmware.intel_me_interface")
        self.assertEqual(finding.status, Status.WARN)
        self.assertIn("mei_me:0000:00:16.0", finding.evidence)
        self.assertEqual(finding.data["bound_devices"], ["mei_me:0000:00:16.0"])  # "module" skipped
        self.assert_no_disable_claim(finding)

    def test_intel_blacklisted_is_pass_without_disable_claim(self):
        self.intel()
        self.put("/proc/modules", "i915 1 0 - Live 0x0\n")
        self.put("/etc/modprobe.d/me.conf", "# comment\nblacklist mei_me\ninstall mei /bin/false\n")
        [finding] = firmware.audit(self.ctx)
        self.assertEqual(finding.status, Status.PASS)
        self.assertIn("mei_me(/etc/modprobe.d/me.conf)", finding.evidence)
        self.assertIn("mei(/etc/modprobe.d/me.conf)", finding.evidence)
        self.assert_no_disable_claim(finding)

    def test_amd_ccp(self):
        self.put("/proc/cpuinfo", fixture("cpuinfo_amd_vm.txt"))
        self.put("/proc/modules", "ccp 1 0 - Live 0x0\n")
        [finding] = firmware.audit(self.ctx)
        self.assertEqual(finding.id, "firmware.amd_psp_interface")
        self.assertEqual(finding.status, Status.WARN)
        self.assert_no_disable_claim(finding)

    def test_unknown_vendor_and_unreadable_modules(self):
        [finding] = firmware.audit(self.ctx)
        self.assertEqual(finding.status, Status.UNKNOWN)
        self.intel()
        [finding] = firmware.audit(self.ctx)
        self.assertEqual(finding.status, Status.UNKNOWN)


class TpmTest(TreeCase):
    def tpm(self, driver="tpm_crb", version="2"):
        self.put("/sys/class/tpm/tpm0/device/uevent", f"DRIVER={driver}\nMODALIAS=acpi:MSFT0101:\n")
        if version is not None:
            self.put("/sys/class/tpm/tpm0/tpm_version_major", version + "\n")
        self.put("/proc/cpuinfo", fixture("cpuinfo_intel.txt"))

    def test_hardware_tpm2_pass(self):
        self.tpm()
        [finding] = tpm.audit(self.ctx)
        self.assertEqual(finding.status, Status.PASS)
        self.assertEqual(finding.data["kind"], "hardware")

    def test_vtpm_proxy_is_virtual(self):
        self.tpm(driver="tpm_vtpm_proxy")
        [finding] = tpm.audit(self.ctx)
        self.assertEqual((finding.status, finding.data["kind"]), (Status.WARN, "virtual"))
        self.assertIn("swtpm", finding.note)

    def test_emulated_tis_in_qemu_is_virtual(self):
        self.tpm(driver="tpm_tis")
        self.put("/sys/class/dmi/id/sys_vendor", "QEMU\n")
        self.put("/proc/4242/comm", "swtpm\n")
        [finding] = tpm.audit(self.ctx)
        self.assertEqual(finding.data["kind"], "virtual")
        self.assertEqual(finding.data["swtpm_processes"], ["4242:swtpm"])
        self.assertEqual(finding.status, Status.WARN)

    def test_hypervisor_cpu_flag(self):
        self.tpm()
        self.put("/proc/cpuinfo", fixture("cpuinfo_amd_vm.txt"))
        self.assertEqual(tpm.classify(self.ctx)["kind"], "virtual")

    def test_driver_from_symlink_and_tpm12(self):
        self.put("/sys/class/tpm/tpm0/caps", "Manufacturer: 0x0\n")
        device = self.mkdir("/sys/class/tpm/tpm0/device")
        os.symlink("../../../bus/platform/drivers/tpm_tis", device / "driver")
        self.put("/proc/cpuinfo", fixture("cpuinfo_intel.txt"))
        [finding] = tpm.audit(self.ctx)
        self.assertEqual(finding.data["driver"], "tpm_tis")
        self.assertEqual(finding.data["version"], 1)
        self.assertEqual(finding.status, Status.WARN)

    def test_absent_and_unknown(self):
        self.mkdir("/sys/class")
        [finding] = tpm.audit(self.ctx)
        self.assertEqual(finding.status, Status.WARN)
        self.tpm(driver="tpm_weird")
        [finding] = tpm.audit(self.ctx)
        self.assertEqual(finding.status, Status.UNKNOWN)

    def test_no_sysfs(self):
        [finding] = tpm.audit(self.ctx)
        self.assertEqual(finding.status, Status.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
