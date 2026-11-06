import json
import os
import unittest

from helpers import HERE, TreeCase

from shield360.auditors import native
from shield360.model import Status

REPO = HERE / "fixtures"
DESKTOP_DIR = REPO / "packaging/desktop"
RECOVERY_DIR = REPO / "packaging/recovery"
DESKTOP_ENTRY = DESKTOP_DIR / "360io-desktop.desktop"
MANIFEST = DESKTOP_DIR / "360io-desktop.shield.json"
RECOVERY_MANIFEST = RECOVERY_DIR / "360io-recovery.shield.json"
MANIFEST_DIR = "/usr/share/360io/shield/native-exceptions"
MANIFEST_PATH = f"{MANIFEST_DIR}/360io-desktop.json"
ENTRY_PATH = "/usr/share/applications/360io-desktop.desktop"
BINARY = "/usr/bin/360io-desktop"
UNIT_SOURCES = {
    "360io-recovery-detect.service": "360io-recovery-detect.service",
    "360io-recovery.target": "360io-recovery.target",
    "360io-recovery-session@.service": "360io-recovery-session@.service",
    "360io-recovery.conf": "display-manager-360io-recovery.conf",
}


class NativeBase(TreeCase):
    def install(self, entry=None, manifest=None, binary=None, with_binary=True):
        """Mimics `cmake --install` of the versioned desktop files into the fake root."""
        self.put(MANIFEST_PATH, manifest if manifest is not None else MANIFEST.read_text())
        self.put(ENTRY_PATH, entry if entry is not None else DESKTOP_ENTRY.read_text())
        if with_binary:
            self.put_bytes(BINARY, binary if binary is not None
                           else (DESKTOP_DIR / "360io-desktop").read_bytes())

    def install_recovery(self, units=None):
        manifest = json.loads(RECOVERY_MANIFEST.read_text())
        self.put(f"{MANIFEST_DIR}/360io-recovery.json", json.dumps(manifest))
        self.put_bytes(manifest["binary"], b"\x7fELF\x02\x01\x01")
        for script in manifest["scripts"]:
            self.put_bytes(script, (RECOVERY_DIR / os.path.basename(script)).read_bytes())
        for unit in manifest["units"]:
            name = os.path.basename(unit)
            text = (units or {}).get(name, (RECOVERY_DIR / UNIT_SOURCES[name]).read_text())
            self.put(unit, text)
        return manifest

    def put_bytes(self, path, data):
        target = self.root / path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    def entry_with(self, exec_line):
        return DESKTOP_ENTRY.read_text().replace(f"Exec={BINARY}", f"Exec={exec_line}")

    def only(self):
        findings = native.audit(self.ctx)
        self.assertEqual(len(findings), 1, findings)
        return findings[0]



class NativeExceptionTest(NativeBase):
    def test_no_manifest_is_reported_without_inventing_state(self):
        f = self.only()
        self.assertEqual((f.id, f.status), ("native.exceptions", Status.PASS))
        self.assertIn("no native exception manifests installed", f.evidence)

    def test_versioned_desktop_files_pass_statically(self):
        self.install()
        f = self.only()
        self.assertEqual((f.id, f.status), ("native.360io-desktop", Status.PASS), f.evidence)
        self.assertIn(f"Exec={BINARY}", f.evidence)
        self.assertIn("no sandbox wrapper or namespace", f.evidence)
        self.assertIn("runtime state not inspected", f.evidence)
        self.assertNotIn("running", f.evidence)
        self.assertEqual(f.data["formats"], {BINARY: "script"})
        self.assertIn("unsandboxed", f.note)
        manifest = json.loads(MANIFEST.read_text())
        self.assertEqual((manifest["binary"], manifest["sandbox"]), (BINARY, "none"))

    def test_running_processes_are_never_reported(self):
        self.install()
        self.mkdir("/proc/4242")
        os.symlink(BINARY, self.root / "proc/4242/exe")
        f = self.only()
        self.assertNotIn("4242", f.evidence)
        self.assertNotIn("process", f.data)

    def test_sandbox_wrappers_in_exec_fail(self):
        for exec_line in (f"bwrap --bind / / {BINARY}", "flatpak run io.threesixty.Desktop",
                          f"/usr/bin/flatpak-spawn --host {BINARY}", f"{BINARY} --via firejail",
                          f"env A=1 unshare -U {BINARY}", f'"/usr/bin/bwrap" {BINARY} %U'):
            with self.subTest(exec_line=exec_line):
                self.install(entry=self.entry_with(exec_line))
                self.assertEqual(self.only().status, Status.FAIL)

    def test_exec_must_run_declared_binary(self):
        self.install(entry=self.entry_with("/opt/other/360io-desktop"))
        f = self.only()
        self.assertEqual(f.status, Status.FAIL)
        self.assertIn("instead of /usr/bin/360io-desktop", f.evidence)

    def test_field_codes_and_quotes_are_tokenized(self):
        self.assertEqual(native.exec_argv('"/usr/bin/360io-desktop" %U --x "a b" 100%%'),
                         [BINARY, "--x", "a b", "100%"])
        self.assertIsNone(native.exec_argv('"unterminated'))
        self.install(entry=self.entry_with(f"{BINARY} %U"))
        self.assertEqual(self.only().status, Status.PASS)

    def test_flatpak_keys_fail(self):
        # Keys only count in [Desktop Entry]; the entry ends with action groups.
        entry = DESKTOP_ENTRY.read_text().replace(
            "[Desktop Entry]\n", "[Desktop Entry]\nX-Flatpak=io.threesixty.Desktop\n", 1)
        self.install(entry=entry)
        self.assertEqual(self.only().status, Status.FAIL)
        self.install(entry=DESKTOP_ENTRY.read_text() + "X-Flatpak=io.threesixty.Desktop\n")
        self.assertEqual(self.only().status, Status.PASS)

    def test_action_exec_is_audited(self):
        for exec_line, status in ((f"{BINARY} --session kde", Status.PASS),
                                  (f"bwrap --bind / / {BINARY} --session kde", Status.FAIL),
                                  ("/opt/other --session kde", Status.FAIL)):
            with self.subTest(exec_line=exec_line):
                self.install(entry=DESKTOP_ENTRY.read_text().replace(
                    f"Exec={BINARY} --session kde", f"Exec={exec_line}"))
                self.assertEqual(self.only().status, status)

    def test_manifest_must_declare_no_sandbox(self):
        manifest = json.loads(MANIFEST.read_text())
        for key, value in (("sandbox", "bwrap"), ("binary", "360io-desktop"),
                           ("kind", "app"), ("desktop_entry", "../x.desktop"), ("id", "../x"),
                           ("scripts", "/usr/bin/x"), ("units", ["relative.service"])):
            with self.subTest(key=key):
                self.install(manifest=json.dumps({**manifest, key: value}))
                findings = native.audit(self.ctx)
                self.assertEqual(findings[0].status, Status.FAIL, findings)
                # A bad id also orphans the entry's backlink, which is flagged too.
                self.assertEqual(len(findings), 2 if key == "id" else 1)

    def test_missing_entry_or_binary_warns(self):
        self.put(MANIFEST_PATH, MANIFEST.read_text())
        f = self.only()
        self.assertEqual(f.status, Status.WARN)
        self.assertIn("not installed", f.evidence)
        self.install(with_binary=False)
        f = self.only()
        self.assertEqual(f.status, Status.WARN)
        self.assertIn(f"{BINARY} not installed", f.evidence)

    def test_script_invoking_sandbox_fails_but_comments_do_not(self):
        for body, status in ((b"#!/bin/sh\nexec bwrap --dev-bind / / /opt/real \"$@\"\n", Status.FAIL),
                             (b"#!/bin/sh\nexec /usr/bin/flatpak-spawn --host x\n", Status.FAIL),
                             (b"#!/bin/sh\necho ${#a} ; unshare -U x\n", Status.FAIL),
                             (b"#!/bin/sh\n# no bwrap or flatpak here\nexec Xephyr :20\n", Status.PASS),
                             (b"#!/bin/sh\nexec /opt/360io/360io-desktop \"$@\"\n", Status.PASS)):
            with self.subTest(body=body):
                self.install(binary=body)
                self.assertEqual(self.only().status, status)

    def test_elf_binary_is_classified(self):
        self.install(binary=b"\x7fELF\x02\x01\x01")
        f = self.only()
        self.assertEqual((f.status, f.data["formats"][BINARY]), (Status.PASS, "elf"))

    def test_missing_backlink_warns(self):
        self.install(entry=DESKTOP_ENTRY.read_text().replace("X-360io-Shield-Exception=", "X-Old="))
        self.assertEqual(self.only().status, Status.WARN)

    def test_entry_claiming_exception_without_manifest_warns(self):
        self.put(ENTRY_PATH, DESKTOP_ENTRY.read_text())
        f = self.only()
        self.assertEqual((f.id, f.status), ("native.360io-desktop.manifest", Status.WARN))

    def test_unparseable_manifest_is_unknown(self):
        self.put(MANIFEST_PATH, "{not json")
        self.assertEqual(self.only().status, Status.UNKNOWN)


class RecoveryExceptionTest(NativeBase):
    def recovery(self):
        findings = {f.id: f for f in native.audit(self.ctx)}
        return findings["native.360io-recovery"]

    def test_versioned_recovery_units_and_scripts_pass(self):
        manifest = self.install_recovery()
        f = self.recovery()
        self.assertEqual(f.status, Status.PASS, f.evidence)
        self.assertIn("4 program(s), 4 unit(s)", f.evidence)
        self.assertIn("runtime state not inspected", f.evidence)
        self.assertEqual(f.data["formats"][manifest["binary"]], "elf")

    def test_namespace_directive_in_unit_fails(self):
        unit = (RECOVERY_DIR / "360io-recovery-session@.service").read_text()
        for extra in ("PrivateTmp=yes", "ProtectSystem=strict", "RootDirectory=/srv/x",
                      "ExecStartPre=/usr/bin/systemd-run --scope true"):
            with self.subTest(extra=extra):
                self.install_recovery({"360io-recovery-session@.service":
                                       unit.replace("[Service]\n", f"[Service]\n{extra}\n")})
                f = self.recovery()
                self.assertEqual(f.status, Status.FAIL)
                self.assertIn("360io-recovery-session@.service uses", f.evidence)

    def test_disabled_directive_is_not_isolation(self):
        self.assertEqual(native.unit_problems("[Service]\nPrivateTmp=no\nExecStart=-/bin/true\n"), [])

    def test_missing_unit_warns(self):
        self.install_recovery()
        os.unlink(self.root / "usr/lib/systemd/system/360io-recovery.target")
        f = self.recovery()
        self.assertEqual(f.status, Status.WARN)
        self.assertIn("360io-recovery.target not installed", f.evidence)


if __name__ == "__main__":
    unittest.main()
