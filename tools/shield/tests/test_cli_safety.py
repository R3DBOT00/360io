import builtins
import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import time
import unittest
from pathlib import Path
from unittest import mock

from helpers import HERE, TreeCase, fixture

from shield360 import auditors, cli
from shield360.model import EXIT_USAGE, Finding, Status

PACKAGE = HERE.parent / "shield360"


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(list(argv))
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue(), err.getvalue()


class FixtureHost(TreeCase):
    def populate(self):
        self.put("/proc/cpuinfo", fixture("cpuinfo_intel.txt"))
        self.put("/proc/modules", "i915 1 0 - Live 0x0\n")
        self.put("/proc/self/mountinfo", fixture("mountinfo_hardened.txt"))
        self.put("/proc/self/status", fixture("proc_status.txt"))
        self.put("/sys/class/tpm/tpm0/device/uevent", "DRIVER=tpm_crb\n")
        self.put("/sys/class/tpm/tpm0/tpm_version_major", "2\n")
        self.block("dm-0", "254:0", "root", "CRYPT-LUKS2-0123-root", slaves=("nvme0n1p2",))
        self.block("nvme0n1p2", "259:2")


class CliTest(FixtureHost):
    def test_json_report_schema(self):
        self.populate()
        code, out, _ = run_cli("--root", str(self.root), "--format", "json")
        report = json.loads(out)
        self.assertEqual(report["tool"], "360io-shield")
        self.assertEqual(report["exit_code"], code)
        self.assertEqual(sum(report["summary"].values()), len(report["findings"]))
        for item in report["findings"]:
            self.assertIn(item["status"], {"PASS", "WARN", "FAIL", "UNKNOWN"})
            self.assertTrue(item["evidence"])
        ids = {i["id"] for i in report["findings"]}
        self.assertTrue({"firmware.intel_me_interface", "tpm.device", "luks.root",
                         "mounts.tmp", "sandbox.seccomp"} <= ids)
        self.assertEqual([i for i in report["findings"] if i["id"] == "luks.root"][0]["status"], "PASS")

    def test_text_report_and_only(self):
        self.populate()
        code, out, _ = run_cli("--root", str(self.root), "--only", "tpm")
        self.assertEqual(code, 0)
        self.assertIn("[PASS   ] tpm.device", out)
        self.assertIn("summary: PASS=1", out)

    def test_output_file(self):
        self.populate()
        target = self.root / "report.json"
        code, out, _ = run_cli("--root", str(self.root), "--only", "tpm", "--format", "json",
                               "-o", str(target))
        self.assertEqual((code, out), (0, ""))
        self.assertEqual(json.loads(target.read_text())["summary"]["PASS"], 1)

    def test_usage_errors_are_64(self):
        for argv in (("--bogus",), ("--only", "nope"), ("--timeout", "0"),
                     ("-o", "/etc/shield.json"), ("-o", "/proc/x"), ("-o", "/sys/x"), ("-o", "/dev/null")):
            code, _, _ = run_cli(*argv)
            self.assertEqual(code, EXIT_USAGE, argv)

    def test_output_symlink_into_etc_refused(self):
        link = self.root / "sneaky.json"
        os.symlink("/etc/shield-sneaky.json", link)
        self.assertEqual(run_cli("-o", str(link))[0], EXIT_USAGE)

    def test_list_and_version(self):
        code, out, _ = run_cli("--list")
        self.assertEqual(code, 0)
        self.assertEqual(out.split(), list(auditors.AUDITORS))
        self.assertEqual(run_cli("--version")[0], 0)


class RobustnessTest(FixtureHost):
    def test_auditor_exception_becomes_unknown(self):
        def boom(ctx):
            raise RuntimeError("parse exploded")
        with mock.patch.dict(auditors.AUDITORS, {"tpm": boom}):
            [f] = auditors.run_auditor("tpm", self.ctx, 1.0)
        self.assertEqual((f.id, f.status), ("tpm.error", Status.UNKNOWN))
        self.assertIn("parse exploded", f.evidence)

    def test_auditor_timeout_becomes_unknown(self):
        def slow(ctx):
            time.sleep(2)
            return [Finding("x", "x", "x", "PASS", "late")]
        with mock.patch.dict(auditors.AUDITORS, {"tpm": slow}):
            start = time.monotonic()
            [f] = auditors.run_auditor("tpm", self.ctx, 0.2)
        self.assertLess(time.monotonic() - start, 1.5)
        self.assertEqual((f.id, f.status), ("tpm.timeout", Status.UNKNOWN))

    def test_empty_root_never_crashes(self):
        findings = auditors.run_all(self.ctx, timeout=5)
        self.assertTrue(findings)
        self.assertFalse([f for f in findings if f.id.endswith((".error", ".timeout"))])


class ReadOnlyTest(FixtureHost):
    def test_full_audit_performs_no_writes_and_no_subprocess(self):
        self.populate()
        real_open = builtins.open
        writes = []

        def guarded_open(file, mode="r", *args, **kwargs):
            if any(c in mode for c in "wax+"):
                writes.append((file, mode))
            return real_open(file, mode, *args, **kwargs)

        forbidden = mock.Mock(side_effect=AssertionError("mutating call"))
        with mock.patch("builtins.open", guarded_open), \
                mock.patch("subprocess.run", forbidden), mock.patch("subprocess.Popen", forbidden), \
                mock.patch("os.remove", forbidden), mock.patch("os.unlink", forbidden), \
                mock.patch("os.rename", forbidden), mock.patch("os.replace", forbidden), \
                mock.patch("os.mkdir", forbidden), mock.patch("os.chmod", forbidden), \
                mock.patch("os.system", forbidden), mock.patch("shutil.rmtree", forbidden):
            findings = auditors.run_all(self.ctx, timeout=5)
        self.assertEqual(writes, [])
        self.assertFalse([f for f in findings if f.id.endswith(".error")], findings)

    def test_source_has_no_mutating_primitives(self):
        banned = re.compile(r"shell\s*=\s*True|os\.system|os\.(remove|unlink|rename|replace|chmod|chown|"
                            r"mkdir|makedirs|rmdir|symlink|truncate)\(|shutil\.(rmtree|move|copy)|"
                            r"write_text|write_bytes|Popen|/dev/tpm|modprobe |sysctl -w|cryptsetup")
        for path in PACKAGE.rglob("*.py"):
            text = path.read_text()
            self.assertIsNone(banned.search(text), f"{path}: {banned.search(text)}")
            opens = re.findall(r"open\([^)]*\"w\"", text)
            if path.name == "cli.py":
                self.assertEqual(len(opens), 1)  # the report file only, path-checked
            else:
                self.assertEqual(opens, [], path)

    def test_allowlist_is_version_probes_only(self):
        from shield360.utils.proc import ALLOWED_COMMANDS
        self.assertTrue(all(argv[1:] == ("--version",) for argv in ALLOWED_COMMANDS))


class LauncherTest(unittest.TestCase):
    def test_launcher_script_runs_unprivileged(self):
        launcher = HERE.parent / "360io-shield"
        proc = subprocess.run([shutil.which("python3") or "python3", str(launcher), "--list"],
                              capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("sandbox", proc.stdout)


if __name__ == "__main__":
    unittest.main()
