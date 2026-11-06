import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

from helpers import TreeCase, fixture, ok

from shield360.auditors import sandbox
from shield360.model import Status
from shield360.utils.proc import CommandNotAllowed, CommandResult, CommandRunner


class SandboxTest(TreeCase):
    def userns(self, max_ns="15000", clone=None):
        self.put("/proc/sys/user/max_user_namespaces", max_ns + "\n")
        if clone is not None:
            self.put("/proc/sys/kernel/unprivileged_userns_clone", clone + "\n")

    def test_bwrap_with_userns_pass(self):
        self.runner.programs["bwrap"] = ok("bubblewrap 0.11.1\n")
        self.userns()
        f = sandbox.audit_bwrap(self.ctx)
        self.assertEqual(f.status, Status.PASS)
        self.assertIn("0.11.1", f.evidence)
        self.assertEqual(self.runner.calls, [("bwrap", "--version")])

    def test_bwrap_without_userns_warn(self):
        self.runner.programs["bwrap"] = ok("bubblewrap 0.11.1\n")
        self.userns(clone="0")
        self.assertEqual(sandbox.audit_bwrap(self.ctx).status, Status.WARN)

    def test_bwrap_missing_or_timeout(self):
        self.assertEqual(sandbox.audit_bwrap(self.ctx).status, Status.WARN)
        self.runner.programs["bwrap"] = CommandResult(("bwrap",), None, timed_out=True, error="timeout")
        f = sandbox.audit_bwrap(self.ctx)
        self.assertEqual(f.status, Status.UNKNOWN)
        self.assertIn("timeout", f.evidence)

    def test_seccomp(self):
        self.assertEqual(sandbox.audit_seccomp(self.ctx).status, Status.UNKNOWN)
        self.put("/proc/self/status", "Name:\tx\n")
        self.assertEqual(sandbox.audit_seccomp(self.ctx).status, Status.FAIL)
        self.put("/proc/self/status", fixture("proc_status.txt"))
        self.assertEqual(sandbox.audit_seccomp(self.ctx).status, Status.WARN)
        self.put("/proc/sys/kernel/seccomp/actions_avail", "kill_process kill_thread trap errno log allow\n")
        self.assertEqual(sandbox.audit_seccomp(self.ctx).status, Status.PASS)

    def test_mat2(self):
        self.assertEqual(sandbox.audit_mat2(self.ctx).status, Status.WARN)
        self.runner.programs["mat2"] = ok("mat2 0.13.4\n")
        self.assertEqual(sandbox.audit_mat2(self.ctx).status, Status.PASS)
        self.runner.programs["mat2"] = CommandResult(("mat2",), 1, "", "boom")
        self.assertEqual(sandbox.audit_mat2(self.ctx).status, Status.UNKNOWN)


class RunnerTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="shield-bin-")
        self.bin = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def script(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/sh\n" + body + "\n")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def test_rejects_non_allowlisted(self):
        runner = CommandRunner(path_env=str(self.bin))
        for argv in (("cryptsetup", "luksDump", "/dev/sda2"), ("bwrap", "--bind", "/", "/"),
                     ("mat2", "--inplace", "x"), ("sh", "-c", "true")):
            with self.assertRaises(CommandNotAllowed):
                runner.run(*argv)

    def test_missing_program(self):
        result = CommandRunner(path_env=str(self.bin)).run("mat2", "--version")
        self.assertFalse(result.ok)
        self.assertEqual(result.error, "not found")

    def test_output_and_clean_env(self):
        self.script("mat2", 'echo "mat2 0.13.4 LC=$LC_ALL SECRET=$SHIELD_SECRET"')
        os.environ["SHIELD_SECRET"] = "leak"
        try:
            result = CommandRunner(path_env=str(self.bin)).run("mat2", "--version")
        finally:
            del os.environ["SHIELD_SECRET"]
        self.assertTrue(result.ok)
        self.assertEqual(result.stdout.strip(), "mat2 0.13.4 LC=C SECRET=")

    def test_timeout(self):
        self.script("bwrap", f"exec {shutil.which('sleep')} 5")
        result = CommandRunner(path_env=str(self.bin), timeout=0.3).run("bwrap", "--version")
        self.assertTrue(result.timed_out)
        self.assertFalse(result.ok)


if __name__ == "__main__":
    unittest.main()
