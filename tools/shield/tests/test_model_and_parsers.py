import unittest

from helpers import fixture

from shield360.model import (EXIT_FAIL, EXIT_PASS, EXIT_UNKNOWN, EXIT_WARN, Finding, Status,
                             exit_code_for, short)
from shield360.utils.fs import parse_int, parse_key_values
from shield360.utils.mounts import effective_mounts, parse_mountinfo


def f(status):
    return Finding("x", "c", "t", status, "e")


class ModelTest(unittest.TestCase):
    def test_exit_code_precedence(self):
        self.assertEqual(exit_code_for([]), EXIT_PASS)
        self.assertEqual(exit_code_for([f(Status.PASS)]), EXIT_PASS)
        self.assertEqual(exit_code_for([f(Status.PASS), f(Status.UNKNOWN)]), EXIT_UNKNOWN)
        self.assertEqual(exit_code_for([f(Status.UNKNOWN), f(Status.WARN)]), EXIT_WARN)
        self.assertEqual(exit_code_for([f(Status.WARN), f(Status.FAIL), f(Status.UNKNOWN)]), EXIT_FAIL)
        self.assertEqual((EXIT_PASS, EXIT_WARN, EXIT_FAIL, EXIT_UNKNOWN), (0, 1, 2, 3))

    def test_evidence_is_short_single_line(self):
        ev = Finding("x", "c", "t", "WARN", "a\nb\x1b[31m" + "z" * 500).evidence
        self.assertNotIn("\n", ev)
        self.assertNotIn("\x1b", ev)
        self.assertLessEqual(len(ev), 200)
        self.assertTrue(ev.endswith("..."))
        self.assertEqual(short("  a   b "), "a b")

    def test_invalid_status_rejected(self):
        with self.assertRaises(ValueError):
            Finding("x", "c", "t", "OK", "e")


class ParserTest(unittest.TestCase):
    def test_mountinfo_parses_and_skips_malformed(self):
        mounts = parse_mountinfo(fixture("mountinfo_hardened.txt"))
        points = [m.mountpoint for m in mounts]
        self.assertIn("/mnt/My Disk", points)  # octal escape decoded
        self.assertNotIn("/broken", points)
        root = [m for m in mounts if m.mountpoint == "/"][0]
        self.assertEqual((root.fstype, root.source, root.major_minor), ("btrfs", "/dev/mapper/root", "254:1"))

    def test_stacked_mount_uses_top(self):
        table = effective_mounts(parse_mountinfo(fixture("mountinfo_hardened.txt")))
        self.assertEqual(table["/dev/shm"].mount_id, 90)
        self.assertIn("noexec", table["/dev/shm"].options)
        self.assertIn("hidepid=invisible", table["/proc"].all_options)

    def test_empty_and_garbage(self):
        self.assertEqual(parse_mountinfo(""), [])
        self.assertEqual(parse_mountinfo("x y z - a\n1 2 - -\n"), [])

    def test_small_parsers(self):
        self.assertEqual(parse_int("2\n"), 2)
        self.assertIsNone(parse_int("abc"))
        self.assertIsNone(parse_int(""))
        self.assertIsNone(parse_int(None))
        self.assertEqual(parse_key_values("A=1\nnoise\nB = x=y"), {"A": "1", "B": "x=y"})


if __name__ == "__main__":
    unittest.main()
