#!/usr/bin/env python3
"""Build a fake /games tree (minimal PE stubs, no real game data).

Usage: make_fake_games.py ROOT

The PEs mirror buildPe() in tests/library/test_support.hpp without version
resources: a PE32+ header and an empty .rsrc section, padded (sparse) to
3 MiB so the scanner ranks them as main executables. Used by the 360io CLI
tests and scripts/e2e-preview.sh; the tree must live on Ext4 or Btrfs+zstd
for the default "directory" mount policy (not tmpfs).
"""
import os
import struct
import sys


def pe_stub(path, size=3 << 20, subsystem=2):
    b = bytearray(0x400)
    b[0:2] = b"MZ"
    struct.pack_into("<I", b, 0x3C, 0x80)
    nt = 0x80
    struct.pack_into("<IHH", b, nt, 0x00004550, 0x8664, 1)
    struct.pack_into("<I", b, nt + 8, 0x5F000000)
    struct.pack_into("<HH", b, nt + 20, 240, 0x0022)
    opt = nt + 24
    struct.pack_into("<H", b, opt, 0x20B)
    struct.pack_into("<H", b, opt + 68, subsystem)
    struct.pack_into("<I", b, opt + 112 - 4, 16)
    sec = opt + 240
    b[sec:sec + 8] = b".rsrc\0\0\0"
    struct.pack_into("<IIII", b, sec + 8, 16, 0x1000, 16, 0x400)
    b += bytes(16)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(b)
        f.truncate(size)


TREE = {
    "Fake Quest/bin/FakeQuest.exe": None,
    "Fake Quest/unins000.exe": 64 << 10,
    "Fake Quest/Redist/vcredist_x64.exe": 64 << 10,
    "Other Game/OtherGame.exe": None,
    "Other Game/Launcher.exe": None,
}

OVERRIDE = """# 360io per-game override (docs/game-library-contract.md)
title = "Other Game (override)"
executable = "OtherGame.exe"
args = ["-windowed"]
runner = "proton"

[env]
DXVK_HUD = "fps"

[gamescope]
enabled = true
width = 1280
height = 720
"""


def main(argv):
    if len(argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 64
    root = argv[1]
    for rel, size in TREE.items():
        pe_stub(os.path.join(root, rel), size or (3 << 20))
    os.makedirs(os.path.join(root, "Other Game/.360io"), exist_ok=True)
    with open(os.path.join(root, "Other Game/.360io/game.toml"), "w", encoding="utf-8") as f:
        f.write(OVERRIDE)
    os.makedirs(os.path.join(root, "Music"), exist_ok=True)
    with open(os.path.join(root, "Music/track.ogg"), "w") as f:
        f.write("not a game\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
