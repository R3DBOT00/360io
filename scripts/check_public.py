#!/usr/bin/env python3
"""Fail closed against the reviewed manifest; inspect every Git object too.

This is a release gate for this source snapshot, not a proof of ownership or a
universal secret detector. Manifest updates require manual content review.
"""
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = 'docs/FILES.sha256'
LIMIT = 1024 * 1024
# Reviewed GitHub bootstrap: only README.md and the owner's MIT notice.
BOOTSTRAP_COMMIT = 'cbee17cf5e95184b4d7bca145e4cfc216d26524b'
BOOTSTRAP_BLOBS = {'9b3a3e857d8c764b70a0fcb9ea0affc1e5350d4d',
                   '7d54ea81f6747bcb1d1fc5ae4f139cf664ae6952'}
APPROVED_ORIGIN = 'https://github.com/R3DBOT00/360io.git'
PATTERNS = {
    'private-key': rb'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----',
    'github-token': rb'gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}',
    'aws-key': rb'AKIA[0-9A-Z]{16}',
    'slack-token': rb'xox[baprs]-[0-9A-Za-z-]{20,}',
    'credential-url': rb'https?://[^\s/]+:[^\s/@]+@',
    'personal-path': rb'/(?:home|Users)/[A-Za-z0-9_.-]+/',
}

def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args], stderr=subprocess.DEVNULL)

def inspect(name, data):
    if len(data) > LIMIT or b'\0' in data:
        raise ValueError(f'Binary or oversized content: {name}')
    data.decode('utf-8')
    for label, pattern in PATTERNS.items():
        if re.search(pattern, data):
            raise ValueError(f'Potential sensitive content ({label}): {name}; value withheld')

def main():
    expected = {}
    for line in (ROOT / MANIFEST).read_text().splitlines():
        digest, name = line.split('  ', 1)
        if not re.fullmatch('[0-9a-f]{64}', digest) or name in expected:
            raise ValueError('Invalid manifest')
        if Path(name).is_absolute() or '..' in Path(name).parts:
            raise ValueError('Unsafe manifest path')
        expected[name] = digest
    seen = set()
    blobs = set()
    for base, dirs, files in os.walk(ROOT, followlinks=False):
        for directory in dirs:
            p = Path(base) / directory
            if p.is_symlink():
                raise ValueError(f'Directory symlink: {p.relative_to(ROOT)}')
        if Path(base) == ROOT and '.git' in dirs:
            dirs.remove('.git')
        for filename in files:
            p = Path(base) / filename
            rel = p.relative_to(ROOT).as_posix()
            if p.is_symlink() or not p.is_file():
                raise ValueError(f'Non-regular file: {rel}')
            if rel != MANIFEST and rel not in expected:
                raise ValueError(f'Unreviewed file: {rel}')
            if p.stat().st_size > LIMIT:
                raise ValueError(f'Oversized file: {rel}')
            data = p.read_bytes()
            inspect(rel, data)
            if rel != MANIFEST and hashlib.sha256(data).hexdigest() != expected[rel]:
                raise ValueError(f'Changed file requires review: {rel}')
            seen.add(rel)
            blobs.add(data)
    if seen != set(expected) | {MANIFEST}:
        raise ValueError('Missing reviewed files')
    if (ROOT / '.git').exists():
        if not (ROOT / '.git').is_dir():
            raise ValueError('External gitdir is forbidden')
        if (ROOT / '.git/objects/info/alternates').exists():
            raise ValueError('External Git object storage is forbidden')
        remotes = git('remote').decode().splitlines()
        if remotes and remotes != ['origin']:
            raise ValueError('Unreviewed remote')
        if remotes:
            for args in [('remote', 'get-url', '--all', 'origin'),
                         ('remote', 'get-url', '--push', '--all', 'origin')]:
                if git(*args).decode().splitlines() != [APPROVED_ORIGIN]:
                    raise ValueError('Unreviewed remote URL')
        # Includes unreachable objects; do not print their contents.
        objects = git('cat-file', '--batch-all-objects', '--batch-check=%(objectname) %(objecttype) %(objectsize)').splitlines()
        commits = 0
        for entry in objects:
            oid, kind, size = entry.decode().split()
            if int(size) > LIMIT:
                raise ValueError('Oversized Git object')
            data = git('cat-file', kind, oid)
            if kind == 'blob':
                inspect('Git blob ' + oid, data)
                if data not in blobs and oid not in BOOTSTRAP_BLOBS:
                    raise ValueError('Unreviewed historical Git blob ' + oid)
            elif kind in {'commit', 'tag'}:
                inspect('Git metadata ' + oid, data)
                if kind == 'commit':
                    commits += 1
                    tree = git('ls-tree', '-r', '-z', oid)
                    names = set()
                    for item in tree.split(b'\0'):
                        if not item:
                            continue
                        meta, name = item.split(b'\t', 1)
                        mode, objtype, _ = meta.split()
                        if mode not in {b'100644', b'100755'} or objtype != b'blob':
                            raise ValueError('Symlink/submodule in Git history')
                        names.add(name.decode())
                    approved_names = {'LICENSE', 'README.md'} if oid == BOOTSTRAP_COMMIT else seen
                    if names != approved_names:
                        raise ValueError('Historical tree differs from approved file list')
        print(f'Git: {len(objects)} objects checked, {commits} commits, remote configuration checked')
    print(f'PASS: {len(seen)} reviewed text files; no extra files, symlinks, binaries or detected secret patterns')

if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, UnicodeError, subprocess.CalledProcessError) as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        sys.exit(1)
