# Publication preparation

This tree is a reduced, independent edition prepared locally for review.
Publication to the configured GitHub repository was explicitly approved by
the project owner. Repository visibility is not changed by this release.

## Included

- Library scanner and local API (`src/daemon/library`), CLI client, and tests.
- Recovery detector (`src/recovery`) and its unit test.
- Shield (`tools/shield`), sample configuration, and tests with synthetic data.
- Eleven project packaging files, used only as Shield fixtures under
  `tools/shield/tests/fixtures/packaging`. Shield tests do not install or execute them.
- Independent build configuration, documentation, MIT License, `.gitignore`, and verifier.

The complete inventory with SHA-256 hashes is in `FILES.sha256`. The manifest
excludes its own hash to avoid self-reference. The verifier requires every
file in the tree to appear in that inventory, except the manifest itself and
`.git`. Keep builds outside the public tree.

## Excluded

Selection uses an explicit allowlist: everything not selected remains only in
the original project. No original file was deleted or moved.

| Group | Reason |
| --- | --- |
| Recompiled Dashboard 17489 and generated/recompiled code | Proprietary origin or redistribution authorization not established |
| Proto Stealth, its configuration, and related runtime | Outside public scope; potentially sensitive material |
| All XEX/XBE files, dumps, firmware, System Updates, keys, and keyvaults | Private/proprietary content |
| Entire asset tree, screenshots, avatars, and fonts | Redistribution authorization not established |
| Qt/QML interface and avatar backend | Depend on omitted assets and integrations |
| Xenia, XenonRecomp, SDKs, and transitive third-party code | Forks and dependencies not reexported in this edition |
| Builds, caches, logs, disk images, toolchains, and temporary directories | Generated, large, or machine-specific artifacts |
| Full daemon, compatibility IPC, deployment scripts, and ISO | Coupled to the private project; require separate review |
| Private documentation, evidence, and agent configuration | Potential internal paths, endpoints, and details |
| All original `.git` directories | Avoid transferring history, remotes, or sensitive objects |

## Checks and limitations

The local inventory recorded 298,631 files outside Git directories. Content
scanning covered 55,735 eligible text files (selected extensions, up to 2 MiB).
There were 12 potential secret matches, all outside the initial selection.
These include examples and third-party code; they do not represent 12 verified
credentials. Values were not copied into the report. Binary files, larger
files, and unselected extensions were not content-scanned at that stage.

The original root has an empty/invalid `.git` directory. All 63 identified
nested Git repositories were excluded. Their histories were not certified as
free of secrets and are not needed for this edition. The public release preserves the reviewed GitHub bootstrap commit, containing
only a README and MIT License, and adds the selected source tree. All Git objects,
including unreachable objects, are checked against reviewed content. The only
approved remote is `https://github.com/R3DBOT00/360io.git`.

The verifier checks token patterns, private keys, URL credentials, and personal
paths. It rejects binaries, symlinks, files larger than 1 MiB, files absent from
the manifest, unreviewed changes, and different historical content. Pattern
matching cannot establish absolute absence of secrets or prove authorship.

There was no license at the original project root. MIT was prepared for
components identified as project code; ownership and any third-party
contributions must be confirmed by the owner before approving publication.
No fork was relicensed. See `DEPENDENCIES.md`.

## Validation

Environment: Linux Ubuntu 26.04, GCC 15.2, CMake 4.2.3, Qt 6.10.2, SQLite 3.46.1,
and Python 3.14.4. Compilation succeeded. The passing suites are
`library.parsers`, `library.io`, `library.store`, `library.service`,
`library.api`, `library.cli`, `recovery.unit`, and `shield.unit` (76 Python tests).
The initial Shield errors were resolved by including text fixtures and pointing
the native tests to that directory; the original project was not modified.

LLVM-generated PE fixture tests were skipped because llvm-rc/Clang/LLD were
unavailable; synthetic in-memory PE tests passed. Dashboard, Kinect hardware,
session startup, and remote service tests were not performed because those
components are not distributed. No test installed services.

Documentation and fixture messages are in English. Locale identifiers and
Unicode normalization inputs are retained to preserve parser coverage.

Before publication, review the reduced scope and ownership, rerun
`scripts/check_public.py`, and explicitly approve the GitHub destination.
Do not copy the local audit directory into the repository: it contains private
paths, environment logs, and an inventory of excluded materials.
