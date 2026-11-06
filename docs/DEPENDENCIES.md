# Dependencies and licenses

No third-party source code or binaries are vendored. The root MIT License
covers only selected project code and this edition's documentation.
Local provenance does not establish ownership: publication approval must
confirm authorship or authorization for the selected files. No license was
found at the original project root, and no conflicting notices were found
in the selected files.

| Dependency | Use | License / handling |
| --- | --- | --- |
| Qt 6 Core and Network | Library and CLI | LGPLv3/GPL/commercial options depending on the package; externally installed and dynamically linked in this validation |
| SQLite3 | Metadata database | Core is in the public domain; externally installed |
| Python >= 3.10 | Shield and tests | PSF; external interpreter, standard library modules only |
| CMake, Ninja/Make, C++ compiler | Build | External tools, not redistributed |
| Linux UAPI/libc/C++ runtime | Recovery and scanner | Platform dependencies; not vendored |
| llvm-rc, clang, lld-link | Optional PE fixtures | External tools; only synthetic fixture sources are included |

Shield queries system tools when available. Missing tools should produce
limited diagnostics or UNKNOWN results; the project does not install or
redistribute them. See `tools/shield/shield360` for the concrete command list.
The included sysctl configuration is text and is not applied automatically.

Official sources consulted:
- [Qt Licensing](https://doc.qt.io/qt-6.8/licensing.html)
- [Qt LGPL obligations](https://www.qt.io/development/open-source-lgpl-obligations)
- [SQLite Copyright](https://www.sqlite.org/copyright.html)

The 360io source license does not replace library redistribution obligations.
Any future binary package requires a separate review of licenses, notices,
corresponding source, and relinking requirements where applicable.

Entirely excluded: Xenia/XenonRecomp forks and transitive third-party code,
libmspack, SDKs, compatibility runtimes, the recompiled dashboard, and assets
without verifiable authorization. Excluding a fork does not mean it is
proprietary; it avoids transferring its tree, history, and obligations without
a dedicated review. The scanner contains code conditional on liburing, but
that code is not compiled in this configuration and no liburing files are
redistributed.
