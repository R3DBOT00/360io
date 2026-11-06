# Development

## Building and testing

Requires Linux, CMake >= 3.21, C++20, Qt 6 Core/Network >= 6.4, SQLite3, and
Python >= 3.10. Use your distribution's development packages.
On Debian/Ubuntu: `cmake ninja-build g++ qt6-base-dev libsqlite3-dev python3`.
Run the following commands from the repository root.

```sh
cmake -S . -B ../360io-public-build -G Ninja -DBUILD_TESTING=ON \
  -DTHREESIXTY_LIBRARY_ALLOW_ANY_FS=ON
cmake --build ../360io-public-build
ctest --test-dir ../360io-public-build --output-on-failure
python3 -B scripts/check_public.py
```

The `ALLOW_ANY_FS` option is intended for fixtures and diagnostics. Omit it for
a regular build (default OFF). This edition uses the thread pool I/O backend;
it neither downloads nor links liburing. When LLVM RC, Clang, and LLD are
installed, the tests generate additional PE fixtures in the build directory.
These files are synthetic and are not executed by the scanner.

To build only the detector and also test Shield, without Qt/SQLite:

```sh
cmake -S . -B ../360io-public-minimal -DTHREESIXTY_BUILD_LIBRARY=OFF
cmake --build ../360io-public-minimal
ctest --test-dir ../360io-public-minimal --output-on-failure
```

## Usage

```sh
../360io-public-build/360io-library --help
python3 -B tools/shield/360io-shield --list
../360io-public-build/360io-recovery-detect --dry-run --timeout-ms 0
```

Use the library client's `--offline` mode: its default mode expects a daemon
that is not included in this edition. The detector only reports or writes a
recovery request; it does not install systemd units or start a recovery session.
Shield uses optional external tools and may report UNKNOWN when permissions,
tools, or data are unavailable. Review personal identifiers and paths before
publishing reports from your host.
