# Game library

`src/daemon/library` contains a VDF/ACF parser, a PE metadata parser, executable
selection rules, name normalization, filesystem access, thread pool I/O,
inotify support, SQLite persistence, an indexing service, and a local Qt API.
The scanner reads metadata; it does not execute games or PE fixtures.

`src/library_cli/main.cpp` provides the client. See `360io-library --help` for
commands and arguments. In this edition, use `--offline` and specify the desired
root and database; 360iod is not distributed. Offline mode writes to its SQLite
database. Do not use a personal game library to run tests.

Tests create temporary directories and synthetic data. The build option
`THREESIXTY_LIBRARY_ALLOW_ANY_FS=ON` enables CLI testing in those directories.
It should not be enabled by default in production packages. Numbered section
references in source comments refer to the private design document, which was
not exported.

This edition does not distribute games, dumps, personal catalogs, or third-party
executables. CMake does not download dependencies.
