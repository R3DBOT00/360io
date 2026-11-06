# 360io

360io is a Linux console environment project designed to bring a living-room
gaming experience to the PC. It aims to bring controller navigation, profiles,
a game library, and system services together in a dedicated interface.

The project is based on CachyOS, with an architecture built around Gamescope
and Qt Quick. Its vision is a distribution with its own session, a graphical
installer, and desktop environment options, while retaining access to Linux
capabilities.

## Project goals

- **Console experience:** an interface designed for controller navigation and living-room use.
- **Local game library:** discovery and organization of games installed on the computer.
- **System integration:** coordination of profiles, devices, media, and session state.
- **Accessible maintenance:** diagnostic and recovery tools for managing the environment.

## Project status

360io is under development, with components implemented and validated in stages.
The complete distribution and integrated console experience remain the project's
goal. This public edition makes part of its foundation available.

## In this repository

| Component | Purpose |
| --- | --- |
| Game library | Discovers local installations, reads metadata, and maintains a SQLite catalog. |
| Library client | Provides command-line access to the scanner for offline use and testing. |
| Recovery detector | Identifies recovery requests through boot parameters or the Shift key. |
| 360io Shield | Audits host configuration and reports security diagnostics. |
| Tests | Validate components using temporary directories and synthetic data. |

The complete interface, integrated daemon, and installation image are not yet
part of this public edition. This repository contains selected project code;
it does not distribute firmware, games, keys, dumps, or proprietary assets.

## Learn more

- [Game library](docs/game-storage-scanner.md)
- [Development, building, and testing](docs/DEVELOPMENT.md)
- [Dependencies and licenses](docs/DEPENDENCIES.md)
- [Public edition scope and audit](docs/PUBLICATION.md)

## License

The project code in this edition is available under the [MIT License](LICENSE).
Dependencies retain their respective licenses.
