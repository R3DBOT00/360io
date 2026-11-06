#pragma once

// Shared configuration and value types of the /games library scanner
// (docs/game-storage-scanner.md). Nothing here touches the filesystem.

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace threesixty::daemon::library {

using Clock = std::chrono::steady_clock;
using std::chrono::milliseconds;

inline constexpr int kRulesetVersion = 2;
inline constexpr int kScorerVersion = 1;

enum class GameState {
    Discovered,
    Stabilizing,
    Scanning,
    Ready,
    Ambiguous,
    Error,
    Removed,
};

const char *gameStateName(GameState state);
std::optional<GameState> gameStateFromName(std::string_view name);

enum class InstallKind { Steam, Directory };
const char *installKindName(InstallKind kind);

enum class MountPolicy {
    // Release behaviour: Ext4 or Btrfs+zstd, root must be its own mount.
    Strict,
    // Developer Preview: same filesystem rules as Strict, but the root may be
    // a plain directory of a larger mount (the installer creates /games as
    // root:games 0775 on the system filesystem).
    Directory,
    // Diagnostics/tests only: any filesystem and any directory is accepted.
    // Never exposed by the daemon unless built with
    // THREESIXTY_LIBRARY_ALLOW_ANY_FS.
    AnyFilesystem,
};

enum class IoBackendPreference { Auto, ThreadPool, IoUring };

enum class ScanPriority : int { Periodic = 0, Bootstrap = 1, Event = 2, User = 3 };

struct LibraryConfig {
    std::string rootPath = "/games";
    std::string databasePath = "/var/lib/360io/library/library.db";

    MountPolicy mountPolicy = MountPolicy::Strict;
    bool allowBtrfsWithoutZstd = false;
    std::string expectedFsUuid;

    IoBackendPreference ioBackend = IoBackendPreference::Auto;
    std::string ioUringDisabledSysctl = "/proc/sys/kernel/io_uring_disabled";
    // Test hooks: pretend io_uring_queue_init failed with this -errno, or
    // make the ring fail at runtime after N submissions (0 = off).
    int simulateIoUringInitError = 0;
    int simulateIoUringRuntimeFailureAfter = 0;
    // Test hook: pretend openat2 is not available (ENOSYS).
    bool forceOpenat2Fallback = false;

    unsigned threadPoolSize = 4;
    unsigned ringEntries = 256;
    unsigned maxInflight = 64;
    milliseconds ioTimeout{5000};

    unsigned installConcurrency = 4;
    unsigned maxCandidateDepth = 6;
    unsigned maxWalkDepth = 16;
    std::size_t maxEntriesPerInstall = 200000;
    std::size_t maxCandidatesPerInstall = 256;
    std::size_t maxSnapshotEntries = 50000;
    std::uint32_t maxPeReadBytes = 2u * 1024 * 1024;
    std::uint32_t maxVersionResourceBytes = 64u * 1024;
    std::uint32_t maxAcfBytes = 256u * 1024;
    unsigned maxOpenFds = 256;
    std::uint64_t bufferBudgetBytes = 64ull * 1024 * 1024;
    milliseconds installTimeout{60000};

    unsigned watchBudget = 32768;
    milliseconds renamePairWindow{500};
    milliseconds debounce{2000};
    milliseconds quietWindow{10000};
    milliseconds tick{250};
    milliseconds stabilizationMax{30 * 60 * 1000};
    milliseconds periodicRescanInterval{6 * 60 * 60 * 1000};
    milliseconds mountRetryInterval{30000};

    int minScore = 25;
    int ambiguityMargin = 10;
    unsigned maxExposedCandidates = 8;

    std::size_t eventLogRetention = 10000;
    std::chrono::seconds tombstoneRetention{30 * 24 * 60 * 60};

    std::size_t scanQueueCapacity = 4096;
    std::size_t ioQueueCapacity = 256;
    std::size_t commitQueueCapacity = 512;

    // Preferred VS_VERSION_INFO language (LANGID); 0 = derive from LANG.
    std::uint16_t preferredLanguage = 0;
};

// Physical identity of an install root (§6).
struct DirIdentity {
    std::string handle; // name_to_handle_at bytes (type + f_handle), empty if unsupported
    std::uint64_t ino = 0;
    std::int64_t btimeNs = 0; // 0 when statx cannot report birth time
    std::int64_t mtimeNs = 0;
    std::uint64_t dev = 0;
};

// Something the scanner can scan: a top-level directory or a Steam app.
struct InstallKey {
    InstallKind kind = InstallKind::Directory;
    std::string relPath;        // raw bytes, relative to root, no leading '/'
    std::string libraryRelPath; // Steam library dir (raw bytes), "" = root itself
    std::uint32_t steamAppId = 0;

    // Stable string used for maps (debounce, generations, queue dedupe).
    std::string mapKey() const;
    bool operator==(const InstallKey &other) const = default;
};

struct SteamInfo {
    std::uint32_t appId = 0;
    std::string name; // sanitized
    std::string installDir; // raw component
    std::uint32_t stateFlags = 0;
    std::int64_t lastUpdated = 0;
    std::uint64_t sizeOnDisk = 0;
    std::string buildId;
    std::int64_t manifestMtimeNs = 0;
};

struct PeMetadata {
    bool validPe = false;
    std::string parseError; // empty = ok; reason slug otherwise
    std::uint16_t machine = 0;
    std::uint16_t subsystem = 0;
    std::uint16_t characteristics = 0;
    std::uint32_t timestamp = 0;
    bool isDll = false;
    bool hasVersionInfo = false;
    std::string productName;
    std::string fileDescription;
    std::string companyName;
    std::string productVersion;
    std::string fileVersion;
    std::string originalFilename;
    std::string internalName;
};

struct ExeCandidate {
    std::string relPath; // raw bytes relative to install root
    std::uint64_t size = 0;
    std::int64_t mtimeNs = 0;
    std::uint64_t ino = 0;
    unsigned depth = 0;
    PeMetadata pe;
    std::string excludedBy; // rule id when hard-excluded
    int score = 0;
    std::string featuresJson;
    bool reusedMetadata = false;
};

enum class WatchCoverage { Full, Partial, None };
const char *watchCoverageName(WatchCoverage coverage);

struct InstallScanResult {
    InstallKey key;
    std::uint64_t generation = 0;
    DirIdentity identity;
    std::optional<SteamInfo> steam;
    GameState state = GameState::Error;
    std::string reason;
    std::string displayName;
    std::string displayNameSource;
    std::vector<ExeCandidate> candidates; // sorted by score desc
    std::optional<std::size_t> mainCandidate; // index into candidates
    std::size_t candidatesTruncated = 0;
    bool entriesTruncated = false;
    WatchCoverage coverage = WatchCoverage::Full;
    // True when the directory is not a game at all (no PE candidate and not
    // a Steam manifest). Such keys never create a game record.
    bool notAGame = false;
    // True when the install root disappeared while scanning.
    bool vanished = false;
    // Temporary copy markers (.part, .tmp, ...) or a Steam download in progress.
    bool tempMarkers = false;
    bool cancelled = false;
    std::uint64_t peBytesRead = 0;
};

struct LibraryEvent {
    std::int64_t seq = 0;
    std::int64_t at = 0; // unix ms
    std::string type;
    std::string gameId;
    std::string payloadJson; // sanitized, relative paths only
};

std::int64_t unixMillisNow();

} // namespace threesixty::daemon::library
