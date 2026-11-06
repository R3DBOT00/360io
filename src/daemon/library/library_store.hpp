#pragma once

// SQLite persistence of the library catalog (§9). One writer connection
// (used by the service's writer thread) and one read-only connection for API
// queries. Every catalog change, its library_event rows and the library_seq
// bump happen in the same transaction (§10 invariant 6).

#include "library_types.hpp"

#include <QJsonObject>

#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

struct sqlite3;

namespace threesixty::daemon::library {

inline constexpr int kSchemaVersion = 2;
inline constexpr int kApplicationId = 0x33363069; // "360i"

struct PreviousCandidate {
    std::uint64_t size = 0;
    std::int64_t mtimeNs = 0;
    std::uint64_t ino = 0;
    PeMetadata pe;
};

struct InstallRow {
    std::int64_t installId = 0;
    std::string gameId;
    InstallKind kind = InstallKind::Directory;
    std::string relPath;
    GameState state = GameState::Discovered;
    bool removed = false;
    WatchCoverage coverage = WatchCoverage::Full;
    std::int64_t rootMtimeNs = 0;
    std::uint32_t steamAppId = 0;
    std::string libraryRelPath;
    std::string handle;
};

struct ListGamesQuery {
    std::vector<GameState> states;
    std::optional<InstallKind> kind;
    std::int64_t offset = 0;
    int limit = 50;
};

class LibraryStore
{
public:
    enum class OpenState { Ok, Created, Recreated, FutureVersion, Failed };

    struct OpenReport {
        OpenState state = OpenState::Failed;
        bool needsFullReconcile = false;
        int crashedRuns = 0;
        int resetScanning = 0;
        std::string detail;
        std::string corruptBackupName; // file name only, never the full path
        int migratedFrom = 0;          // user_version before forward migrations (0 = none ran)
        std::string migrationBackupName; // file name only
    };

    LibraryStore() = default;
    ~LibraryStore();
    LibraryStore(const LibraryStore &) = delete;
    LibraryStore &operator=(const LibraryStore &) = delete;

    OpenReport open(const std::string &path);
    void close(bool cleanShutdown);
    bool isOpen() const { return m_db != nullptr; }
    bool readOnly() const { return m_readOnly; }
    static const char *openStateName(OpenState state);

    // --- writer-side API (single thread) ---
    std::string meta(const std::string &key) const;
    void setMeta(const std::string &key, const std::string &value);
    bool dirty() const;
    void setDirty(bool dirty);
    std::int64_t librarySeq() const;

    std::int64_t beginRun(const std::string &kind);
    void finishRun(std::int64_t runId, const std::string &outcome);

    std::optional<InstallRow> findInstall(const InstallKey &key, const DirIdentity &identity,
                                          const std::string &fsUuid) const;
    std::optional<InstallRow> findActiveInstallByRelPath(const std::string &relPath) const;
    std::vector<InstallRow> activeInstalls() const;
    std::map<std::string, PreviousCandidate> previousCandidates(std::int64_t installId) const;

    std::vector<LibraryEvent> applyScanResult(const InstallScanResult &result,
                                              const std::string &fsUuid);
    // Steam manifest seen by discovery: DISCOVERED record (or restore).
    std::vector<LibraryEvent> recordDiscovered(const InstallKey &key, const DirIdentity &identity,
                                               const SteamInfo &steam, const std::string &fsUuid,
                                               std::int64_t *installIdOut = nullptr);
    std::vector<LibraryEvent> recordManifestError(const InstallKey &key, const std::string &reason,
                                                  const std::string &fsUuid,
                                                  std::int64_t *installIdOut = nullptr);
    std::vector<LibraryEvent> transitionInstall(std::int64_t installId,
                                                const std::set<GameState> &from, GameState to,
                                                const std::string &reason);
    std::vector<LibraryEvent> setCoverage(std::int64_t installId, WatchCoverage coverage);
    // Marks active installs not in seen as REMOVED (only after a complete
    // reconciliation with a valid mount).
    std::vector<LibraryEvent> applyRemovals(const std::set<std::int64_t> &seenInstallIds);
    std::vector<LibraryEvent> setUserMainExecutable(const std::string &gameId,
                                                    std::optional<std::int64_t> candidateId,
                                                    std::string &error);
    std::vector<LibraryEvent> appendLibraryEvent(const std::string &type,
                                                 const std::string &payloadJson);
    void purge(std::chrono::seconds tombstoneRetention, std::size_t eventRetention);
    void checkpoint(bool truncate);

    // --- read-side API (any thread) ---
    QJsonObject listGames(const ListGamesQuery &query) const;
    std::optional<QJsonObject> getGame(const std::string &gameId) const;
    // resync = true when since is outside the retained log.
    std::vector<LibraryEvent> eventsSince(std::int64_t since, bool &resync,
                                          std::size_t limit = 5000) const;
    std::map<std::string, int> countsByState() const;
    int partialInstalls() const;
    QJsonObject lastRuns() const;

    // Test hook: run fn inside an open write transaction and never commit
    // (used to simulate a crash between statements).
    void debugBeginTransaction();

private:
    struct Txn;
    std::int64_t nextSeq();
    LibraryEvent addEvent(const std::string &type, const std::string &gameId,
                          const std::string &payloadJson);
    void refreshGame(const std::string &gameId, std::vector<LibraryEvent> &events,
                     const char *forcedEvent = nullptr);
    std::string createGame(GameState state, const std::string &name, const std::string &source,
                           std::uint32_t steamAppId);
    bool exec(const char *sql) const;
    bool createSchema();
    // Forward-only migrations from `from` to kSchemaVersion (§9.3); each step
    // runs in its own transaction. backup = take VACUUM INTO copies first.
    bool migrate(int from, bool backup, std::string &backupName, std::string &error);
    bool openHandles(const std::string &path, bool readOnly, std::string &error);
    void closeHandles();

    sqlite3 *m_db = nullptr;
    sqlite3 *m_reader = nullptr;
    mutable std::mutex m_readerMutex;
    // Writer connection: used by the writer thread and by scan workers for
    // short lookups; SQLite handles are opened NOMUTEX.
    mutable std::recursive_mutex m_dbMutex;
    bool m_readOnly = false;
    std::string m_path;
};

std::string makeUuidV4();

} // namespace threesixty::daemon::library
