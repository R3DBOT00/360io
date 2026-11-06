#pragma once

// Orchestrates the /games library scanner (§4, §5, §9.4, §13): mount
// validation, bootstrap/reconciliation, inotify + debounce/stabilization,
// prioritized scan workers, a single SQLite writer, event fan-out, health
// and progress. The API layer (library_api) only talks to this class.

#include "inotify_watcher.hpp"
#include "install_scanner.hpp"
#include "io_engine.hpp"
#include "library_store.hpp"
#include "library_types.hpp"
#include "safe_fs.hpp"

#include <QJsonObject>

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace threesixty::daemon::library {

enum class ReconcileKind { None = 0, Cheap = 1, Discovery = 2, Full = 3 };

class LibraryService
{
public:
    explicit LibraryService(LibraryConfig config);
    ~LibraryService();
    LibraryService(const LibraryService &) = delete;
    LibraryService &operator=(const LibraryService &) = delete;

    // Opens the database and starts the threads. False only when the
    // database cannot be used at all; missing storage is not an error.
    bool start();
    void stop();

    // --- API (thread-safe) ---
    QJsonObject listGames(const ListGamesQuery &query) const;
    std::optional<QJsonObject> getGame(const std::string &gameId) const;
    struct RescanReply {
        bool ok = false;
        std::string error;
        std::int64_t requestId = 0;
        int queued = 0;
    };
    RescanReply rescan(const std::string &gameId, bool full);
    std::string setMainExecutable(const std::string &gameId, std::optional<std::int64_t> candidateId);
    QJsonObject health() const;
    QJsonObject progress() const;

    using EventSink = std::function<void(const LibraryEvent &)>;
    int subscribe(EventSink sink);
    void unsubscribe(int id);
    std::vector<LibraryEvent> eventsSince(std::int64_t since, bool &resync) const;
    std::int64_t librarySeq() const;

    // --- test hooks ---
    void injectInotifyEvent(RawInotifyEvent event);
    // Drops kernel inotify events while paused (simulates lost events).
    void setInotifyPaused(bool paused);
    bool waitIdle(std::chrono::milliseconds timeout);
    std::uint64_t completedReconciles() const { return m_reconcilesCompleted.load(); }
    std::uint64_t inotifyOverflows() const { return m_overflows.load(); }
    const IoEngine *ioEngine() const { return m_engine.get(); }
    bool storageAvailable() const;

private:
    struct RunTracker {
        std::atomic<int> outstanding{0};
        std::atomic<bool> aborted{false};
    };
    struct Job {
        InstallKey key;
        std::optional<DiscoveredInstall> discovered;
        ScanPriority priority = ScanPriority::Event;
        std::uint64_t generation = 0;
        std::uint64_t order = 0;
        std::shared_ptr<RunTracker> tracker;
    };
    struct Running {
        CancelToken token;
        std::uint64_t generation = 0;
    };
    struct Pending {
        InstallKey key;
        Clock::time_point first;
        Clock::time_point last;
        Clock::time_point lastSnapshot;
        std::optional<InstallSnapshot> snapshot;
        std::string reportedReason;
        std::chrono::milliseconds snapshotInterval{0};
    };
    struct PendingMove {
        std::string from;
        bool isDir = false;
        Clock::time_point at;
    };
    struct RootHandle {
        UniqueFd fd;
        MountCheck mount;
    };
    enum class KeyKind { None, Install, Library };
    struct KeyResult {
        KeyKind kind = KeyKind::None;
        InstallKey key;
        bool isInstallRoot = false;
    };

    // threads
    void coordinatorLoop();
    void reconcilerLoop();
    void workerLoop();
    void writerLoop();

    // writer queue
    void postWrite(std::function<void()> fn, bool mayBlock = true);
    template <typename Fn>
    auto writeSync(Fn &&fn) -> decltype(fn());
    void flushWrites();
    void publish(const std::vector<LibraryEvent> &events);

    // coordinator helpers
    void handleRawEvent(const RawInotifyEvent &event, Clock::time_point now);
    void onTick(Clock::time_point now);
    void markDirty(const std::string &rel, Clock::time_point now);
    void onDeleted(const std::string &rel, bool isDir);
    KeyResult keyFor(const std::string &rel) const;
    void addWatchTree(const std::string &rel);
    // Validates the mount and (re)opens the root. fromReconcile suppresses
    // scheduling another reconciliation.
    void checkMount(bool fromReconcile);

    // scheduling
    void requestReconcile(ReconcileKind kind, bool user = false);
    void requestReconcileLocked(ReconcileKind kind, bool afterDebounce, bool user = false);
    bool enqueue(Job job, bool blocking);
    void bumpGeneration(const std::string &mapKey);
    void finishTracker(const std::shared_ptr<RunTracker> &tracker);
    void abortAll(const char *reason);

    // reconcile steps
    void runReconcile(ReconcileKind kind, bool user);
    void installWatches(const RootHandle &root, const DiscoveryResult &discovery);
    bool confirmAbsent(const RootHandle &root, const InstallRow &row);
    bool cheapDiverges(const RootHandle &root, const DiscoveredInstall &install,
                       const InstallRow &row);
    std::shared_ptr<RootHandle> currentRoot() const;
    WatchCoverage coverageFor(const std::string &mapKey) const;

    void processJob(const Job &job, const CancelToken &token);
    void dropKeyLocked(const std::string &mapKey);

    LibraryConfig m_config;
    LibraryStore m_store;
    LibraryStore::OpenReport m_dbReport;
    std::unique_ptr<SafeOpener> m_opener;
    std::unique_ptr<IoEngine> m_engine;
    std::unique_ptr<InstallScanner> m_scanner;
    InotifyWatcher m_watcher;

    std::atomic<bool> m_stopping{false};
    bool m_started = false;
    int m_wakeFd = -1;
    std::thread m_coordinator;
    std::thread m_reconciler;
    std::thread m_writer;
    std::vector<std::thread> m_workers;

    // Shared scheduling state.
    mutable std::mutex m_mutex;
    std::condition_variable m_jobsCv;
    std::condition_variable m_idleCv;
    std::map<std::string, Job> m_queued;                    // mapKey -> job
    std::set<std::tuple<int, std::uint64_t, std::string>> m_order; // (-prio, order, mapKey)
    std::uint64_t m_nextOrder = 0;
    mutable std::mutex m_genMutex; // guards m_generations; held by the writer while committing
    std::map<std::string, std::uint64_t> m_generations;
    std::map<std::string, Running> m_running;
    std::map<std::string, Pending> m_pending;
    std::map<std::uint32_t, PendingMove> m_pendingMoves;
    std::map<std::string, WatchCoverage> m_coverage;
    std::map<std::pair<std::string, std::string>, std::uint32_t> m_steamDirs; // (lib, installdir) -> appid
    std::set<std::string> m_steamLibraries;
    mutable std::mutex m_rootMutex;
    std::shared_ptr<RootHandle> m_root;
    std::uint64_t m_overflowEpoch = 0;
    bool m_mountCheckRequested = false;
    std::string m_storageState = "UNKNOWN";
    bool m_overflowPending = false;
    std::deque<RawInotifyEvent> m_injected;
    bool m_inotifyPaused = false;

    // Reconcile request state.
    std::condition_variable m_reconcileCv;
    ReconcileKind m_reconcileRequest = ReconcileKind::None;
    bool m_reconcileUser = false;
    Clock::time_point m_reconcileNotBefore{};
    bool m_reconcileRunning = false;
    std::shared_ptr<RunTracker> m_currentRun;
    Clock::time_point m_nextPeriodic{};
    Clock::time_point m_nextMountRetry{};

    // Writer queue.
    std::mutex m_writeMutex;
    std::condition_variable m_writeCv;
    std::condition_variable m_writeSpaceCv;
    std::deque<std::function<void()>> m_writes;
    bool m_writerBusy = false;
    bool m_writerStop = false;

    // Subscribers.
    mutable std::mutex m_subMutex;
    std::map<int, EventSink> m_subscribers;
    int m_nextSubscriber = 1;

    // Progress/metrics.
    mutable std::mutex m_progressMutex;
    std::string m_runKind;
    std::string m_runPhase = "idle";
    std::int64_t m_runId = 0;
    std::int64_t m_runTotal = 0;
    std::atomic<std::int64_t> m_runDone{0};
    std::int64_t m_lastOverflowAt = 0;
    std::atomic<std::int64_t> m_requestIds{0};
    std::atomic<std::uint64_t> m_overflows{0};
    std::atomic<std::uint64_t> m_eventsReceived{0};
    std::atomic<std::uint64_t> m_eventsCoalesced{0};
    std::atomic<std::uint64_t> m_scansCompleted{0};
    std::atomic<std::uint64_t> m_staleResultsDropped{0};
    std::atomic<std::uint64_t> m_reconcilesCompleted{0};
    std::atomic<std::uint64_t> m_ioBackendChangesSeen{0};
};

} // namespace threesixty::daemon::library
