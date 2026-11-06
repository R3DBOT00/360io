#include "library_service.hpp"

#include "acf_parser.hpp"
#include "sanitize.hpp"

#include <QDebug>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLoggingCategory>

#include <cerrno>
#include <future>
#include <random>

#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <unistd.h>

Q_LOGGING_CATEGORY(lcLibrary, "threesixty.library")

namespace threesixty::daemon::library {

namespace {

using namespace std::chrono_literals;

std::vector<std::string> splitRel(const std::string &rel)
{
    std::vector<std::string> parts;
    std::size_t start = 0;
    while (start <= rel.size()) {
        const std::size_t slash = rel.find('/', start);
        const std::size_t end = slash == std::string::npos ? rel.size() : slash;
        if (end > start) {
            parts.push_back(rel.substr(start, end - start));
        }
        if (slash == std::string::npos) {
            break;
        }
        start = slash + 1;
    }
    return parts;
}

bool skipTopLevel(const std::string &name)
{
    return name.empty() || name.front() == '.' || name == "lost+found";
}

std::string json(const QJsonObject &object)
{
    return QJsonDocument(object).toJson(QJsonDocument::Compact).toStdString();
}

const char *reconcileKindName(ReconcileKind kind, bool user, bool dirty)
{
    if (user) {
        return kind == ReconcileKind::Full ? "USER" : "USER_CHEAP";
    }
    switch (kind) {
    case ReconcileKind::Full:
        return dirty ? "RECONCILE" : "FULL";
    case ReconcileKind::Discovery:
        return "EVENT";
    case ReconcileKind::Cheap:
        return "PERIODIC";
    case ReconcileKind::None:
        break;
    }
    return "NONE";
}

std::chrono::milliseconds jittered(std::chrono::milliseconds base)
{
    static std::mt19937_64 rng(std::random_device{}());
    std::uniform_real_distribution<double> dist(0.9, 1.1);
    return std::chrono::milliseconds(static_cast<std::int64_t>(double(base.count()) * dist(rng)));
}

} // namespace

LibraryService::LibraryService(LibraryConfig config)
    : m_config(std::move(config))
{
}

LibraryService::~LibraryService()
{
    stop();
}

bool LibraryService::start()
{
    if (m_started) {
        return true;
    }
    m_dbReport = m_store.open(m_config.databasePath);
    if (m_dbReport.state == LibraryStore::OpenState::Failed) {
        qCWarning(lcLibrary).noquote() << "library: database unavailable:" << m_dbReport.detail.c_str();
        return false;
    }
    m_opener = std::make_unique<SafeOpener>(m_config.forceOpenat2Fallback);
    m_engine = std::make_unique<IoEngine>(m_config, *m_opener);
    m_scanner = std::make_unique<InstallScanner>(m_config, *m_engine, *m_opener);
    if (!m_watcher.init(m_config.watchBudget)) {
        qCWarning(lcLibrary) << "library: inotify unavailable; relying on periodic rescans";
    }
    m_wakeFd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    qCInfo(lcLibrary).noquote() << "library: io backend" << ioBackendKindName(m_engine->kind())
                                << "reason" << m_engine->reason().c_str() << "openat2"
                                << (m_opener->usesOpenat2() ? "yes" : "fallback") << "db"
                                << LibraryStore::openStateName(m_dbReport.state);

    m_started = true;
    m_stopping = false;
    m_writerStop = false;
    m_writer = std::thread([this] { writerLoop(); });
    for (unsigned i = 0; i < std::max(1u, m_config.installConcurrency); ++i) {
        m_workers.emplace_back([this] { workerLoop(); });
    }
    m_reconciler = std::thread([this] { reconcilerLoop(); });
    m_coordinator = std::thread([this] { coordinatorLoop(); });

    {
        std::lock_guard lock(m_mutex);
        m_nextPeriodic = Clock::now() + jittered(m_config.periodicRescanInterval);
    }
    if (!m_store.readOnly()) {
        // A new filter ruleset changes which executables are excluded, so
        // every install is rescored once (full reconcile) after an upgrade.
        const std::string ruleset = std::to_string(kRulesetVersion);
        const bool rulesetChanged = m_store.meta("ruleset_version") != ruleset;
        if (rulesetChanged) {
            m_store.setMeta("ruleset_version", ruleset);
        }
        requestReconcile(m_dbReport.needsFullReconcile || rulesetChanged ? ReconcileKind::Full
                                                                         : ReconcileKind::Cheap);
    }
    return true;
}

void LibraryService::stop()
{
    if (!m_started) {
        return;
    }
    m_stopping = true;
    {
        std::lock_guard lock(m_mutex);
        abortAll("SHUTDOWN");
    }
    m_jobsCv.notify_all();
    m_reconcileCv.notify_all();
    m_idleCv.notify_all();
    if (m_wakeFd >= 0) {
        const std::uint64_t one = 1;
        [[maybe_unused]] const ssize_t n = ::write(m_wakeFd, &one, sizeof one);
    }
    if (m_coordinator.joinable()) {
        m_coordinator.join();
    }
    if (m_reconciler.joinable()) {
        m_reconciler.join();
    }
    for (std::thread &worker : m_workers) {
        worker.join();
    }
    m_workers.clear();
    {
        std::lock_guard lock(m_writeMutex);
        m_writerStop = true;
    }
    m_writeCv.notify_all();
    m_writeSpaceCv.notify_all();
    if (m_writer.joinable()) {
        m_writer.join();
    }
    m_store.close(true);
    m_scanner.reset();
    m_engine.reset();
    if (m_wakeFd >= 0) {
        ::close(m_wakeFd);
        m_wakeFd = -1;
    }
    m_started = false;
}

// ---------------------------------------------------------------- writer ---

void LibraryService::postWrite(std::function<void()> fn, bool mayBlock)
{
    std::unique_lock lock(m_writeMutex);
    if (m_writerStop) {
        return;
    }
    if (mayBlock) {
        m_writeSpaceCv.wait(lock, [this] {
            return m_writerStop || m_writes.size() < std::max<std::size_t>(1, m_config.commitQueueCapacity);
        });
    }
    m_writes.push_back(std::move(fn));
    m_writeCv.notify_one();
}

template <typename Fn>
auto LibraryService::writeSync(Fn &&fn) -> decltype(fn())
{
    using Result = decltype(fn());
    auto task = std::make_shared<std::packaged_task<Result()>>(std::forward<Fn>(fn));
    std::future<Result> future = task->get_future();
    bool posted = false;
    {
        std::unique_lock lock(m_writeMutex);
        if (!m_writerStop) {
            m_writeSpaceCv.wait(lock, [this] {
                return m_writerStop || m_writes.size() < std::max<std::size_t>(1, m_config.commitQueueCapacity);
            });
            if (!m_writerStop) {
                m_writes.push_back([task] { (*task)(); });
                posted = true;
            }
        }
    }
    if (!posted) {
        (*task)();
    } else {
        m_writeCv.notify_one();
    }
    return future.get();
}

void LibraryService::flushWrites()
{
    writeSync([] { return 0; });
}

void LibraryService::writerLoop()
{
    const auto drainDeadlineDefault = Clock::time_point::max();
    auto drainDeadline = drainDeadlineDefault;
    while (true) {
        std::function<void()> fn;
        {
            std::unique_lock lock(m_writeMutex);
            m_writeCv.wait(lock, [this] { return m_writerStop || !m_writes.empty(); });
            if (m_writerStop && drainDeadline == drainDeadlineDefault) {
                drainDeadline = Clock::now() + 5s; // SIGTERM drain budget (§13)
            }
            if (m_writes.empty() || Clock::now() > drainDeadline) {
                if (m_writerStop) {
                    m_writes.clear();
                    m_writeSpaceCv.notify_all();
                    return;
                }
                continue;
            }
            fn = std::move(m_writes.front());
            m_writes.pop_front();
            m_writerBusy = true;
        }
        m_writeSpaceCv.notify_one();
        fn();
        {
            std::lock_guard lock(m_writeMutex);
            m_writerBusy = false;
        }
        m_idleCv.notify_all();
    }
}

void LibraryService::publish(const std::vector<LibraryEvent> &events)
{
    if (events.empty()) {
        return;
    }
    std::lock_guard lock(m_subMutex);
    for (const LibraryEvent &event : events) {
        for (auto &[id, sink] : m_subscribers) {
            sink(event);
        }
    }
}

// ------------------------------------------------------------ scheduling ---

std::shared_ptr<LibraryService::RootHandle> LibraryService::currentRoot() const
{
    std::lock_guard lock(m_rootMutex);
    return m_root;
}

bool LibraryService::storageAvailable() const
{
    return currentRoot() != nullptr;
}

WatchCoverage LibraryService::coverageFor(const std::string &mapKey) const
{
    std::lock_guard lock(m_mutex);
    if (m_watcher.fd() < 0) {
        return WatchCoverage::None;
    }
    auto it = m_coverage.find(mapKey);
    return it == m_coverage.end() ? WatchCoverage::Full : it->second;
}

void LibraryService::finishTracker(const std::shared_ptr<RunTracker> &tracker)
{
    if (tracker) {
        tracker->outstanding.fetch_sub(1);
        m_runDone.fetch_add(1);
        m_idleCv.notify_all();
    }
}

void LibraryService::bumpGeneration(const std::string &mapKey)
{
    // Caller holds m_mutex.
    {
        std::lock_guard gen(m_genMutex);
        ++m_generations[mapKey];
    }
    auto running = m_running.find(mapKey);
    if (running != m_running.end()) {
        m_engine->cancel(running->second.token);
    }
    auto queued = m_queued.find(mapKey);
    if (queued != m_queued.end()) {
        m_order.erase({-int(queued->second.priority), queued->second.order, mapKey});
        finishTracker(queued->second.tracker);
        m_queued.erase(queued);
    }
}

void LibraryService::dropKeyLocked(const std::string &mapKey)
{
    bumpGeneration(mapKey);
    m_pending.erase(mapKey);
}

bool LibraryService::enqueue(Job job, bool blocking)
{
    const std::string mapKey = job.key.mapKey();
    std::unique_lock lock(m_mutex);
    if (blocking) {
        // Backpressure towards the walker/reconciler.
        m_idleCv.wait(lock, [&] {
            return m_stopping || (job.tracker && job.tracker->aborted) ||
                m_queued.size() < std::max<std::size_t>(1, m_config.scanQueueCapacity) ||
                m_queued.contains(mapKey);
        });
        if (m_stopping || (job.tracker && job.tracker->aborted)) {
            finishTracker(job.tracker);
            return false;
        }
    } else if (m_queued.size() >= std::max<std::size_t>(1, m_config.scanQueueCapacity) &&
               !m_queued.contains(mapKey)) {
        return false;
    }
    auto existing = m_queued.find(mapKey);
    if (existing != m_queued.end()) {
        if (int(existing->second.priority) > int(job.priority)) {
            job.priority = existing->second.priority;
        }
        m_order.erase({-int(existing->second.priority), existing->second.order, mapKey});
        finishTracker(existing->second.tracker);
        m_queued.erase(existing);
    }
    {
        std::lock_guard gen(m_genMutex);
        job.generation = ++m_generations[mapKey];
    }
    auto running = m_running.find(mapKey);
    if (running != m_running.end()) {
        m_engine->cancel(running->second.token); // superseded by the new generation
    }
    job.order = ++m_nextOrder;
    m_order.insert({-int(job.priority), job.order, mapKey});
    m_queued.emplace(mapKey, std::move(job));
    m_jobsCv.notify_one();
    return true;
}

void LibraryService::abortAll(const char *reason)
{
    // Caller holds m_mutex.
    for (auto &[key, job] : m_queued) {
        finishTracker(job.tracker);
    }
    m_queued.clear();
    m_order.clear();
    {
        std::lock_guard gen(m_genMutex);
        for (auto &[key, running] : m_running) {
            ++m_generations[key];
        }
    }
    for (auto &[key, running] : m_running) {
        if (m_engine) {
            m_engine->cancel(running.token);
        }
    }
    if (m_currentRun) {
        m_currentRun->aborted = true;
    }
    m_pending.clear();
    m_pendingMoves.clear();
    qCInfo(lcLibrary) << "library: pipeline aborted, reason" << reason;
    m_idleCv.notify_all();
}

void LibraryService::requestReconcile(ReconcileKind kind, bool user)
{
    std::lock_guard lock(m_mutex);
    requestReconcileLocked(kind, false, user);
}

void LibraryService::requestReconcileLocked(ReconcileKind kind, bool afterDebounce, bool user)
{
    if (int(kind) > int(m_reconcileRequest)) {
        m_reconcileRequest = kind;
    }
    m_reconcileUser = m_reconcileUser || user;
    const auto notBefore = afterDebounce ? Clock::now() + m_config.debounce : Clock::now();
    if (m_reconcileNotBefore < Clock::now() || !afterDebounce) {
        m_reconcileNotBefore = afterDebounce ? notBefore : Clock::now();
    }
    m_reconcileCv.notify_all();
}

// ---------------------------------------------------------------- mount ---

void LibraryService::checkMount(bool fromReconcile)
{
    const MountCheck check = validateLibraryMount(m_config);
    std::vector<std::function<void()>> writes;
    {
        std::lock_guard lock(m_mutex);
        std::shared_ptr<RootHandle> previous = currentRoot();
        if (check.state == MountState::Ok) {
            if (previous && previous->mount.mountId == check.mountId) {
                m_storageState = "AVAILABLE";
                return;
            }
            UniqueFd fd(::open(m_config.rootPath.c_str(),
                               O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
            if (!fd.valid()) {
                m_storageState = "MOUNT_ABSENT";
                return;
            }
            if (previous) {
                abortAll("REMOUNT");
                m_watcher.clear();
                m_coverage.clear();
            }
            auto root = std::make_shared<RootHandle>();
            root->fd = std::move(fd);
            root->mount = check;
            {
                std::lock_guard rootLock(m_rootMutex);
                m_root = root;
            }
            const bool wasUnavailable = m_storageState != "AVAILABLE";
            m_storageState = "AVAILABLE";
            if (wasUnavailable && !m_store.readOnly()) {
                QJsonObject payload{{QStringLiteral("fs_type"), QString::fromStdString(check.fsType)},
                                    {QStringLiteral("read_only"), check.readOnly}};
                writes.push_back([this, payload] {
                    m_store.setMeta("fs_uuid", currentRoot() ? currentRoot()->mount.fsUuid : "");
                    publish(m_store.appendLibraryEvent("storage.available", json(payload)));
                });
            }
            if (!fromReconcile && (previous || wasUnavailable)) {
                requestReconcileLocked(ReconcileKind::Full, false);
            }
        } else {
            const std::string state = mountStateName(check.state);
            if (previous) {
                // Media gone: cancel everything, keep games (absence != removal).
                abortAll("STORAGE_UNAVAILABLE");
                {
                    std::lock_guard rootLock(m_rootMutex);
                    m_root.reset();
                }
                m_watcher.clear();
                m_coverage.clear();
            }
            if (m_storageState != state && !m_store.readOnly()) {
                QJsonObject payload{{QStringLiteral("reason"), QString::fromStdString(state)}};
                writes.push_back([this, payload] {
                    m_store.setDirty(true);
                    publish(m_store.appendLibraryEvent("storage.unavailable", json(payload)));
                });
            }
            m_storageState = state;
            m_nextMountRetry = Clock::now() + m_config.mountRetryInterval;
        }
    }
    for (auto &write : writes) {
        postWrite(std::move(write), false);
    }
}

// ----------------------------------------------------------- coordinator ---

LibraryService::KeyResult LibraryService::keyFor(const std::string &rel) const
{
    // Caller holds m_mutex.
    KeyResult result;
    const std::vector<std::string> parts = splitRel(rel);
    if (parts.empty() || skipTopLevel(parts[0])) {
        return result;
    }
    std::string library;
    std::size_t rest = 0;
    bool isLibrary = false;
    if (parts[0] == "steamapps" && m_steamLibraries.contains("")) {
        isLibrary = true;
        rest = 0;
    } else if (m_steamLibraries.contains(parts[0])) {
        isLibrary = true;
        library = parts[0];
        rest = 1;
    }
    if (isLibrary) {
        if (parts.size() <= rest || parts[rest] != "steamapps") {
            result.kind = parts.size() <= rest ? KeyKind::Library : KeyKind::None;
            return result;
        }
        const std::size_t sub = rest + 1;
        if (parts.size() <= sub) {
            result.kind = KeyKind::Library;
            return result;
        }
        result.key.kind = InstallKind::Steam;
        result.key.libraryRelPath = library;
        if (const auto appId = appIdFromManifestName(parts[sub])) {
            result.kind = KeyKind::Install;
            result.key.steamAppId = *appId;
            result.isInstallRoot = parts.size() == sub + 1;
            return result;
        }
        if (parts[sub] == "common" && parts.size() > sub + 1) {
            auto it = m_steamDirs.find({library, parts[sub + 1]});
            if (it == m_steamDirs.end()) {
                result.kind = KeyKind::Library;
                return result;
            }
            result.kind = KeyKind::Install;
            result.key.steamAppId = it->second;
            result.key.relPath = joinRel(joinRel(joinRel(library, "steamapps"), "common"), parts[sub + 1]);
            result.isInstallRoot = parts.size() == sub + 2;
            return result;
        }
        if (parts[sub] == "downloading" && parts.size() > sub + 1) {
            std::uint32_t appId = 0;
            try {
                appId = static_cast<std::uint32_t>(std::stoul(parts[sub + 1]));
            } catch (...) {
                return result;
            }
            result.kind = KeyKind::Install;
            result.key.steamAppId = appId;
            return result;
        }
        return result;
    }
    if (parts.size() >= 2 && parts[1] == "steamapps") {
        result.kind = KeyKind::Library; // a new Steam library appeared
        return result;
    }
    result.kind = KeyKind::Install;
    result.key.kind = InstallKind::Directory;
    result.key.relPath = parts[0];
    result.isInstallRoot = parts.size() == 1;
    return result;
}

void LibraryService::markDirty(const std::string &rel, Clock::time_point now)
{
    // Caller holds m_mutex.
    const KeyResult kr = keyFor(rel);
    if (kr.kind == KeyKind::Library) {
        requestReconcileLocked(ReconcileKind::Discovery, true);
        return;
    }
    if (kr.kind != KeyKind::Install) {
        return;
    }
    const std::string mapKey = kr.key.mapKey();
    bumpGeneration(mapKey);
    auto [it, inserted] = m_pending.try_emplace(mapKey);
    Pending &pending = it->second;
    if (inserted) {
        pending.key = kr.key;
        pending.first = now;
        pending.snapshotInterval = std::max<std::chrono::milliseconds>(m_config.debounce / 2, m_config.tick);
        const InstallKey key = kr.key;
        const std::string fsUuid = currentRoot() ? currentRoot()->mount.fsUuid : std::string();
        postWrite([this, key, fsUuid] {
            std::optional<InstallRow> row = key.kind == InstallKind::Steam
                ? m_store.findInstall(key, DirIdentity{}, fsUuid)
                : m_store.findActiveInstallByRelPath(key.relPath);
            if (row && !row->removed) {
                publish(m_store.transitionInstall(
                    row->installId,
                    {GameState::Discovered, GameState::Ready, GameState::Ambiguous, GameState::Error,
                     GameState::Scanning},
                    GameState::Stabilizing, "CHANGED"));
            }
        }, false);
    } else {
        m_eventsCoalesced.fetch_add(1);
    }
    if (kr.key.kind == InstallKind::Steam && !kr.key.relPath.empty()) {
        pending.key.relPath = kr.key.relPath;
    }
    pending.last = now;
}

void LibraryService::onDeleted(const std::string &rel, bool isDir)
{
    // Caller holds m_mutex.
    const KeyResult kr = keyFor(rel);
    if (kr.kind == KeyKind::Install && kr.isInstallRoot) {
        dropKeyLocked(kr.key.mapKey());
        if (isDir) {
            m_watcher.removeTree(rel);
        }
        requestReconcileLocked(ReconcileKind::Discovery, true);
        return;
    }
    markDirty(rel, Clock::now());
}

void LibraryService::addWatchTree(const std::string &rel)
{
    std::shared_ptr<RootHandle> root = currentRoot();
    if (!root || m_watcher.fd() < 0) {
        return;
    }
    std::deque<std::pair<std::string, unsigned>> queue;
    queue.emplace_back(rel, 0);
    const KeyResult kr = keyFor(rel);
    while (!queue.empty()) {
        auto [dir, depth] = std::move(queue.front());
        queue.pop_front();
        const auto added = m_watcher.addWatch(root->fd.get(), *m_opener, dir);
        if (added == InotifyWatcher::AddResult::BudgetExhausted) {
            if (kr.kind == KeyKind::Install) {
                m_coverage[kr.key.mapKey()] = WatchCoverage::Partial;
            }
            return;
        }
        if (added == InotifyWatcher::AddResult::Failed || depth >= m_config.maxWalkDepth) {
            continue;
        }
        UniqueFd fd(m_opener->openBeneath(root->fd.get(), dir, true));
        if (!fd.valid()) {
            continue;
        }
        std::vector<DirEntryRaw> entries;
        bool truncated = false;
        listDirectory(fd.get(), m_config.maxEntriesPerInstall, entries, truncated);
        for (const DirEntryRaw &entry : entries) {
            if (entry.type == DT_DIR) {
                queue.emplace_back(joinRel(dir, entry.name), depth + 1);
            }
        }
    }
}

void LibraryService::handleRawEvent(const RawInotifyEvent &event, Clock::time_point now)
{
    // Caller holds m_mutex.
    m_eventsReceived.fetch_add(1);
    if (event.mask & IN_Q_OVERFLOW) {
        // Everything pending is unreliable: full reconciliation, no
        // incremental decisions until it finishes (§4.3, invariant 5).
        m_overflows.fetch_add(1);
        m_lastOverflowAt = unixMillisNow();
        ++m_overflowEpoch;
        m_pending.clear();
        m_pendingMoves.clear();
        m_overflowPending = true;
        if (!m_store.readOnly()) {
            postWrite([this] { m_store.setDirty(true); }, false);
        }
        requestReconcileLocked(ReconcileKind::Full, false);
        qCWarning(lcLibrary) << "library: inotify queue overflow; full reconciliation scheduled";
        return;
    }
    if (event.mask & IN_IGNORED) {
        m_watcher.removeWd(event.wd);
        return;
    }
    if (event.mask & IN_UNMOUNT) {
        m_mountCheckRequested = true;
        return;
    }
    const std::optional<std::string> base = m_watcher.relFor(event.wd);
    if (!base) {
        return;
    }
    if (event.mask & (IN_DELETE_SELF | IN_MOVE_SELF)) {
        if (base->empty()) {
            m_mountCheckRequested = true; // the root itself went away
        }
        return;
    }
    const std::string full = joinRel(*base, event.name);
    const bool isDir = (event.mask & IN_ISDIR) != 0;

    if (event.mask & IN_MOVED_FROM) {
        m_pendingMoves[event.cookie] = PendingMove{full, isDir, now};
        return;
    }
    if (event.mask & IN_MOVED_TO) {
        auto move = m_pendingMoves.find(event.cookie);
        if (move != m_pendingMoves.end()) {
            const PendingMove from = move->second;
            m_pendingMoves.erase(move);
            if (isDir) {
                m_watcher.renamePrefix(from.from, full);
            }
            const KeyResult oldKey = keyFor(from.from);
            const KeyResult newKey = keyFor(full);
            if (oldKey.kind == KeyKind::Install && oldKey.isInstallRoot &&
                oldKey.key.mapKey() != newKey.key.mapKey()) {
                // Install root renamed: identity (file handle) keeps its
                // install_id/game_id when the new name is scanned.
                dropKeyLocked(oldKey.key.mapKey());
                if (!(newKey.kind == KeyKind::Install && newKey.isInstallRoot)) {
                    requestReconcileLocked(ReconcileKind::Discovery, true);
                }
            } else if (oldKey.kind != KeyKind::None) {
                markDirty(from.from, now);
            }
            if (isDir) {
                addWatchTree(full);
            }
            markDirty(full, now);
            return;
        }
        if (isDir) {
            addWatchTree(full);
        }
        markDirty(full, now);
        return;
    }
    if (event.mask & IN_CREATE) {
        if (isDir) {
            addWatchTree(full); // files created before the watch are caught by the scan
        }
        markDirty(full, now);
        return;
    }
    if (event.mask & IN_DELETE) {
        onDeleted(full, isDir);
        return;
    }
    if (event.mask & (IN_CLOSE_WRITE | IN_ATTRIB)) {
        markDirty(full, now);
    }
}

void LibraryService::onTick(Clock::time_point now)
{
    struct Due {
        std::string mapKey;
        InstallKey key;
        Clock::time_point last;
    };
    std::vector<Due> due;
    bool mountCheck = false;
    {
        std::lock_guard lock(m_mutex);
        for (auto it = m_pendingMoves.begin(); it != m_pendingMoves.end();) {
            if (now - it->second.at >= m_config.renamePairWindow) {
                // Unpaired MOVED_FROM: removal candidate (confirmed only by reconciliation).
                const PendingMove move = it->second;
                it = m_pendingMoves.erase(it);
                if (move.isDir) {
                    m_watcher.removeTree(move.from);
                }
                onDeleted(move.from, move.isDir);
            } else {
                ++it;
            }
        }
        if (now >= m_nextPeriodic) {
            m_nextPeriodic = now + jittered(m_config.periodicRescanInterval);
            requestReconcileLocked(ReconcileKind::Cheap, false);
        }
        if (m_mountCheckRequested || (m_storageState != "AVAILABLE" && now >= m_nextMountRetry &&
                                      m_nextMountRetry != Clock::time_point{})) {
            m_mountCheckRequested = false;
            mountCheck = true;
        }
        if (!m_overflowPending && currentRoot()) {
            for (auto &[mapKey, pending] : m_pending) {
                if (now - pending.last >= m_config.debounce &&
                    now - pending.lastSnapshot >= pending.snapshotInterval) {
                    due.push_back({mapKey, pending.key, pending.last});
                }
            }
        }
    }
    if (mountCheck) {
        checkMount(false);
    }
    const std::uint64_t changes = m_engine->backendChanges();
    if (changes != m_ioBackendChangesSeen.exchange(changes) && !m_store.readOnly()) {
        QJsonObject payload{{QStringLiteral("io_backend"), QString::fromLatin1(ioBackendKindName(m_engine->kind()))},
                            {QStringLiteral("reason"), QString::fromStdString(m_engine->reason())}};
        postWrite([this, payload] { publish(m_store.appendLibraryEvent("health.changed", json(payload))); }, false);
    }
    if (due.empty()) {
        return;
    }
    std::shared_ptr<RootHandle> root = currentRoot();
    if (!root) {
        return;
    }

    struct Evaluated {
        Due due;
        InstallSnapshot snapshot;
        bool steamOk = true;
        bool manifestBroken = false;
        InstallKey resolved;
    };
    std::vector<Evaluated> evaluated;
    for (Due &d : due) {
        Evaluated e{d, {}, true, false, d.key};
        if (d.key.kind == InstallKind::Steam) {
            const auto install = m_scanner->discoverOne(root->fd.get(), d.key);
            if (!install) {
                e.snapshot.exists = false;
                evaluated.push_back(std::move(e));
                continue;
            }
            e.resolved = install->key;
            e.manifestBroken = !install->manifestError.empty();
            e.steamOk = e.manifestBroken ||
                (install->steam && (install->steam->stateFlags & kSteamStateFullyInstalled));
        }
        e.snapshot = e.manifestBroken ? InstallSnapshot{true} : m_scanner->snapshot(root->fd.get(), e.resolved);
        if (e.manifestBroken) {
            e.snapshot.exists = true;
        }
        evaluated.push_back(std::move(e));
    }

    std::vector<Job> jobs;
    std::vector<std::pair<std::string, std::string>> reasons; // mapKey, reason
    {
        std::lock_guard lock(m_mutex);
        if (m_overflowPending) {
            return;
        }
        for (Evaluated &e : evaluated) {
            auto it = m_pending.find(e.due.mapKey);
            if (it == m_pending.end() || it->second.last != e.due.last) {
                continue; // changed again meanwhile; next tick
            }
            Pending &pending = it->second;
            pending.key = e.resolved.kind == InstallKind::Steam && !e.resolved.relPath.empty()
                ? e.resolved
                : pending.key;
            if (!e.snapshot.exists) {
                m_pending.erase(it);
                requestReconcileLocked(ReconcileKind::Discovery, true);
                continue;
            }
            const bool stable = pending.snapshot && *pending.snapshot == e.snapshot;
            if (stable && now - pending.last >= m_config.quietWindow && !e.snapshot.tempMarkers &&
                e.steamOk) {
                Job job;
                job.key = pending.key;
                job.priority = ScanPriority::Event;
                jobs.push_back(std::move(job));
                m_pending.erase(it);
                continue;
            }
            pending.snapshot = e.snapshot;
            pending.lastSnapshot = now;
            std::string reason;
            if (!e.steamOk) {
                reason = "STEAM_UPDATING";
            } else if (e.snapshot.tempMarkers) {
                reason = "COPY_IN_PROGRESS";
            }
            if (now - pending.first > m_config.stabilizationMax) {
                reason = "STILL_CHANGING";
                pending.snapshotInterval = std::min<std::chrono::milliseconds>(
                    pending.snapshotInterval * 2, std::chrono::milliseconds(60000));
            }
            if (!reason.empty() && reason != pending.reportedReason) {
                pending.reportedReason = reason;
                reasons.emplace_back(e.due.mapKey, reason);
                const InstallKey key = pending.key;
                const std::string fsUuid = root->mount.fsUuid;
                postWrite([this, key, fsUuid, reason] {
                    std::optional<InstallRow> row = key.kind == InstallKind::Steam
                        ? m_store.findInstall(key, DirIdentity{}, fsUuid)
                        : m_store.findActiveInstallByRelPath(key.relPath);
                    if (row && !row->removed) {
                        publish(m_store.transitionInstall(
                            row->installId,
                            {GameState::Stabilizing, GameState::Discovered, GameState::Ready,
                             GameState::Ambiguous, GameState::Error},
                            GameState::Stabilizing, reason));
                    }
                }, false);
            }
        }
    }
    for (Job &job : jobs) {
        const InstallKey key = job.key;
        if (!enqueue(std::move(job), false)) {
            // Queue full: keep it pending and retry on a later tick.
            std::lock_guard lock(m_mutex);
            auto [it, inserted] = m_pending.try_emplace(key.mapKey());
            if (inserted) {
                it->second.key = key;
                it->second.first = it->second.last = now;
                it->second.snapshotInterval = m_config.debounce;
            }
        }
    }
}

void LibraryService::coordinatorLoop()
{
    UniqueFd mountinfo(::open("/proc/self/mountinfo", O_RDONLY | O_CLOEXEC));
    std::vector<RawInotifyEvent> raw;
    while (!m_stopping.load()) {
        pollfd fds[3];
        int count = 0;
        const int inotifyIndex = m_watcher.fd() >= 0 ? count : -1;
        if (inotifyIndex >= 0) {
            fds[count++] = {m_watcher.fd(), POLLIN, 0};
        }
        const int mountIndex = mountinfo.valid() ? count : -1;
        if (mountIndex >= 0) {
            fds[count++] = {mountinfo.get(), POLLPRI, 0};
        }
        fds[count++] = {m_wakeFd, POLLIN, 0};
        const int wakeIndex = count - 1;
        ::poll(fds, static_cast<nfds_t>(count), static_cast<int>(m_config.tick.count()));
        if (m_stopping.load()) {
            break;
        }
        const auto now = Clock::now();
        raw.clear();
        if (inotifyIndex >= 0 && (fds[inotifyIndex].revents & POLLIN)) {
            m_watcher.readEvents(raw);
        }
        {
            std::lock_guard lock(m_mutex);
            if (m_inotifyPaused) {
                raw.clear();
            }
            while (!m_injected.empty()) {
                raw.push_back(std::move(m_injected.front()));
                m_injected.pop_front();
            }
            for (const RawInotifyEvent &event : raw) {
                handleRawEvent(event, now);
            }
        }
        if (mountIndex >= 0 && (fds[mountIndex].revents & (POLLPRI | POLLERR))) {
            char buffer[4096];
            ::lseek(mountinfo.get(), 0, SEEK_SET);
            while (::read(mountinfo.get(), buffer, sizeof buffer) > 0) {
            }
            checkMount(false);
        }
        if (fds[wakeIndex].revents & POLLIN) {
            std::uint64_t value = 0;
            [[maybe_unused]] const ssize_t n = ::read(m_wakeFd, &value, sizeof value);
        }
        onTick(now);
        m_idleCv.notify_all();
    }
}

// -------------------------------------------------------------- workers ---

void LibraryService::workerLoop()
{
    while (true) {
        Job job;
        CancelToken token = makeCancelToken();
        {
            std::unique_lock lock(m_mutex);
            m_jobsCv.wait(lock, [this] { return m_stopping.load() || !m_order.empty(); });
            if (m_stopping.load()) {
                return;
            }
            const auto first = m_order.begin();
            const std::string mapKey = std::get<2>(*first);
            m_order.erase(first);
            auto it = m_queued.find(mapKey);
            job = std::move(it->second);
            m_queued.erase(it);
            m_running[mapKey] = Running{token, job.generation};
        }
        m_idleCv.notify_all(); // queue space for blocked producers
        processJob(job, token);
        {
            std::lock_guard lock(m_mutex);
            auto it = m_running.find(job.key.mapKey());
            if (it != m_running.end() && it->second.token == token) {
                m_running.erase(it);
            }
        }
        finishTracker(job.tracker);
        m_idleCv.notify_all();
    }
}

void LibraryService::processJob(const Job &job, const CancelToken &token)
{
    std::shared_ptr<RootHandle> root = currentRoot();
    if (!root || m_store.readOnly()) {
        return;
    }
    const std::string mapKey = job.key.mapKey();
    const std::string fsUuid = root->mount.fsUuid;
    std::optional<DiscoveredInstall> install =
        job.discovered ? job.discovered : m_scanner->discoverOne(root->fd.get(), job.key);
    if (!install) {
        requestReconcile(ReconcileKind::Discovery);
        return;
    }
    if (!install->manifestError.empty()) {
        const DiscoveredInstall d = *install;
        const std::uint64_t generation = job.generation;
        postWrite([this, d, fsUuid, mapKey, generation] {
            std::lock_guard gen(m_genMutex);
            if (m_generations[mapKey] != generation) {
                return;
            }
            publish(m_store.recordManifestError(d.key, "INVALID_MANIFEST", fsUuid));
        });
        return;
    }
    if (install->steam) {
        std::lock_guard lock(m_mutex);
        m_steamDirs[{install->key.libraryRelPath, install->steam->installDir}] = install->key.steamAppId;
    }

    const std::optional<InstallRow> row = m_store.findInstall(install->key, install->identity, fsUuid);
    std::map<std::string, PreviousCandidate> previous;
    if (row) {
        previous = m_store.previousCandidates(row->installId);
        const std::int64_t installId = row->installId;
        postWrite([this, installId] {
            publish(m_store.transitionInstall(installId, {GameState::Discovered, GameState::Stabilizing},
                                              GameState::Scanning, ""));
        });
    }

    InstallScanResult result = m_scanner->scan(root->fd.get(), *install, job.generation, previous, token);
    if (result.cancelled) {
        return;
    }
    result.coverage = coverageFor(mapKey);
    m_scansCompleted.fetch_add(1);

    const bool keepStabilizing = result.state == GameState::Stabilizing || result.tempMarkers;
    const bool vanished = result.vanished;
    const std::uint64_t generation = job.generation;
    postWrite([this, result = std::move(result), fsUuid, mapKey, generation] {
        // Invariant 4: results of an old generation are never written.
        std::lock_guard gen(m_genMutex);
        if (m_generations[mapKey] != generation) {
            m_staleResultsDropped.fetch_add(1);
            return;
        }
        publish(m_store.applyScanResult(result, fsUuid));
    });
    if (vanished) {
        requestReconcile(ReconcileKind::Discovery);
        return;
    }
    if (keepStabilizing) {
        std::lock_guard lock(m_mutex);
        auto [it, inserted] = m_pending.try_emplace(mapKey);
        if (inserted) {
            it->second.key = install->key;
            it->second.first = it->second.last = Clock::now();
            it->second.snapshotInterval =
                std::max<std::chrono::milliseconds>(m_config.debounce / 2, m_config.tick);
        }
    }
}

// ------------------------------------------------------------ reconcile ---

void LibraryService::reconcilerLoop()
{
    while (!m_stopping.load()) {
        ReconcileKind kind = ReconcileKind::None;
        bool user = false;
        std::uint64_t epoch = 0;
        {
            std::unique_lock lock(m_mutex);
            m_reconcileCv.wait_for(lock, 200ms, [this] {
                return m_stopping.load() ||
                    (m_reconcileRequest != ReconcileKind::None && Clock::now() >= m_reconcileNotBefore);
            });
            if (m_stopping.load()) {
                return;
            }
            if (m_reconcileRequest == ReconcileKind::None || Clock::now() < m_reconcileNotBefore) {
                continue;
            }
            kind = m_reconcileRequest;
            user = m_reconcileUser;
            m_reconcileRequest = ReconcileKind::None;
            m_reconcileUser = false;
            m_reconcileRunning = true;
            epoch = m_overflowEpoch;
        }
        runReconcile(kind, user);
        {
            std::lock_guard lock(m_mutex);
            m_reconcileRunning = false;
            if (kind == ReconcileKind::Full && epoch == m_overflowEpoch &&
                m_reconcileRequest != ReconcileKind::Full) {
                m_overflowPending = false;
            }
            m_currentRun.reset();
        }
        {
            std::lock_guard lock(m_progressMutex);
            m_runPhase = "idle";
        }
        m_idleCv.notify_all();
    }
}

bool LibraryService::confirmAbsent(const RootHandle &root, const InstallRow &row)
{
    if (row.kind == InstallKind::Steam) {
        const std::string manifest = joinRel(joinRel(row.libraryRelPath, "steamapps"),
                                             "appmanifest_" + std::to_string(row.steamAppId) + ".acf");
        const int fd = m_opener->openBeneath(root.fd.get(), manifest, false);
        if (fd >= 0) {
            ::close(fd);
            return false;
        }
        return fd == -ENOENT || fd == -ENOTDIR;
    }
    UniqueFd dir(m_opener->openBeneath(root.fd.get(), row.relPath, true));
    if (!dir.valid()) {
        // Only a definite "not there" counts; EACCES/timeouts never remove.
        return dir.get() == -ENOENT || dir.get() == -ENOTDIR;
    }
    const DirIdentity identity = identityOf(dir.get());
    return !row.handle.empty() && !identity.handle.empty() && identity.handle != row.handle;
}

bool LibraryService::cheapDiverges(const RootHandle &root, const DiscoveredInstall &install,
                                   const InstallRow &row)
{
    if (install.identity.mtimeNs != row.rootMtimeNs) {
        return true;
    }
    UniqueFd dir(m_opener->openBeneath(root.fd.get(), install.key.relPath, true));
    if (!dir.valid()) {
        return true;
    }
    for (const auto &[rel, previous] : m_store.previousCandidates(row.installId)) {
        struct statx stx {};
        if (::statx(dir.get(), rel.c_str(), AT_SYMLINK_NOFOLLOW, STATX_SIZE | STATX_MTIME | STATX_INO,
                    &stx) != 0) {
            return true;
        }
        const std::int64_t mtime = std::int64_t(stx.stx_mtime.tv_sec) * 1000000000 + stx.stx_mtime.tv_nsec;
        if (stx.stx_size != previous.size || mtime != previous.mtimeNs || stx.stx_ino != previous.ino) {
            return true;
        }
    }
    return false;
}

void LibraryService::installWatches(const RootHandle &root, const DiscoveryResult &discovery)
{
    if (m_watcher.fd() < 0) {
        return;
    }
    const int rootFd = root.fd.get();
    std::map<std::string, WatchCoverage> coverage;
    // Phase A: root > library roots > steamapps > each install root.
    std::vector<std::string> essential{""};
    for (const std::string &library : discovery.steamLibraries) {
        if (!library.empty()) {
            essential.push_back(library);
        }
        essential.push_back(joinRel(library, "steamapps"));
        essential.push_back(joinRel(library, "steamapps/common"));
        essential.push_back(joinRel(library, "steamapps/downloading"));
    }
    std::vector<const DiscoveredInstall *> roots;
    for (const DiscoveredInstall &install : discovery.installs) {
        if (install.manifestError.empty() && !install.installDirMissing) {
            essential.push_back(install.key.relPath);
            roots.push_back(&install);
        }
    }
    bool exhausted = false;
    for (const std::string &rel : essential) {
        if (m_watcher.addWatch(rootFd, *m_opener, rel) == InotifyWatcher::AddResult::BudgetExhausted) {
            exhausted = true;
            break;
        }
    }
    // Phase B: install subdirectories by increasing depth, all installs interleaved.
    std::vector<std::pair<std::string, std::string>> frontier; // (mapKey, rel)
    for (const DiscoveredInstall *install : roots) {
        frontier.emplace_back(install->key.mapKey(), install->key.relPath);
        coverage[install->key.mapKey()] = exhausted ? WatchCoverage::Partial : WatchCoverage::Full;
    }
    for (unsigned depth = 0; depth < m_config.maxWalkDepth && !frontier.empty(); ++depth) {
        std::vector<std::pair<std::string, std::string>> next;
        for (const auto &[mapKey, rel] : frontier) {
            UniqueFd fd(m_opener->openBeneath(rootFd, rel, true));
            if (!fd.valid()) {
                continue;
            }
            std::vector<DirEntryRaw> entries;
            bool truncated = false;
            listDirectory(fd.get(), m_config.maxEntriesPerInstall, entries, truncated);
            for (const DirEntryRaw &entry : entries) {
                if (entry.type != DT_DIR) {
                    continue;
                }
                const std::string child = joinRel(rel, entry.name);
                if (exhausted || m_watcher.addWatch(rootFd, *m_opener, child) ==
                        InotifyWatcher::AddResult::BudgetExhausted) {
                    exhausted = true;
                    coverage[mapKey] = WatchCoverage::Partial;
                    continue;
                }
                next.emplace_back(mapKey, child);
            }
        }
        frontier = std::move(next);
    }
    std::lock_guard lock(m_mutex);
    m_coverage = std::move(coverage);
}

void LibraryService::runReconcile(ReconcileKind kind, bool user)
{
    checkMount(true);
    std::shared_ptr<RootHandle> root = currentRoot();
    if (!root || m_store.readOnly()) {
        return;
    }
    const bool full = kind == ReconcileKind::Full;
    const bool dirty = m_store.dirty();
    const std::string kindName = reconcileKindName(kind, user, dirty);
    auto tracker = std::make_shared<RunTracker>();
    tracker->outstanding = 1; // sentinel held during discovery/enqueue
    {
        std::lock_guard lock(m_mutex);
        m_currentRun = tracker;
    }
    const std::int64_t runId = writeSync([&] {
        if (full) {
            m_store.setDirty(true);
        }
        const std::int64_t id = m_store.beginRun(kindName);
        publish(m_store.appendLibraryEvent(
            "scan.started", json({{QStringLiteral("kind"), QString::fromStdString(kindName)},
                                  {QStringLiteral("run_id"), static_cast<qint64>(id)}})));
        return id;
    });
    {
        std::lock_guard lock(m_progressMutex);
        m_runKind = kindName;
        m_runId = runId;
        m_runPhase = "discovering";
        m_runTotal = 0;
        m_runDone = 0;
    }
    const auto started = Clock::now();

    const DiscoveryResult discovery = m_scanner->discover(root->fd.get(), nullptr);
    if (discovery.error != 0) {
        qCWarning(lcLibrary) << "library: root listing failed, errno" << -discovery.error;
        writeSync([&] {
            m_store.finishRun(runId, "FAILED");
            return 0;
        });
        return;
    }
    {
        std::lock_guard lock(m_mutex);
        m_steamLibraries = std::set<std::string>(discovery.steamLibraries.begin(),
                                                 discovery.steamLibraries.end());
        m_steamDirs.clear();
        for (const DiscoveredInstall &install : discovery.installs) {
            if (install.steam) {
                m_steamDirs[{install.key.libraryRelPath, install.steam->installDir}] =
                    install.key.steamAppId;
            }
        }
    }
    // Watches before the scan: concurrent changes either show up in the
    // walk or produce events (§4.2).
    if (full || m_watcher.used() == 0) {
        installWatches(*root, discovery);
    }
    {
        std::lock_guard lock(m_progressMutex);
        m_runPhase = "scanning";
        m_runTotal = static_cast<std::int64_t>(discovery.installs.size());
    }

    const std::string fsUuid = root->mount.fsUuid;
    for (const DiscoveredInstall &install : discovery.installs) {
        if (m_stopping.load() || tracker->aborted.load()) {
            break;
        }
        if (!install.manifestError.empty()) {
            writeSync([&] {
                publish(m_store.recordManifestError(install.key, "INVALID_MANIFEST", fsUuid));
                return 0;
            });
            m_runDone.fetch_add(1);
            continue;
        }
        if (install.steam) {
            writeSync([&] {
                publish(m_store.recordDiscovered(install.key, install.identity, *install.steam, fsUuid));
                return 0;
            });
        }
        const std::optional<InstallRow> row = m_store.findInstall(install.key, install.identity, fsUuid);
        bool needScan = full || !row || row->state == GameState::Discovered ||
            row->state == GameState::Stabilizing || row->state == GameState::Scanning;
        if (!needScan && kind == ReconcileKind::Cheap) {
            needScan = row->coverage != WatchCoverage::Full || cheapDiverges(*root, install, *row);
        }
        if (!needScan) {
            m_runDone.fetch_add(1);
            continue;
        }
        Job job;
        job.key = install.key;
        job.discovered = install;
        job.priority = user ? ScanPriority::User
            : full          ? ScanPriority::Bootstrap
            : kind == ReconcileKind::Cheap ? ScanPriority::Periodic
                                           : ScanPriority::Event;
        job.tracker = tracker;
        tracker->outstanding.fetch_add(1);
        enqueue(std::move(job), true);
    }
    tracker->outstanding.fetch_sub(1); // drop the sentinel
    {
        std::unique_lock lock(m_mutex);
        m_idleCv.wait(lock, [&] {
            return m_stopping.load() || tracker->aborted.load() || tracker->outstanding.load() <= 0;
        });
    }
    if (m_stopping.load() || tracker->aborted.load()) {
        writeSync([&] {
            m_store.finishRun(runId, "CANCELLED");
            return 0;
        });
        return;
    }
    flushWrites();

    // Removal only with a valid mount, after a complete pass (§9.4).
    {
        std::lock_guard lock(m_progressMutex);
        m_runPhase = "reconciling";
    }
    const MountCheck mount = validateLibraryMount(m_config);
    if (mount.state != MountState::Ok || mount.mountId != root->mount.mountId) {
        writeSync([&] {
            m_store.finishRun(runId, "CANCELLED");
            return 0;
        });
        checkMount(false);
        return;
    }
    std::set<std::int64_t> keep;
    for (const DiscoveredInstall &install : discovery.installs) {
        if (auto row = m_store.findInstall(install.key, install.identity, fsUuid)) {
            keep.insert(row->installId);
        }
    }
    for (const InstallRow &row : m_store.activeInstalls()) {
        if (!keep.contains(row.installId) && !confirmAbsent(*root, row)) {
            keep.insert(row.installId);
        }
    }
    bool overflowDuringRun = false;
    {
        std::lock_guard lock(m_mutex);
        overflowDuringRun = m_reconcileRequest == ReconcileKind::Full && m_overflowPending;
    }
    writeSync([&] {
        publish(m_store.applyRemovals(keep));
        if (full && !overflowDuringRun) {
            m_store.setDirty(false);
        }
        m_store.finishRun(runId, "OK");
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - started);
        QJsonObject payload{{QStringLiteral("kind"), QString::fromStdString(kindName)},
                            {QStringLiteral("run_id"), static_cast<qint64>(runId)},
                            {QStringLiteral("duration_ms"), static_cast<qint64>(elapsed.count())}};
        publish(m_store.appendLibraryEvent("scan.finished", json(payload)));
        if (full) {
            publish(m_store.appendLibraryEvent("library.reconciled", json(payload)));
        }
        m_store.purge(m_config.tombstoneRetention, m_config.eventLogRetention);
        m_store.checkpoint(false);
        return 0;
    });
    m_reconcilesCompleted.fetch_add(1);
    qCInfo(lcLibrary).noquote() << "library: reconcile" << kindName.c_str() << "finished,"
                                << discovery.installs.size() << "installs";
}

// ------------------------------------------------------------------ API ---

QJsonObject LibraryService::listGames(const ListGamesQuery &query) const
{
    return m_store.listGames(query);
}

std::optional<QJsonObject> LibraryService::getGame(const std::string &gameId) const
{
    return m_store.getGame(gameId);
}

LibraryService::RescanReply LibraryService::rescan(const std::string &gameId, bool full)
{
    RescanReply reply;
    if (m_store.readOnly()) {
        reply.error = "READ_ONLY";
        return reply;
    }
    reply.requestId = ++m_requestIds;
    if (gameId.empty()) {
        requestReconcile(full ? ReconcileKind::Full : ReconcileKind::Cheap, true);
        reply.ok = true;
        return reply;
    }
    const auto game = m_store.getGame(gameId);
    if (!game) {
        reply.error = "NOT_FOUND";
        return reply;
    }
    for (const InstallRow &row : m_store.activeInstalls()) {
        if (row.gameId != gameId) {
            continue;
        }
        Job job;
        job.key.kind = row.kind;
        job.key.relPath = row.relPath;
        job.key.libraryRelPath = row.libraryRelPath;
        job.key.steamAppId = row.steamAppId;
        job.priority = ScanPriority::User;
        if (enqueue(std::move(job), false)) {
            ++reply.queued;
        }
    }
    reply.ok = true;
    return reply;
}

std::string LibraryService::setMainExecutable(const std::string &gameId,
                                              std::optional<std::int64_t> candidateId)
{
    std::string error;
    writeSync([&] {
        publish(m_store.setUserMainExecutable(gameId, candidateId, error));
        return 0;
    });
    if (error.empty() && !candidateId) {
        rescan(gameId, true);
    }
    return error;
}

int LibraryService::subscribe(EventSink sink)
{
    std::lock_guard lock(m_subMutex);
    const int id = m_nextSubscriber++;
    m_subscribers.emplace(id, std::move(sink));
    return id;
}

void LibraryService::unsubscribe(int id)
{
    std::lock_guard lock(m_subMutex);
    m_subscribers.erase(id);
}

std::vector<LibraryEvent> LibraryService::eventsSince(std::int64_t since, bool &resync) const
{
    return m_store.eventsSince(since, resync);
}

std::int64_t LibraryService::librarySeq() const
{
    return m_store.listGames(ListGamesQuery{{}, std::nullopt, 0, 1}).value(QStringLiteral("library_seq")).toInteger();
}

QJsonObject LibraryService::health() const
{
    QJsonObject storage;
    std::shared_ptr<RootHandle> root = currentRoot();
    std::string storageState;
    std::size_t partialKnown = 0;
    std::int64_t lastOverflow = 0;
    bool overflowPending = false;
    {
        std::lock_guard lock(m_mutex);
        storageState = m_storageState;
        lastOverflow = m_lastOverflowAt;
        overflowPending = m_overflowPending;
        for (const auto &[key, coverage] : m_coverage) {
            partialKnown += coverage != WatchCoverage::Full ? 1 : 0;
        }
    }
    storage.insert(QStringLiteral("state"), QString::fromStdString(storageState));
    storage.insert(QStringLiteral("policy"),
                   m_config.mountPolicy == MountPolicy::Strict      ? QStringLiteral("ext4|btrfs+zstd")
                   : m_config.mountPolicy == MountPolicy::Directory ? QStringLiteral("directory:ext4|btrfs+zstd")
                                                                    : QStringLiteral("any-filesystem"));
    storage.insert(QStringLiteral("root"), QString::fromStdString(m_config.rootPath));
    if (root) {
        storage.insert(QStringLiteral("fs_type"), QString::fromStdString(root->mount.fsType));
        storage.insert(QStringLiteral("read_only"), root->mount.readOnly);
    }

    QJsonObject io;
    if (m_engine) {
        io.insert(QStringLiteral("kind"), QString::fromLatin1(ioBackendKindName(m_engine->kind())));
        io.insert(QStringLiteral("reason"), QString::fromStdString(m_engine->reason()));
        io.insert(QStringLiteral("changes"), static_cast<qint64>(m_engine->backendChanges()));
        io.insert(QStringLiteral("liburing_compiled"), liburingCompiledIn());
        io.insert(QStringLiteral("openat2"), m_opener && m_opener->usesOpenat2());
    }

    QJsonObject db{
        {QStringLiteral("state"), QString::fromLatin1(LibraryStore::openStateName(m_dbReport.state))},
        {QStringLiteral("read_only"), m_store.readOnly()},
        {QStringLiteral("dirty"), m_store.isOpen() ? m_store.dirty() : true},
    };
    if (!m_dbReport.detail.empty()) {
        db.insert(QStringLiteral("detail"), QString::fromStdString(m_dbReport.detail));
    }
    db.insert(QStringLiteral("schema_version"), kSchemaVersion);
    if (m_dbReport.migratedFrom > 0) {
        db.insert(QStringLiteral("migrated_from"), m_dbReport.migratedFrom);
        db.insert(QStringLiteral("migration_backup"), QString::fromStdString(m_dbReport.migrationBackupName));
    }
    if (!m_dbReport.corruptBackupName.empty()) {
        db.insert(QStringLiteral("corrupt_backup"), QString::fromStdString(m_dbReport.corruptBackupName));
    }
    db.insert(QStringLiteral("crashed_runs_recovered"), m_dbReport.crashedRuns);

    QJsonObject watches{
        {QStringLiteral("available"), m_watcher.fd() >= 0},
        {QStringLiteral("used"), static_cast<qint64>(m_watcher.used())},
        {QStringLiteral("budget"), static_cast<qint64>(m_watcher.budget())},
        {QStringLiteral("exhausted"), m_watcher.exhausted()},
        {QStringLiteral("partial_installs"), m_store.partialInstalls()},
        {QStringLiteral("partial_keys"), static_cast<qint64>(partialKnown)},
    };

    QJsonObject byState;
    for (const auto &[state, count] : m_store.countsByState()) {
        byState.insert(QString::fromStdString(state), count);
    }
    QJsonObject errors;
    if (m_scanner) {
        QJsonObject pe;
        for (const auto &[reason, count] : m_scanner->peFailures()) {
            pe.insert(QString::fromStdString(reason), static_cast<qint64>(count));
        }
        QJsonObject acf;
        for (const auto &[reason, count] : m_scanner->acfFailures()) {
            acf.insert(QString::fromStdString(reason), static_cast<qint64>(count));
        }
        errors.insert(QStringLiteral("pe_parse_failures_total"), pe);
        errors.insert(QStringLiteral("acf_parse_failures_total"), acf);
    }

    QJsonObject metrics{
        {QStringLiteral("inotify_overflows_total"), static_cast<qint64>(m_overflows.load())},
        {QStringLiteral("events_received_total"), static_cast<qint64>(m_eventsReceived.load())},
        {QStringLiteral("events_coalesced_total"), static_cast<qint64>(m_eventsCoalesced.load())},
        {QStringLiteral("scans_completed_total"), static_cast<qint64>(m_scansCompleted.load())},
        {QStringLiteral("stale_results_dropped_total"), static_cast<qint64>(m_staleResultsDropped.load())},
        {QStringLiteral("reconciles_completed_total"), static_cast<qint64>(m_reconcilesCompleted.load())},
    };
    if (m_engine) {
        const IoStats &stats = m_engine->stats();
        metrics.insert(QStringLiteral("io_inflight"), static_cast<qint64>(stats.inflight.load()));
        metrics.insert(QStringLiteral("io_inflight_peak"), static_cast<qint64>(stats.peakInflight.load()));
        metrics.insert(QStringLiteral("io_timeouts_total"), static_cast<qint64>(stats.timeouts.load()));
        metrics.insert(QStringLiteral("io_cancelled_total"), static_cast<qint64>(stats.cancelled.load()));
        metrics.insert(QStringLiteral("bytes_read_total"), static_cast<qint64>(stats.bytesRead.load()));
        metrics.insert(QStringLiteral("open_fds"), static_cast<qint64>(m_engine->fdBudget().inUse()));
        metrics.insert(QStringLiteral("open_fds_peak"), static_cast<qint64>(m_engine->fdBudget().peak()));
        metrics.insert(QStringLiteral("open_fds_limit"), static_cast<qint64>(m_engine->fdBudget().capacity()));
        metrics.insert(QStringLiteral("buffer_bytes_in_use"), static_cast<qint64>(m_engine->bufferBudget().inUse()));
        metrics.insert(QStringLiteral("buffer_bytes_peak"), static_cast<qint64>(m_engine->bufferBudget().peak()));
    }
    {
        std::lock_guard lock(m_subMutex);
        metrics.insert(QStringLiteral("subscribers"), static_cast<qint64>(m_subscribers.size()));
    }

    QJsonObject out{
        {QStringLiteral("storage"), storage},
        {QStringLiteral("io_backend"), io},
        {QStringLiteral("db"), db},
        {QStringLiteral("watches"), watches},
        {QStringLiteral("games_by_state"), byState},
        {QStringLiteral("errors"), errors},
        {QStringLiteral("metrics"), metrics},
        {QStringLiteral("reconcile_pending_after_overflow"), overflowPending},
    };
    const QJsonObject runs = m_store.lastRuns();
    for (auto it = runs.begin(); it != runs.end(); ++it) {
        out.insert(it.key(), it.value());
    }
    if (lastOverflow != 0) {
        out.insert(QStringLiteral("last_overflow_at"), static_cast<qint64>(lastOverflow));
    }
    return out;
}

QJsonObject LibraryService::progress() const
{
    QJsonObject queue;
    {
        std::lock_guard lock(m_mutex);
        queue.insert(QStringLiteral("scan"), static_cast<qint64>(m_queued.size()));
        queue.insert(QStringLiteral("running"), static_cast<qint64>(m_running.size()));
        queue.insert(QStringLiteral("stabilizing"), static_cast<qint64>(m_pending.size()));
    }
    {
        std::lock_guard lock(const_cast<std::mutex &>(m_writeMutex));
        queue.insert(QStringLiteral("commit"), static_cast<qint64>(m_writes.size()));
    }
    if (m_engine) {
        queue.insert(QStringLiteral("io_inflight"), static_cast<qint64>(m_engine->stats().inflight.load()));
    }
    std::lock_guard lock(m_progressMutex);
    QJsonObject out{
        {QStringLiteral("phase"), QString::fromStdString(m_runPhase)},
        {QStringLiteral("queue"), queue},
    };
    if (m_runPhase != "idle") {
        out.insert(QStringLiteral("run_kind"), QString::fromStdString(m_runKind));
        out.insert(QStringLiteral("run_id"), static_cast<qint64>(m_runId));
        out.insert(QStringLiteral("installs_done"), static_cast<qint64>(m_runDone.load()));
        out.insert(QStringLiteral("installs_total"), static_cast<qint64>(m_runTotal));
    }
    return out;
}

// ------------------------------------------------------------ test hooks ---

void LibraryService::injectInotifyEvent(RawInotifyEvent event)
{
    {
        std::lock_guard lock(m_mutex);
        m_injected.push_back(std::move(event));
    }
    if (m_wakeFd >= 0) {
        const std::uint64_t one = 1;
        [[maybe_unused]] const ssize_t n = ::write(m_wakeFd, &one, sizeof one);
    }
}

void LibraryService::setInotifyPaused(bool paused)
{
    std::lock_guard lock(m_mutex);
    m_inotifyPaused = paused;
}

bool LibraryService::waitIdle(std::chrono::milliseconds timeout)
{
    const auto deadline = Clock::now() + timeout;
    while (Clock::now() < deadline) {
        bool idle = false;
        {
            std::lock_guard lock(m_mutex);
            idle = m_queued.empty() && m_running.empty() && m_pending.empty() &&
                m_pendingMoves.empty() && m_injected.empty() &&
                m_reconcileRequest == ReconcileKind::None && !m_reconcileRunning;
        }
        if (idle) {
            std::lock_guard lock(m_writeMutex);
            idle = m_writes.empty() && !m_writerBusy;
        }
        if (idle) {
            // Let the coordinator drain kernel events that might still be queued.
            std::this_thread::sleep_for(std::max<std::chrono::milliseconds>(m_config.tick * 2, 20ms));
            std::lock_guard lock(m_mutex);
            if (m_queued.empty() && m_running.empty() && m_pending.empty() && m_pendingMoves.empty() &&
                m_reconcileRequest == ReconcileKind::None && !m_reconcileRunning) {
                return true;
            }
        }
        std::this_thread::sleep_for(10ms);
    }
    return false;
}

} // namespace threesixty::daemon::library
