#include "io_engine.hpp"

#include <QDebug>

#include <cerrno>
#include <chrono>
#include <deque>
#include <fstream>
#include <thread>
#include <unordered_map>

#include <fcntl.h>
#include <linux/openat2.h>
#include <unistd.h>

#ifdef THREESIXTY_HAVE_LIBURING
#include <liburing.h>
#endif

namespace threesixty::daemon::library {

namespace {

using namespace std::chrono_literals;

struct PendingOp {
    IoRequest req;
    IoResult result;
    std::mutex mutex;
    std::condition_variable cv;
    bool done = false;
    bool abandoned = false;
    bool cancelRequested = false;
    std::uint64_t id = 0;
    // Storage that must outlive an io_uring submission.
    open_how how {};
    std::vector<std::uint8_t> buffer;
#ifdef THREESIXTY_HAVE_LIBURING
    __kernel_timespec timeout {};
#endif
};
using PendingOpPtr = std::shared_ptr<PendingOp>;

bool tokenCancelled(const CancelToken &token)
{
    return token && token->cancelled.load();
}

} // namespace

class IoBackend
{
public:
    IoBackend(const LibraryConfig &config, const SafeOpener &opener, IoStats &stats,
              ResourceBudget &fdBudget)
        : m_config(config)
        , m_opener(opener)
        , m_stats(stats)
        , m_fdBudget(fdBudget)
    {
    }
    virtual ~IoBackend() = default;
    virtual IoBackendKind kind() const = 0;
    virtual std::vector<IoResult> runBatch(std::vector<IoRequest> &requests) = 0;
    virtual void cancel(const CancelToken &token) = 0;

protected:
    // Synchronous execution, shared by the thread pool and by io_uring for
    // opens when openat2 is unavailable (strict component-wise fallback).
    int execute(PendingOp &op)
    {
        IoRequest &req = op.req;
        switch (req.op) {
        case IoOp::Statx:
            if (::statx(req.dirFd, req.path.c_str(), AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT,
                        STATX_BASIC_STATS | STATX_BTIME, &op.result.stx) != 0) {
                return -errno;
            }
            return 0;
        case IoOp::Open:
            return m_opener.openBeneath(req.dirFd, req.path, req.directory);
        case IoOp::Read: {
            op.buffer.resize(req.length);
            std::size_t done = 0;
            while (done < req.length) {
                const ssize_t n = ::pread(req.fd, op.buffer.data() + done, req.length - done,
                                          static_cast<off_t>(req.offset + done));
                if (n < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    return -errno;
                }
                if (n == 0) {
                    break;
                }
                done += static_cast<std::size_t>(n);
            }
            return static_cast<int>(done);
        }
        case IoOp::Close:
            return ::close(req.fd) == 0 ? 0 : -errno;
        }
        return -EINVAL;
    }

    void complete(const PendingOpPtr &op, int res, bool cancelled, bool timedOut)
    {
        std::lock_guard lock(op->mutex);
        if (op->done) {
            return;
        }
        op->done = true;
        m_stats.completed.fetch_add(1);
        if (op->abandoned) {
            // Late completion of an op whose waiter already returned.
            if (op->req.op == IoOp::Open) {
                if (res >= 0) {
                    ::close(res);
                }
                m_fdBudget.release(1);
            }
            op->cv.notify_all();
            return;
        }
        op->result.res = res;
        op->result.cancelled = cancelled;
        op->result.timedOut = timedOut;
        if (cancelled) {
            m_stats.cancelled.fetch_add(1);
        }
        if (timedOut) {
            m_stats.timeouts.fetch_add(1);
        }
        if (op->req.op == IoOp::Read && res >= 0) {
            op->buffer.resize(static_cast<std::size_t>(res));
            op->result.data = std::move(op->buffer);
            m_stats.bytesRead.fetch_add(static_cast<std::uint64_t>(res));
        }
        op->cv.notify_all();
    }

    // Waits for op; gives up at deadline or on cancellation (abandon).
    IoResult wait(const PendingOpPtr &op, Clock::time_point deadline, bool abandonOnCancel)
    {
        std::unique_lock lock(op->mutex);
        while (!op->done) {
            op->cv.wait_for(lock, 20ms);
            if (op->done) {
                break;
            }
            const bool cancelled = tokenCancelled(op->req.token);
            if (Clock::now() >= deadline || (cancelled && abandonOnCancel)) {
                op->abandoned = true;
                IoResult result;
                result.abandoned = true;
                if (cancelled) {
                    result.res = -ECANCELED;
                    result.cancelled = true;
                    m_stats.cancelled.fetch_add(1);
                } else {
                    result.res = -ETIMEDOUT;
                    result.timedOut = true;
                    m_stats.timeouts.fetch_add(1);
                }
                return result;
            }
        }
        return std::move(op->result);
    }

    const LibraryConfig &m_config;
    const SafeOpener &m_opener;
    IoStats &m_stats;
    ResourceBudget &m_fdBudget;
};

namespace {

class ThreadPoolBackend final : public IoBackend
{
public:
    ThreadPoolBackend(const LibraryConfig &config, const SafeOpener &opener, IoStats &stats,
                      ResourceBudget &fdBudget)
        : IoBackend(config, opener, stats, fdBudget)
    {
        const unsigned count = std::max(1u, config.threadPoolSize);
        for (unsigned i = 0; i < count; ++i) {
            m_threads.emplace_back([this] { workerLoop(); });
        }
    }

    ~ThreadPoolBackend() override
    {
        {
            std::lock_guard lock(m_mutex);
            m_stop = true;
        }
        m_notEmpty.notify_all();
        m_notFull.notify_all();
        for (std::thread &thread : m_threads) {
            thread.join();
        }
    }

    IoBackendKind kind() const override { return IoBackendKind::ThreadPool; }

    std::vector<IoResult> runBatch(std::vector<IoRequest> &requests) override
    {
        std::vector<PendingOpPtr> ops;
        ops.reserve(requests.size());
        const auto deadline = Clock::now() + m_config.ioTimeout;
        for (IoRequest &request : requests) {
            auto op = std::make_shared<PendingOp>();
            op->req = std::move(request);
            {
                std::unique_lock lock(m_mutex);
                // Backpressure: the producer blocks while the queue is full.
                m_notFull.wait(lock, [this] {
                    return m_stop || m_queue.size() < std::max<std::size_t>(1, m_config.ioQueueCapacity);
                });
                m_queue.push_back(op);
            }
            m_stats.submitted.fetch_add(1);
            m_notEmpty.notify_one();
            ops.push_back(std::move(op));
        }
        std::vector<IoResult> results;
        results.reserve(ops.size());
        for (const PendingOpPtr &op : ops) {
            results.push_back(wait(op, deadline, true));
        }
        return results;
    }

    void cancel(const CancelToken &) override
    {
        // Queued ops observe the token when dequeued; waiters when polling.
    }

private:
    void workerLoop()
    {
        while (true) {
            PendingOpPtr op;
            {
                std::unique_lock lock(m_mutex);
                m_notEmpty.wait(lock, [this] { return m_stop || !m_queue.empty(); });
                if (m_stop && m_queue.empty()) {
                    return;
                }
                op = std::move(m_queue.front());
                m_queue.pop_front();
            }
            m_notFull.notify_one();
            if (tokenCancelled(op->req.token) && op->req.op != IoOp::Close) {
                complete(op, -ECANCELED, true, false);
                continue;
            }
            m_stats.noteInflight(1);
            const int res = execute(*op);
            m_stats.noteInflight(-1);
            complete(op, res, false, false);
        }
    }

    std::mutex m_mutex;
    std::condition_variable m_notEmpty;
    std::condition_variable m_notFull;
    std::deque<PendingOpPtr> m_queue;
    std::vector<std::thread> m_threads;
    bool m_stop = false;
};

#ifdef THREESIXTY_HAVE_LIBURING

constexpr std::uint64_t kTimeoutTag = ~0ull;
constexpr std::uint64_t kCancelTag = ~0ull - 1;

class UringBackend final : public IoBackend
{
public:
    UringBackend(const LibraryConfig &config, const SafeOpener &opener, IoStats &stats,
                 ResourceBudget &fdBudget)
        : IoBackend(config, opener, stats, fdBudget)
        , m_inflightBudget(std::max(1u, config.maxInflight))
    {
    }

    // Returns 0 or -errno; reason is set on failure (§5.3).
    int init(std::string &reason)
    {
        if (m_config.simulateIoUringInitError != 0) {
            const int err = m_config.simulateIoUringInitError;
            reason = (err == -EPERM || err == -EACCES) ? "EPERM" : "UNSUPPORTED";
            return err;
        }
        const int ret = io_uring_queue_init(std::max(8u, m_config.ringEntries), &m_ring, 0);
        if (ret < 0) {
            reason = (ret == -EPERM || ret == -EACCES) ? "EPERM" : "UNSUPPORTED";
            return ret;
        }
        m_initialized = true;
        io_uring_probe *probe = io_uring_get_probe_ring(&m_ring);
        if (probe == nullptr) {
            reason = "MISSING_OPS";
            return -EINVAL;
        }
        bool ok = true;
        for (int opcode : {IORING_OP_STATX, IORING_OP_OPENAT2, IORING_OP_READ, IORING_OP_CLOSE,
                           IORING_OP_LINK_TIMEOUT, IORING_OP_ASYNC_CANCEL}) {
            ok = ok && io_uring_opcode_supported(probe, opcode);
        }
        io_uring_free_probe(probe);
        if (!ok) {
            reason = "MISSING_OPS";
            return -EINVAL;
        }
        m_reaper = std::thread([this] { reaperLoop(); });
        return 0;
    }

    ~UringBackend() override
    {
        m_stop = true;
        if (m_reaper.joinable()) {
            m_reaper.join();
        }
        if (m_initialized) {
            io_uring_queue_exit(&m_ring);
        }
    }

    IoBackendKind kind() const override { return IoBackendKind::IoUring; }

    std::vector<IoResult> runBatch(std::vector<IoRequest> &requests) override
    {
        std::vector<PendingOpPtr> ops;
        std::vector<bool> submitted;
        ops.reserve(requests.size());
        // The kernel-side linked timeout fires first; this is a safety net.
        const auto deadline = Clock::now() + m_config.ioTimeout + 2s;
        for (IoRequest &request : requests) {
            auto op = std::make_shared<PendingOp>();
            op->req = std::move(request);
            ops.push_back(op);
            submitted.push_back(submitOne(op));
        }
        {
            std::lock_guard lock(m_sqMutex);
            flushLocked();
        }
        std::vector<IoResult> results;
        results.reserve(ops.size());
        for (std::size_t i = 0; i < ops.size(); ++i) {
            if (!submitted[i]) {
                IoResult failed;
                failed.backendFailure = true;
                failed.res = -EAGAIN;
                results.push_back(std::move(failed));
            } else {
                results.push_back(wait(ops[i], deadline, false));
            }
            if (results.back().backendFailure) {
                // Hand the request back so the engine can replay it.
                requests[i] = ops[i]->req;
            }
        }
        return results;
    }

    void cancel(const CancelToken &token) override
    {
        std::vector<PendingOpPtr> targets;
        {
            std::lock_guard lock(m_mapMutex);
            for (auto &[id, op] : m_inflight) {
                if (op->req.token == token) {
                    targets.push_back(op);
                }
            }
        }
        std::lock_guard lock(m_sqMutex);
        for (const PendingOpPtr &op : targets) {
            {
                std::lock_guard opLock(op->mutex);
                if (op->done) {
                    continue;
                }
                op->cancelRequested = true;
            }
            io_uring_sqe *sqe = getSqeLocked();
            if (sqe == nullptr) {
                continue;
            }
            io_uring_prep_cancel64(sqe, op->id, 0);
            io_uring_sqe_set_data64(sqe, kCancelTag);
        }
        flushLocked();
    }

private:
    io_uring_sqe *getSqeLocked()
    {
        io_uring_sqe *sqe = io_uring_get_sqe(&m_ring);
        if (sqe == nullptr) {
            flushLocked();
            sqe = io_uring_get_sqe(&m_ring);
        }
        return sqe;
    }

    void flushLocked()
    {
        if (m_broken || m_unsubmitted == 0) {
            return;
        }
        int ret = 0;
        if (m_config.simulateIoUringRuntimeFailureAfter > 0 &&
            m_submitCalls >= static_cast<unsigned>(m_config.simulateIoUringRuntimeFailureAfter)) {
            ret = -EPERM;
        } else {
            ret = io_uring_submit(&m_ring);
            ++m_submitCalls;
        }
        if (ret < 0) {
            qWarning().noquote() << "library: io_uring submit failed:" << -ret;
            m_broken = true;
            failUnsubmittedLocked();
            return;
        }
        m_unsubmitted = 0;
        m_unsubmittedIds.clear();
    }

    void failUnsubmittedLocked()
    {
        // Ops prepared but never accepted by the kernel: complete them as
        // backend failures so the engine replays them on the thread pool.
        std::vector<PendingOpPtr> stuck;
        {
            std::lock_guard lock(m_mapMutex);
            for (std::uint64_t id : m_unsubmittedIds) {
                auto it = m_inflight.find(id);
                if (it != m_inflight.end()) {
                    stuck.push_back(it->second);
                    m_inflight.erase(it);
                }
            }
        }
        m_unsubmittedIds.clear();
        m_unsubmitted = 0;
        for (const PendingOpPtr &op : stuck) {
            m_inflightBudget.release(1);
            m_stats.noteInflight(-1);
            std::lock_guard lock(op->mutex);
            op->done = true;
            op->result.backendFailure = true;
            op->result.res = -EAGAIN;
            op->cv.notify_all();
        }
    }

    bool submitOne(const PendingOpPtr &op)
    {
        if (m_broken) {
            return false;
        }
        if (tokenCancelled(op->req.token) && op->req.op != IoOp::Close) {
            complete(op, -ECANCELED, true, false);
            return true;
        }
        if (op->req.op == IoOp::Open && !m_opener.usesOpenat2()) {
            // No openat2: keep the strict component-wise fallback, synchronously.
            complete(op, execute(*op), false, false);
            return true;
        }
        if (!m_inflightBudget.tryAcquire(1)) {
            {
                std::lock_guard lock(m_sqMutex);
                flushLocked();
            }
            m_inflightBudget.acquire(1, nullptr);
        }
        std::lock_guard lock(m_sqMutex);
        if (m_broken) {
            m_inflightBudget.release(1);
            return false;
        }
        io_uring_sqe *sqe = getSqeLocked();
        io_uring_sqe *timeoutSqe = sqe != nullptr ? getSqeLocked() : nullptr;
        if (sqe == nullptr || timeoutSqe == nullptr || m_broken) {
            m_inflightBudget.release(1);
            return false;
        }
        op->id = m_nextId++;
        IoRequest &req = op->req;
        switch (req.op) {
        case IoOp::Statx:
            io_uring_prep_statx(sqe, req.dirFd, req.path.c_str(),
                                AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT,
                                STATX_BASIC_STATS | STATX_BTIME, &op->result.stx);
            break;
        case IoOp::Open:
            op->how.flags = O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK |
                (req.directory ? O_DIRECTORY : O_NOFOLLOW);
            op->how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV;
            if (req.path.empty()) {
                req.path = ".";
            }
            io_uring_prep_openat2(sqe, req.dirFd, req.path.c_str(), &op->how);
            break;
        case IoOp::Read:
            op->buffer.resize(req.length);
            io_uring_prep_read(sqe, req.fd, op->buffer.data(), req.length, req.offset);
            break;
        case IoOp::Close:
            io_uring_prep_close(sqe, req.fd);
            break;
        }
        io_uring_sqe_set_data64(sqe, op->id);
        sqe->flags |= IOSQE_IO_LINK;
        const auto timeoutNs = std::chrono::duration_cast<std::chrono::nanoseconds>(m_config.ioTimeout);
        op->timeout.tv_sec = timeoutNs.count() / 1000000000;
        op->timeout.tv_nsec = timeoutNs.count() % 1000000000;
        io_uring_prep_link_timeout(timeoutSqe, &op->timeout, 0);
        io_uring_sqe_set_data64(timeoutSqe, kTimeoutTag);
        {
            std::lock_guard mapLock(m_mapMutex);
            m_inflight.emplace(op->id, op);
        }
        m_unsubmittedIds.push_back(op->id);
        m_unsubmitted += 2;
        m_stats.submitted.fetch_add(1);
        m_stats.noteInflight(1);
        if (m_unsubmitted >= 32) {
            flushLocked();
        }
        return true;
    }

    void reaperLoop()
    {
        while (!m_stop.load()) {
            io_uring_cqe *cqe = nullptr;
            __kernel_timespec ts {0, 50 * 1000 * 1000};
            const int ret = io_uring_wait_cqe_timeout(&m_ring, &cqe, &ts);
            if (ret < 0 || cqe == nullptr) {
                continue;
            }
            unsigned head = 0;
            unsigned seen = 0;
            io_uring_for_each_cqe(&m_ring, head, cqe)
            {
                ++seen;
                handleCqe(io_uring_cqe_get_data64(cqe), cqe->res);
            }
            io_uring_cq_advance(&m_ring, seen);
        }
    }

    void handleCqe(std::uint64_t id, int res)
    {
        if (id == kTimeoutTag || id == kCancelTag) {
            return;
        }
        PendingOpPtr op;
        {
            std::lock_guard lock(m_mapMutex);
            auto it = m_inflight.find(id);
            if (it == m_inflight.end()) {
                return;
            }
            op = it->second;
            m_inflight.erase(it);
        }
        m_inflightBudget.release(1);
        m_stats.noteInflight(-1);
        bool cancelled = false;
        bool timedOut = false;
        if (res == -ECANCELED || res == -EINTR) {
            std::lock_guard lock(op->mutex);
            cancelled = op->cancelRequested || tokenCancelled(op->req.token);
            timedOut = !cancelled;
        }
        complete(op, timedOut ? -ETIMEDOUT : res, cancelled, timedOut);
    }

    io_uring m_ring {};
    bool m_initialized = false;
    std::mutex m_sqMutex;
    std::mutex m_mapMutex;
    std::unordered_map<std::uint64_t, PendingOpPtr> m_inflight;
    std::vector<std::uint64_t> m_unsubmittedIds;
    unsigned m_unsubmitted = 0;
    unsigned m_submitCalls = 0;
    std::uint64_t m_nextId = 1;
    bool m_broken = false;
    ResourceBudget m_inflightBudget;
    std::atomic<bool> m_stop{false};
    std::thread m_reaper;
};

#endif // THREESIXTY_HAVE_LIBURING

// maxOpenFds, but never more than 25 % of RLIMIT_NOFILE (§5.4).
std::uint64_t fdCapacity(const LibraryConfig &config)
{
    std::uint64_t capacity = std::max(4u, config.maxOpenFds);
    const long openMax = ::sysconf(_SC_OPEN_MAX);
    if (openMax > 0) {
        capacity = std::min<std::uint64_t>(capacity, std::max<long>(4, openMax / 4));
    }
    return capacity;
}

int readSysctl(const std::string &path)
{
    std::ifstream in(path);
    int value = 0;
    if (in >> value) {
        return value;
    }
    return 0; // absent => 0 (§5.3)
}

} // namespace

const char *ioBackendKindName(IoBackendKind kind)
{
    return kind == IoBackendKind::IoUring ? "io_uring" : "threadpool";
}

bool liburingCompiledIn()
{
#ifdef THREESIXTY_HAVE_LIBURING
    return true;
#else
    return false;
#endif
}

void IoStats::noteInflight(std::int64_t delta)
{
    const std::int64_t now = inflight.fetch_add(delta) + delta;
    std::int64_t peak = peakInflight.load();
    while (now > peak && !peakInflight.compare_exchange_weak(peak, now)) {
    }
}

bool ResourceBudget::acquire(std::uint64_t amount, const CancelToken &token)
{
    if (amount > m_capacity) {
        return false;
    }
    std::unique_lock lock(m_mutex);
    while (m_used + amount > m_capacity) {
        if (tokenCancelled(token)) {
            return false;
        }
        m_cv.wait_for(lock, 20ms);
    }
    m_used += amount;
    m_peak = std::max(m_peak, m_used);
    return true;
}

bool ResourceBudget::tryAcquire(std::uint64_t amount)
{
    std::lock_guard lock(m_mutex);
    if (m_used + amount > m_capacity) {
        return false;
    }
    m_used += amount;
    m_peak = std::max(m_peak, m_used);
    return true;
}

void ResourceBudget::release(std::uint64_t amount)
{
    {
        std::lock_guard lock(m_mutex);
        m_used -= std::min(m_used, amount);
    }
    m_cv.notify_all();
}

std::uint64_t ResourceBudget::inUse() const
{
    std::lock_guard lock(m_mutex);
    return m_used;
}

std::uint64_t ResourceBudget::peak() const
{
    std::lock_guard lock(m_mutex);
    return m_peak;
}

IoEngine::IoEngine(const LibraryConfig &config, const SafeOpener &opener)
    : m_config(config)
    , m_opener(opener)
    , m_fdBudget(fdCapacity(config))
    , m_bufferBudget(std::max<std::uint64_t>(1 << 20, config.bufferBudgetBytes))
{

    std::string reason;
    if (config.ioBackend == IoBackendPreference::ThreadPool) {
        reason = "CONFIG";
    } else if (!liburingCompiledIn()) {
        reason = "NO_LIBURING";
    } else if (readSysctl(config.ioUringDisabledSysctl) == 2) {
        reason = "SYSCTL_DISABLED";
    }
#ifdef THREESIXTY_HAVE_LIBURING
    if (reason.empty()) {
        auto uring = std::make_shared<UringBackend>(m_config, m_opener, m_stats, m_fdBudget);
        if (uring->init(reason) == 0) {
            m_backend = std::move(uring);
            m_reason = "OK";
            return;
        }
    }
#endif
    m_backend = std::make_shared<ThreadPoolBackend>(m_config, m_opener, m_stats, m_fdBudget);
    m_reason = reason;
}

IoEngine::~IoEngine()
{
    std::lock_guard lock(m_backendMutex);
    m_backend.reset();
    m_retired.reset();
}

unsigned IoEngine::perWorkerFdQuota() const
{
    const std::uint64_t perWorker =
        m_fdBudget.capacity() / std::max(1u, m_config.installConcurrency) / 2;
    return static_cast<unsigned>(std::clamp<std::uint64_t>(perWorker, 1, m_config.maxInflight));
}

IoBackendKind IoEngine::kind() const
{
    std::lock_guard lock(m_backendMutex);
    return m_backend->kind();
}

std::string IoEngine::reason() const
{
    std::lock_guard lock(m_backendMutex);
    return m_reason;
}

void IoEngine::switchToThreadPool(const std::string &reason)
{
    std::lock_guard lock(m_backendMutex);
    if (m_backend->kind() == IoBackendKind::ThreadPool) {
        return;
    }
    qWarning().noquote() << "library: io backend switched to threadpool, reason" << reason.c_str();
    m_retired = std::move(m_backend);
    m_backend = std::make_shared<ThreadPoolBackend>(m_config, m_opener, m_stats, m_fdBudget);
    m_reason = reason;
    m_backendChanges.fetch_add(1);
}

std::vector<IoResult> IoEngine::runBatch(std::vector<IoRequest> requests)
{
    const std::size_t count = requests.size();
    std::vector<IoResult> results(count);
    std::vector<BudgetLease> leases(count);
    std::vector<bool> ready(count, false);
    std::vector<std::size_t> indices;
    std::vector<IoRequest> submit;
    for (std::size_t i = 0; i < count; ++i) {
        IoRequest &req = requests[i];
        if (req.op == IoOp::Open && !m_fdBudget.acquire(1, req.token)) {
            results[i].res = tokenCancelled(req.token) ? -ECANCELED : -EMFILE;
            ready[i] = true;
            continue;
        }
        if (req.op == IoOp::Read) {
            if (!m_bufferBudget.acquire(req.length, req.token)) {
                results[i].res = tokenCancelled(req.token) ? -ECANCELED : -ENOMEM;
                ready[i] = true;
                continue;
            }
            leases[i] = BudgetLease(&m_bufferBudget, req.length);
        }
        indices.push_back(i);
        submit.push_back(req);
    }

    std::shared_ptr<IoBackend> backend;
    {
        std::lock_guard lock(m_backendMutex);
        backend = m_backend;
    }
    std::vector<IoResult> partial = backend->runBatch(submit);
    std::vector<std::size_t> replay;
    for (std::size_t k = 0; k < partial.size(); ++k) {
        if (partial[k].backendFailure) {
            replay.push_back(k);
        }
    }
    if (!replay.empty()) {
        switchToThreadPool("RUNTIME_FAILURE");
        std::vector<IoRequest> again;
        for (std::size_t k : replay) {
            again.push_back(submit[k]);
        }
        std::shared_ptr<IoBackend> fallback;
        {
            std::lock_guard lock(m_backendMutex);
            fallback = m_backend;
        }
        std::vector<IoResult> replayed = fallback->runBatch(again);
        for (std::size_t r = 0; r < replay.size(); ++r) {
            partial[replay[r]] = std::move(replayed[r]);
        }
    }

    for (std::size_t k = 0; k < partial.size(); ++k) {
        const std::size_t i = indices[k];
        IoResult &result = partial[k];
        const IoOp op = requests[i].op;
        if (op == IoOp::Open && result.res < 0 && !result.abandoned) {
            m_fdBudget.release(1);
        }
        if (op == IoOp::Close) {
            m_fdBudget.release(1);
        }
        if (op == IoOp::Read) {
            result.bufferLease = std::move(leases[i]);
        }
        results[i] = std::move(result);
    }
    return results;
}

IoResult IoEngine::run(IoRequest request)
{
    std::vector<IoRequest> batch;
    batch.push_back(std::move(request));
    return std::move(runBatch(std::move(batch)).front());
}

void IoEngine::cancel(const CancelToken &token)
{
    if (!token) {
        return;
    }
    token->cancelled.store(true);
    std::shared_ptr<IoBackend> backend;
    {
        std::lock_guard lock(m_backendMutex);
        backend = m_backend;
    }
    backend->cancel(token);
}

} // namespace threesixty::daemon::library
