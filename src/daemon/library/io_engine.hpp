#pragma once

// Asynchronous I/O for the scanner pipeline (§5). One interface, two
// backends: io_uring (liburing, when built and allowed at runtime) and a
// fixed thread pool using statx/openat2/pread. Callers submit batches and
// never know which backend served them.

#include "library_types.hpp"
#include "safe_fs.hpp"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include <sys/stat.h>

namespace threesixty::daemon::library {

enum class IoBackendKind { ThreadPool, IoUring };
const char *ioBackendKindName(IoBackendKind kind);

struct CancelState {
    std::atomic<bool> cancelled{false};
};
using CancelToken = std::shared_ptr<CancelState>;
inline CancelToken makeCancelToken() { return std::make_shared<CancelState>(); }

// Counting semaphore used for fds and buffer bytes (§5.4 limits).
class ResourceBudget
{
public:
    explicit ResourceBudget(std::uint64_t capacity)
        : m_capacity(capacity)
    {
    }
    // Blocks until amount is available; false if amount > capacity or cancelled.
    bool acquire(std::uint64_t amount, const CancelToken &token);
    bool tryAcquire(std::uint64_t amount);
    void release(std::uint64_t amount);
    std::uint64_t inUse() const;
    std::uint64_t peak() const;
    std::uint64_t capacity() const { return m_capacity; }

private:
    const std::uint64_t m_capacity;
    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    std::uint64_t m_used = 0;
    std::uint64_t m_peak = 0;
};

// Moves ownership of acquired budget; releases on destruction.
class BudgetLease
{
public:
    BudgetLease() = default;
    BudgetLease(ResourceBudget *budget, std::uint64_t amount)
        : m_budget(budget)
        , m_amount(amount)
    {
    }
    ~BudgetLease() { reset(); }
    BudgetLease(BudgetLease &&other) noexcept
        : m_budget(std::exchange(other.m_budget, nullptr))
        , m_amount(std::exchange(other.m_amount, 0))
    {
    }
    BudgetLease &operator=(BudgetLease &&other) noexcept
    {
        if (this != &other) {
            reset();
            m_budget = std::exchange(other.m_budget, nullptr);
            m_amount = std::exchange(other.m_amount, 0);
        }
        return *this;
    }
    void reset()
    {
        if (m_budget != nullptr && m_amount > 0) {
            m_budget->release(m_amount);
        }
        m_budget = nullptr;
        m_amount = 0;
    }

private:
    ResourceBudget *m_budget = nullptr;
    std::uint64_t m_amount = 0;
};

enum class IoOp { Statx, Open, Read, Close };

struct IoRequest {
    IoOp op = IoOp::Read;
    int dirFd = -1;
    std::string path;     // Statx/Open: relative to dirFd
    bool directory = false;
    int fd = -1;          // Read/Close
    std::uint64_t offset = 0;
    std::uint32_t length = 0;
    CancelToken token;
};

struct IoResult {
    int res = 0; // fd / bytes read / 0 on success, -errno on failure
    std::vector<std::uint8_t> data;
    struct statx stx {};
    bool timedOut = false;
    bool cancelled = false;
    bool backendFailure = false; // internal: request never reached the kernel
    bool abandoned = false;      // internal: waiter gave up; late completion cleans up
    BudgetLease bufferLease;
};

struct IoStats {
    std::atomic<std::uint64_t> submitted{0};
    std::atomic<std::uint64_t> completed{0};
    std::atomic<std::uint64_t> timeouts{0};
    std::atomic<std::uint64_t> cancelled{0};
    std::atomic<std::uint64_t> bytesRead{0};
    std::atomic<std::int64_t> inflight{0};
    std::atomic<std::int64_t> peakInflight{0};
    void noteInflight(std::int64_t delta);
};

class IoBackend;

class IoEngine
{
public:
    IoEngine(const LibraryConfig &config, const SafeOpener &opener);
    ~IoEngine();
    IoEngine(const IoEngine &) = delete;
    IoEngine &operator=(const IoEngine &) = delete;

    // Blocking from the caller's point of view; the requests of a batch are
    // in flight concurrently. Results keep request order.
    std::vector<IoResult> runBatch(std::vector<IoRequest> requests);
    IoResult run(IoRequest request);

    // Cancels queued/in-flight requests carrying this token.
    void cancel(const CancelToken &token);

    IoBackendKind kind() const;
    std::string reason() const;
    std::uint64_t backendChanges() const { return m_backendChanges.load(); }

    const IoStats &stats() const { return m_stats; }
    ResourceBudget &fdBudget() { return m_fdBudget; }
    ResourceBudget &bufferBudget() { return m_bufferBudget; }
    const ResourceBudget &fdBudget() const { return m_fdBudget; }
    const ResourceBudget &bufferBudget() const { return m_bufferBudget; }

    // Largest number of fds a single scan worker may hold at once.
    unsigned perWorkerFdQuota() const;

private:
    void switchToThreadPool(const std::string &reason);

    const LibraryConfig m_config;
    const SafeOpener &m_opener;
    IoStats m_stats;
    ResourceBudget m_fdBudget;
    ResourceBudget m_bufferBudget;
    mutable std::mutex m_backendMutex;
    std::shared_ptr<IoBackend> m_backend;
    std::shared_ptr<IoBackend> m_retired;
    std::string m_reason;
    std::atomic<std::uint64_t> m_backendChanges{0};
};

// Exposed for tests: the decision of §5.3 without building anything.
struct IoBackendSelection {
    IoBackendKind kind = IoBackendKind::ThreadPool;
    std::string reason;
};
bool liburingCompiledIn();

} // namespace threesixty::daemon::library
