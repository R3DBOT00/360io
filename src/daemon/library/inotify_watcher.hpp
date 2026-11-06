#pragma once

// inotify watch table for the library root (§4.3). inotify is not
// recursive: one watch per relevant directory, bounded by a budget. Watches
// are added through /proc/self/fd/<fd> of a directory opened with
// openat2(RESOLVE_BENEATH), so a racing symlink can never place a watch
// outside the root.

#include "safe_fs.hpp"

#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace threesixty::daemon::library {

struct RawInotifyEvent {
    int wd = -1;
    std::uint32_t mask = 0;
    std::uint32_t cookie = 0;
    std::string name;
};

class InotifyWatcher
{
public:
    InotifyWatcher() = default;
    ~InotifyWatcher();
    InotifyWatcher(const InotifyWatcher &) = delete;
    InotifyWatcher &operator=(const InotifyWatcher &) = delete;

    // budget: configured cap; the effective budget is also capped at 50 % of
    // fs.inotify.max_user_watches.
    bool init(unsigned budget);
    int fd() const { return m_fd; }

    enum class AddResult { Added, Existing, BudgetExhausted, Failed };
    AddResult addWatch(int rootFd, const SafeOpener &opener, const std::string &rel);
    void removeWd(int wd);
    // Drops every watch at or below rel (subtree moved out of the root).
    void removeTree(const std::string &rel);
    void renamePrefix(const std::string &from, const std::string &to);
    void clear();

    std::optional<std::string> relFor(int wd) const;
    // Reads all queued kernel events (64 KiB batches, non-blocking).
    void readEvents(std::vector<RawInotifyEvent> &out);

    std::size_t used() const;
    unsigned budget() const { return m_budget; }
    bool exhausted() const;

    static constexpr std::uint32_t kMask = 0x00000100 /*IN_CREATE*/ | 0x00000200 /*IN_DELETE*/ |
        0x00000040 /*IN_MOVED_FROM*/ | 0x00000080 /*IN_MOVED_TO*/ | 0x00000008 /*IN_CLOSE_WRITE*/ |
        0x00000004 /*IN_ATTRIB*/ | 0x00000400 /*IN_DELETE_SELF*/ | 0x00000800 /*IN_MOVE_SELF*/ |
        0x01000000 /*IN_ONLYDIR*/ | 0x04000000 /*IN_EXCL_UNLINK*/;

private:
    int m_fd = -1;
    unsigned m_budget = 0;
    bool m_exhausted = false;
    mutable std::mutex m_mutex;
    std::map<int, std::string> m_wdToRel;
    std::map<std::string, int> m_relToWd;
};

} // namespace threesixty::daemon::library
