#include "inotify_watcher.hpp"

#include <cerrno>
#include <cstring>
#include <fstream>

#include <sys/inotify.h>
#include <unistd.h>

namespace threesixty::daemon::library {

InotifyWatcher::~InotifyWatcher()
{
    if (m_fd >= 0) {
        ::close(m_fd);
    }
}

bool InotifyWatcher::init(unsigned budget)
{
    unsigned systemMax = 0;
    std::ifstream in("/proc/sys/fs/inotify/max_user_watches");
    in >> systemMax;
    m_budget = budget;
    if (systemMax > 0) {
        m_budget = std::min(m_budget, std::max(1u, systemMax / 2));
    }
    m_fd = ::inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    return m_fd >= 0;
}

InotifyWatcher::AddResult InotifyWatcher::addWatch(int rootFd, const SafeOpener &opener,
                                                   const std::string &rel)
{
    if (m_fd < 0) {
        return AddResult::Failed;
    }
    {
        std::lock_guard lock(m_mutex);
        if (m_relToWd.contains(rel)) {
            return AddResult::Existing;
        }
        if (m_wdToRel.size() >= m_budget) {
            m_exhausted = true;
            return AddResult::BudgetExhausted;
        }
    }
    UniqueFd dir(opener.openBeneath(rootFd, rel, true));
    if (!dir.valid()) {
        return AddResult::Failed;
    }
    const std::string procPath = "/proc/self/fd/" + std::to_string(dir.get());
    const int wd = ::inotify_add_watch(m_fd, procPath.c_str(), kMask);
    if (wd < 0) {
        if (errno == ENOSPC) {
            std::lock_guard lock(m_mutex);
            m_exhausted = true;
            return AddResult::BudgetExhausted;
        }
        return AddResult::Failed;
    }
    std::lock_guard lock(m_mutex);
    auto existing = m_wdToRel.find(wd);
    if (existing != m_wdToRel.end()) {
        // Same inode already watched under another name (hard to reach for
        // directories, but keep the table consistent).
        m_relToWd.erase(existing->second);
    }
    m_wdToRel[wd] = rel;
    m_relToWd[rel] = wd;
    return AddResult::Added;
}

void InotifyWatcher::removeWd(int wd)
{
    std::lock_guard lock(m_mutex);
    auto it = m_wdToRel.find(wd);
    if (it == m_wdToRel.end()) {
        return;
    }
    m_relToWd.erase(it->second);
    m_wdToRel.erase(it);
}

void InotifyWatcher::removeTree(const std::string &rel)
{
    std::vector<int> drop;
    {
        std::lock_guard lock(m_mutex);
        for (const auto &[path, wd] : m_relToWd) {
            if (path == rel || (path.size() > rel.size() && path.compare(0, rel.size(), rel) == 0 &&
                                path[rel.size()] == '/')) {
                drop.push_back(wd);
            }
        }
        for (int wd : drop) {
            m_relToWd.erase(m_wdToRel[wd]);
            m_wdToRel.erase(wd);
        }
    }
    for (int wd : drop) {
        ::inotify_rm_watch(m_fd, wd);
    }
}

void InotifyWatcher::renamePrefix(const std::string &from, const std::string &to)
{
    std::lock_guard lock(m_mutex);
    std::map<std::string, int> renamed;
    for (auto it = m_relToWd.begin(); it != m_relToWd.end();) {
        const std::string &path = it->first;
        if (path == from || (path.size() > from.size() && path.compare(0, from.size(), from) == 0 &&
                             path[from.size()] == '/')) {
            const std::string next = to + path.substr(from.size());
            renamed[next] = it->second;
            m_wdToRel[it->second] = next;
            it = m_relToWd.erase(it);
        } else {
            ++it;
        }
    }
    for (auto &[path, wd] : renamed) {
        m_relToWd[path] = wd;
    }
}

void InotifyWatcher::clear()
{
    std::lock_guard lock(m_mutex);
    for (const auto &[wd, rel] : m_wdToRel) {
        ::inotify_rm_watch(m_fd, wd);
    }
    m_wdToRel.clear();
    m_relToWd.clear();
    m_exhausted = false;
}

std::optional<std::string> InotifyWatcher::relFor(int wd) const
{
    std::lock_guard lock(m_mutex);
    auto it = m_wdToRel.find(wd);
    if (it == m_wdToRel.end()) {
        return std::nullopt;
    }
    return it->second;
}

void InotifyWatcher::readEvents(std::vector<RawInotifyEvent> &out)
{
    if (m_fd < 0) {
        return;
    }
    alignas(inotify_event) char buffer[64 * 1024];
    while (true) {
        const ssize_t n = ::read(m_fd, buffer, sizeof buffer);
        if (n <= 0) {
            return;
        }
        for (ssize_t offset = 0; offset < n;) {
            const auto *event = reinterpret_cast<const inotify_event *>(buffer + offset);
            RawInotifyEvent raw;
            raw.wd = event->wd;
            raw.mask = event->mask;
            raw.cookie = event->cookie;
            if (event->len > 0) {
                raw.name = std::string(event->name, strnlen(event->name, event->len));
            }
            out.push_back(std::move(raw));
            offset += static_cast<ssize_t>(sizeof(inotify_event) + event->len);
        }
    }
}

std::size_t InotifyWatcher::used() const
{
    std::lock_guard lock(m_mutex);
    return m_wdToRel.size();
}

bool InotifyWatcher::exhausted() const
{
    std::lock_guard lock(m_mutex);
    return m_exhausted;
}

} // namespace threesixty::daemon::library
