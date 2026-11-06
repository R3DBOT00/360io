#include "recovery_detect.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>

#include <dirent.h>
#include <fcntl.h>
#include <linux/input.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace threesixty::recovery {

namespace {

constexpr std::size_t kKeyBytes = (KEY_MAX + 8) / 8;

bool isSpace(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

class Fd {
public:
    explicit Fd(int fd) : fd_(fd) {}
    ~Fd() { if (fd_ >= 0) ::close(fd_); }
    Fd(const Fd &) = delete;
    Fd &operator=(const Fd &) = delete;
    int get() const { return fd_; }

private:
    int fd_;
};

std::string errnoText(const char *what)
{
    return std::string(what) + ": " + std::strerror(errno);
}

} // namespace

std::string_view reasonName(Reason reason)
{
    switch (reason) {
    case Reason::Cmdline: return "cmdline";
    case Reason::Shift: return "shift";
    case Reason::None: break;
    }
    return "none";
}

bool cmdlineRequestsRecovery(std::string_view cmdline)
{
    std::size_t pos = 0;
    while (pos < cmdline.size()) {
        while (pos < cmdline.size() && isSpace(cmdline[pos]))
            ++pos;
        std::size_t end = pos;
        while (end < cmdline.size() && !isSpace(cmdline[end]))
            ++end;
        if (cmdline.substr(pos, end - pos) == kCmdlineToken)
            return true;
        pos = end;
    }
    return false;
}

bool testKeyBit(std::span<const std::uint8_t> bits, unsigned code)
{
    const std::size_t byte = code / 8;
    return byte < bits.size() && (bits[byte] >> (code % 8)) & 1u;
}

bool shiftHeld(std::span<const std::uint8_t> keyState)
{
    return testKeyBit(keyState, KEY_LEFTSHIFT) || testKeyBit(keyState, KEY_RIGHTSHIFT);
}

bool hasShiftKey(std::span<const std::uint8_t> keyCaps)
{
    return testKeyBit(keyCaps, KEY_LEFTSHIFT) || testKeyBit(keyCaps, KEY_RIGHTSHIFT);
}

ScanResult scanForShift(const ScanOptions &options)
{
    ScanResult result;
    const auto deadline = options.now() + options.timeout;
    for (;;) {
        ++result.rounds;
        result.devicesOpened = 0;
        result.keyboards = 0;
        for (const auto &path : options.listDevices()) {
            const DeviceProbe probe = options.probe(path);
            if (!probe.opened)
                continue;
            ++result.devicesOpened;
            if (!hasShiftKey(probe.caps))
                continue;
            ++result.keyboards;
            if (shiftHeld(probe.state)) {
                result.shift = true;
                return result;
            }
        }
        const auto now = options.now();
        if (now >= deadline)
            return result;
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        options.sleep(std::min(options.interval, left));
    }
}

std::vector<std::string> listEventDevices(const std::string &inputDir)
{
    std::vector<std::string> out;
    DIR *dir = ::opendir(inputDir.c_str());
    if (!dir)
        return out;
    while (const dirent *entry = ::readdir(dir)) {
        const std::string_view name = entry->d_name;
        if (name.starts_with("event") && name.size() > 5
            && std::all_of(name.begin() + 5, name.end(), [](char c) { return c >= '0' && c <= '9'; }))
            out.push_back(inputDir + "/" + std::string(name));
    }
    ::closedir(dir);
    std::sort(out.begin(), out.end());
    return out;
}

DeviceProbe probeEventDevice(const std::string &path)
{
    DeviceProbe probe;
    Fd fd(::open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOCTTY));
    if (fd.get() < 0)
        return probe;
    struct stat st {};
    if (::fstat(fd.get(), &st) != 0 || !S_ISCHR(st.st_mode))
        return probe;
    probe.opened = true;
    probe.caps.assign(kKeyBytes, 0);
    probe.state.assign(kKeyBytes, 0);
    if (::ioctl(fd.get(), EVIOCGBIT(EV_KEY, kKeyBytes), probe.caps.data()) < 0)
        probe.caps.clear();
    if (::ioctl(fd.get(), EVIOCGKEY(kKeyBytes), probe.state.data()) < 0)
        probe.state.clear();
    return probe;
}

std::optional<std::string> writeFlag(const std::string &runDir, Reason reason)
{
    Fd base(::open(runDir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (base.get() < 0)
        return errnoText(runDir.c_str());
    if (::mkdirat(base.get(), "360io", 0755) != 0 && errno != EEXIST)
        return errnoText("mkdir 360io");
    Fd dir(::openat(base.get(), "360io", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (dir.get() < 0)
        return errnoText("open 360io");

    const std::string tmpName = std::string(kFlagName) + ".tmp";
    ::unlinkat(dir.get(), tmpName.c_str(), 0);
    Fd tmp(::openat(dir.get(), tmpName.c_str(),
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644));
    if (tmp.get() < 0)
        return errnoText("create flag");
    const std::string body = "reason=" + std::string(reasonName(reason)) + "\n";
    if (::write(tmp.get(), body.data(), body.size()) != static_cast<ssize_t>(body.size()))
        return errnoText("write flag");
    if (::renameat(dir.get(), tmpName.c_str(), dir.get(), std::string(kFlagName).c_str()) != 0)
        return errnoText("rename flag");
    return std::nullopt;
}

} // namespace threesixty::recovery
