#pragma once

// Read-only filesystem primitives confined to the library root (§3.2, §8.3):
// mount validation, openat2(RESOLVE_BENEATH) with a stricter openat
// fallback, getdents64 listing and directory identity. Nothing here writes.

#include "library_types.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace threesixty::daemon::library {

class UniqueFd
{
public:
    UniqueFd() = default;
    explicit UniqueFd(int fd)
        : m_fd(fd)
    {
    }
    ~UniqueFd() { reset(); }
    UniqueFd(const UniqueFd &) = delete;
    UniqueFd &operator=(const UniqueFd &) = delete;
    UniqueFd(UniqueFd &&other) noexcept
        : m_fd(other.release())
    {
    }
    UniqueFd &operator=(UniqueFd &&other) noexcept
    {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }
    int get() const { return m_fd; }
    bool valid() const { return m_fd >= 0; }
    int release()
    {
        const int fd = m_fd;
        m_fd = -1;
        return fd;
    }
    void reset(int fd = -1);

private:
    int m_fd = -1;
};

enum class MountState {
    Ok,
    Absent,
    NotAMountpoint,
    UnsupportedFs,
    UnexpectedDevice,
    PolicyViolation,
};
const char *mountStateName(MountState state);

struct MountCheck {
    MountState state = MountState::Absent;
    std::string fsType;   // ext4, btrfs, tmpfs, ... (diagnostic)
    std::string fsUuid;   // from /dev/disk/by-uuid or fsid fallback
    std::uint64_t mountId = 0;
    bool readOnly = false;
    std::string detail;
};

MountCheck validateLibraryMount(const LibraryConfig &config);

// Parsed line of /proc/self/mountinfo (only the fields we need).
struct MountInfoEntry {
    std::uint64_t mountId = 0;
    unsigned major = 0;
    unsigned minor = 0;
    std::string mountPoint;
    std::string mountOptions;
    std::string fsType;
    std::string superOptions;
};
std::vector<MountInfoEntry> parseMountInfo(std::string_view text);

class SafeOpener
{
public:
    explicit SafeOpener(bool forceFallback = false);

    bool usesOpenat2() const { return m_openat2; }

    // Opens rel (raw bytes, '/'-separated, no leading '/') beneath rootFd.
    // Directories get O_DIRECTORY; files get O_NOFOLLOW on the last
    // component. Returns fd or -errno. Escapes fail with -EXDEV/-ELOOP.
    int openBeneath(int rootFd, std::string_view rel, bool directory) const;

private:
    int fallbackOpen(int rootFd, std::string_view rel, bool directory) const;
    bool m_openat2 = false;
};

bool kernelSupportsOpenat2();

struct DirEntryRaw {
    std::string name; // raw bytes
    unsigned char type = 0; // DT_*
    std::uint64_t ino = 0;
};

// getdents64 on dirFd; stops after maxEntries (truncated = true). Returns
// -errno on failure, 0 on success. "." and ".." are skipped; DT_UNKNOWN is
// resolved with fstatat(AT_SYMLINK_NOFOLLOW).
int listDirectory(int dirFd, std::size_t maxEntries, std::vector<DirEntryRaw> &out,
                  bool &truncated);

// name_to_handle_at + statx for a directory fd (§6).
DirIdentity identityOf(int dirFd);

std::string joinRel(std::string_view a, std::string_view b);

} // namespace threesixty::daemon::library
