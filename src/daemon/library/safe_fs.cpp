#include "safe_fs.hpp"

#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>

#include <dirent.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <linux/openat2.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#ifndef BTRFS_SUPER_MAGIC
#define BTRFS_SUPER_MAGIC 0x9123683E
#endif
#ifndef EXT4_SUPER_MAGIC
#define EXT4_SUPER_MAGIC 0xEF53
#endif
#ifndef TMPFS_MAGIC
#define TMPFS_MAGIC 0x01021994
#endif
#ifndef STATX_MNT_ID
#define STATX_MNT_ID 0x00001000U
#endif

namespace threesixty::daemon::library {

namespace {

std::string readSmallFile(const char *path)
{
    std::ifstream in(path, std::ios::binary);
    std::ostringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}

std::string unescapeMountField(std::string_view field)
{
    std::string out;
    for (std::size_t i = 0; i < field.size(); ++i) {
        if (field[i] == '\\' && i + 3 < field.size() && field[i + 1] >= '0' &&
            field[i + 1] <= '7') {
            const int value = (field[i + 1] - '0') * 64 + (field[i + 2] - '0') * 8 + (field[i + 3] - '0');
            out.push_back(static_cast<char>(value));
            i += 3;
        } else {
            out.push_back(field[i]);
        }
    }
    return out;
}

bool hasOption(std::string_view options, std::string_view name)
{
    std::size_t start = 0;
    while (start <= options.size()) {
        const std::size_t comma = options.find(',', start);
        const std::string_view opt =
            options.substr(start, comma == std::string_view::npos ? std::string_view::npos : comma - start);
        if (opt == name) {
            return true;
        }
        if (comma == std::string_view::npos) {
            break;
        }
        start = comma + 1;
    }
    return false;
}

bool hasZstd(std::string_view options)
{
    for (std::string_view key : {"compress=zstd", "compress-force=zstd"}) {
        std::size_t pos = options.find(key);
        while (pos != std::string_view::npos) {
            const bool startOk = pos == 0 || options[pos - 1] == ',';
            const std::size_t end = pos + key.size();
            const bool endOk = end == options.size() || options[end] == ',' || options[end] == ':';
            if (startOk && endOk) {
                return true;
            }
            pos = options.find(key, pos + 1);
        }
    }
    return false;
}

std::string fsTypeName(long type)
{
    switch (static_cast<unsigned long>(type)) {
    case EXT4_SUPER_MAGIC:
        return "ext4";
    case BTRFS_SUPER_MAGIC:
        return "btrfs";
    case TMPFS_MAGIC:
        return "tmpfs";
    default: {
        char buf[32];
        std::snprintf(buf, sizeof buf, "0x%lx", static_cast<unsigned long>(type));
        return buf;
    }
    }
}

std::string uuidForDevice(unsigned major, unsigned minor, const struct statfs &sfs)
{
    DIR *dir = opendir("/dev/disk/by-uuid");
    if (dir != nullptr) {
        while (dirent *entry = readdir(dir)) {
            if (entry->d_name[0] == '.') {
                continue;
            }
            struct stat st {};
            const std::string path = std::string("/dev/disk/by-uuid/") + entry->d_name;
            if (stat(path.c_str(), &st) == 0 && S_ISBLK(st.st_mode) &&
                ::major(st.st_rdev) == major && ::minor(st.st_rdev) == minor) {
                std::string uuid = entry->d_name;
                closedir(dir);
                return uuid;
            }
        }
        closedir(dir);
    }
    int fsid[2];
    std::memcpy(fsid, &sfs.f_fsid, sizeof fsid);
    char buf[48];
    std::snprintf(buf, sizeof buf, "fsid-%08x%08x", static_cast<unsigned>(fsid[0]),
                  static_cast<unsigned>(fsid[1]));
    return buf;
}

std::string trimTrailingSlash(std::string path)
{
    while (path.size() > 1 && path.back() == '/') {
        path.pop_back();
    }
    return path;
}

} // namespace

void UniqueFd::reset(int fd)
{
    if (m_fd >= 0) {
        ::close(m_fd);
    }
    m_fd = fd;
}

const char *mountStateName(MountState state)
{
    switch (state) {
    case MountState::Ok:
        return "OK";
    case MountState::Absent:
        return "MOUNT_ABSENT";
    case MountState::NotAMountpoint:
        return "NOT_A_MOUNTPOINT";
    case MountState::UnsupportedFs:
        return "UNSUPPORTED_FS";
    case MountState::UnexpectedDevice:
        return "UNEXPECTED_DEVICE";
    case MountState::PolicyViolation:
        return "MOUNT_POLICY_VIOLATION";
    }
    return "UNKNOWN";
}

std::vector<MountInfoEntry> parseMountInfo(std::string_view text)
{
    std::vector<MountInfoEntry> entries;
    std::size_t lineStart = 0;
    while (lineStart < text.size()) {
        std::size_t lineEnd = text.find('\n', lineStart);
        if (lineEnd == std::string_view::npos) {
            lineEnd = text.size();
        }
        const std::string line(text.substr(lineStart, lineEnd - lineStart));
        lineStart = lineEnd + 1;

        std::istringstream in(line);
        std::vector<std::string> fields;
        std::string field;
        while (in >> field) {
            fields.push_back(field);
        }
        std::size_t dash = 0;
        for (std::size_t i = 6; i < fields.size(); ++i) {
            if (fields[i] == "-") {
                dash = i;
                break;
            }
        }
        if (dash == 0 || dash + 1 >= fields.size()) {
            continue;
        }
        MountInfoEntry entry;
        entry.mountId = std::strtoull(fields[0].c_str(), nullptr, 10);
        const std::size_t colon = fields[2].find(':');
        if (colon == std::string::npos) {
            continue;
        }
        entry.major = static_cast<unsigned>(std::strtoul(fields[2].substr(0, colon).c_str(), nullptr, 10));
        entry.minor = static_cast<unsigned>(std::strtoul(fields[2].substr(colon + 1).c_str(), nullptr, 10));
        entry.mountPoint = unescapeMountField(fields[4]);
        entry.mountOptions = fields[5];
        entry.fsType = dash + 1 < fields.size() ? fields[dash + 1] : "";
        entry.superOptions = dash + 3 < fields.size() ? fields[dash + 3] : "";
        entries.push_back(std::move(entry));
    }
    return entries;
}

MountCheck validateLibraryMount(const LibraryConfig &config)
{
    MountCheck check;
    const std::string root = trimTrailingSlash(config.rootPath);
    UniqueFd fd(::open(root.c_str(), O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (!fd.valid()) {
        check.state = MountState::Absent;
        check.detail = std::strerror(errno);
        return check;
    }
    struct statx stx {};
    if (::statx(fd.get(), "", AT_EMPTY_PATH, STATX_MNT_ID | STATX_INO | STATX_TYPE, &stx) != 0) {
        check.state = MountState::Absent;
        check.detail = std::strerror(errno);
        return check;
    }
    struct statfs sfs {};
    if (::fstatfs(fd.get(), &sfs) != 0) {
        check.state = MountState::Absent;
        check.detail = std::strerror(errno);
        return check;
    }
    check.fsType = fsTypeName(sfs.f_type);
    check.mountId = (stx.stx_mask & STATX_MNT_ID) ? stx.stx_mnt_id : 0;

    const auto mounts = parseMountInfo(readSmallFile("/proc/self/mountinfo"));
    const MountInfoEntry *entry = nullptr;
    for (const MountInfoEntry &candidate : mounts) {
        if (candidate.mountId == check.mountId) {
            entry = &candidate;
        }
    }
    if (entry != nullptr) {
        check.readOnly = hasOption(entry->mountOptions, "ro");
        check.fsUuid = uuidForDevice(entry->major, entry->minor, sfs);
    } else {
        check.fsUuid = uuidForDevice(~0u, ~0u, sfs);
    }

    if (config.mountPolicy == MountPolicy::AnyFilesystem) {
        check.state = MountState::Ok;
        check.detail = "policy=any-filesystem";
        return check;
    }

    struct stat rootStat {};
    struct stat libStat {};
    if (entry == nullptr) {
        check.state = MountState::NotAMountpoint;
        return check;
    }
    if (config.mountPolicy != MountPolicy::Directory &&
        (entry->mountPoint != root || ::stat("/", &rootStat) != 0 ||
         ::fstat(fd.get(), &libStat) != 0 || rootStat.st_dev == libStat.st_dev)) {
        check.state = MountState::NotAMountpoint;
        return check;
    }
    const unsigned long type = static_cast<unsigned long>(sfs.f_type);
    if (type != EXT4_SUPER_MAGIC && type != BTRFS_SUPER_MAGIC) {
        check.state = MountState::UnsupportedFs;
        return check;
    }
    if (!config.expectedFsUuid.empty()) {
        struct stat dev {};
        const std::string path = "/dev/disk/by-uuid/" + config.expectedFsUuid;
        if (::stat(path.c_str(), &dev) != 0 || ::major(dev.st_rdev) != entry->major ||
            ::minor(dev.st_rdev) != entry->minor) {
            check.state = MountState::UnexpectedDevice;
            return check;
        }
        check.fsUuid = config.expectedFsUuid;
    }
    if (type == BTRFS_SUPER_MAGIC && !config.allowBtrfsWithoutZstd &&
        !hasZstd(entry->mountOptions) && !hasZstd(entry->superOptions)) {
        check.state = MountState::PolicyViolation;
        check.detail = "btrfs without compress=zstd";
        return check;
    }
    check.state = MountState::Ok;
    return check;
}

bool kernelSupportsOpenat2()
{
    open_how how {};
    how.flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC;
    const long fd = ::syscall(SYS_openat2, AT_FDCWD, "/", &how, sizeof how);
    if (fd >= 0) {
        ::close(static_cast<int>(fd));
        return true;
    }
    return false;
}

SafeOpener::SafeOpener(bool forceFallback)
    : m_openat2(!forceFallback && kernelSupportsOpenat2())
{
}

int SafeOpener::openBeneath(int rootFd, std::string_view rel, bool directory) const
{
    if (rel.empty()) {
        rel = ".";
    }
    if (!m_openat2) {
        return fallbackOpen(rootFd, rel, directory);
    }
    const std::string path(rel);
    open_how how {};
    how.flags = O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK |
        (directory ? O_DIRECTORY : O_NOFOLLOW);
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV;
    const long fd = ::syscall(SYS_openat2, rootFd, path.c_str(), &how, sizeof how);
    if (fd < 0) {
        const int err = errno;
        if (err == ENOSYS) {
            return fallbackOpen(rootFd, rel, directory);
        }
        return -err;
    }
    return static_cast<int>(fd);
}

int SafeOpener::fallbackOpen(int rootFd, std::string_view rel, bool directory) const
{
    // Stricter than openat2: every component is opened with O_NOFOLLOW, so
    // any symlink (even one staying inside the root) is rejected.
    struct stat rootStat {};
    if (::fstat(rootFd, &rootStat) != 0) {
        return -errno;
    }
    if (rel == ".") {
        const int fd = ::openat(rootFd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        return fd >= 0 ? fd : -errno;
    }
    std::vector<std::string> parts;
    std::size_t start = 0;
    while (start <= rel.size()) {
        const std::size_t slash = rel.find('/', start);
        const std::string_view part =
            rel.substr(start, slash == std::string_view::npos ? std::string_view::npos : slash - start);
        if (part.empty() || part == "." || part == "..") {
            return -EXDEV;
        }
        parts.emplace_back(part);
        if (slash == std::string_view::npos) {
            break;
        }
        start = slash + 1;
    }
    UniqueFd current(::fcntl(rootFd, F_DUPFD_CLOEXEC, 0));
    if (!current.valid()) {
        return -errno;
    }
    for (std::size_t i = 0; i < parts.size(); ++i) {
        const bool last = i + 1 == parts.size();
        int flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY | O_NONBLOCK;
        if (!last || directory) {
            flags |= O_DIRECTORY;
        }
        UniqueFd next(::openat(current.get(), parts[i].c_str(), flags));
        if (!next.valid()) {
            const int err = errno;
            return err == ENOTDIR && !last ? -ELOOP : -err;
        }
        struct stat st {};
        if (::fstat(next.get(), &st) != 0) {
            return -errno;
        }
        if (st.st_dev != rootStat.st_dev) {
            return -EXDEV;
        }
        current = std::move(next);
    }
    return current.release();
}

int listDirectory(int dirFd, std::size_t maxEntries, std::vector<DirEntryRaw> &out, bool &truncated)
{
    truncated = false;
    alignas(8) char buffer[64 * 1024];
    while (true) {
        const long n = ::syscall(SYS_getdents64, dirFd, buffer, sizeof buffer);
        if (n < 0) {
            return -errno;
        }
        if (n == 0) {
            return 0;
        }
        long offset = 0;
        while (offset < n) {
            struct Dirent64 {
                std::uint64_t d_ino;
                std::int64_t d_off;
                unsigned short d_reclen;
                unsigned char d_type;
                char d_name[1];
            };
            const auto *entry = reinterpret_cast<const Dirent64 *>(buffer + offset);
            if (entry->d_reclen == 0) {
                return -EIO;
            }
            offset += entry->d_reclen;
            const std::string_view name(entry->d_name);
            if (name == "." || name == "..") {
                continue;
            }
            if (out.size() >= maxEntries) {
                truncated = true;
                return 0;
            }
            DirEntryRaw raw;
            raw.name = std::string(name);
            raw.ino = entry->d_ino;
            raw.type = entry->d_type;
            if (raw.type == DT_UNKNOWN) {
                struct stat st {};
                if (::fstatat(dirFd, raw.name.c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0) {
                    raw.type = S_ISDIR(st.st_mode) ? DT_DIR
                        : S_ISREG(st.st_mode)      ? DT_REG
                        : S_ISLNK(st.st_mode)      ? DT_LNK
                                                   : DT_UNKNOWN;
                }
            }
            out.push_back(std::move(raw));
        }
    }
}

DirIdentity identityOf(int dirFd)
{
    DirIdentity id;
    struct {
        file_handle header;
        unsigned char bytes[MAX_HANDLE_SZ];
    } handle {};
    handle.header.handle_bytes = MAX_HANDLE_SZ;
    int mountId = 0;
    if (::name_to_handle_at(dirFd, "", &handle.header, &mountId, AT_EMPTY_PATH) == 0) {
        const auto type = static_cast<std::int32_t>(handle.header.handle_type);
        id.handle.assign(reinterpret_cast<const char *>(&type), sizeof type);
        id.handle.append(reinterpret_cast<const char *>(handle.header.f_handle),
                         handle.header.handle_bytes);
    }
    struct statx stx {};
    if (::statx(dirFd, "", AT_EMPTY_PATH, STATX_INO | STATX_BTIME | STATX_MTIME, &stx) == 0) {
        id.ino = stx.stx_ino;
        if (stx.stx_mask & STATX_BTIME) {
            id.btimeNs = std::int64_t(stx.stx_btime.tv_sec) * 1000000000 + stx.stx_btime.tv_nsec;
        }
        id.mtimeNs = std::int64_t(stx.stx_mtime.tv_sec) * 1000000000 + stx.stx_mtime.tv_nsec;
        id.dev = makedev(stx.stx_dev_major, stx.stx_dev_minor);
    }
    return id;
}

std::string joinRel(std::string_view a, std::string_view b)
{
    if (a.empty()) {
        return std::string(b);
    }
    if (b.empty()) {
        return std::string(a);
    }
    std::string out(a);
    out.push_back('/');
    out.append(b);
    return out;
}

} // namespace threesixty::daemon::library
