#include "install_scanner.hpp"

#include "acf_parser.hpp"
#include "exe_rules.hpp"
#include "pe_parser.hpp"
#include "sanitize.hpp"

#include <QDebug>

#include <cerrno>
#include <deque>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace threesixty::daemon::library {

namespace {

class EngineByteSource final : public PeByteSource
{
public:
    EngineByteSource(IoEngine &engine, int fd, CancelToken token)
        : m_engine(engine)
        , m_fd(fd)
        , m_token(std::move(token))
    {
    }

    bool readAt(std::uint64_t offset, std::uint32_t len, std::vector<std::uint8_t> &out) override
    {
        IoRequest request;
        request.op = IoOp::Read;
        request.fd = m_fd;
        request.offset = offset;
        request.length = len;
        request.token = m_token;
        IoResult result = m_engine.run(std::move(request));
        if (result.res < 0 || static_cast<std::uint32_t>(result.res) != len) {
            return false;
        }
        out = std::move(result.data);
        return true;
    }

private:
    IoEngine &m_engine;
    int m_fd;
    CancelToken m_token;
};

std::string lastComponent(std::string_view rel)
{
    const std::size_t slash = rel.rfind('/');
    return std::string(slash == std::string_view::npos ? rel : rel.substr(slash + 1));
}

std::int64_t toNs(const statx_timestamp &ts)
{
    return std::int64_t(ts.tv_sec) * 1000000000 + ts.tv_nsec;
}

bool skipTopLevelName(std::string_view name)
{
    return name.empty() || name.front() == '.' || name == "lost+found";
}

struct PendingCandidate {
    std::string rel;
    unsigned depth = 0;
};

} // namespace

bool isTempMarkerName(std::string_view name)
{
    for (std::string_view suffix : {".part", ".tmp", ".crdownload", ".!qb", "~"}) {
        if (asciiIEndsWith(name, suffix)) {
            return true;
        }
    }
    return false;
}

InstallScanner::InstallScanner(const LibraryConfig &config, IoEngine &engine, const SafeOpener &opener)
    : m_config(config)
    , m_engine(engine)
    , m_opener(opener)
{
}

void InstallScanner::countPeFailure(const std::string &reason)
{
    std::lock_guard lock(m_countersMutex);
    ++m_peFailures[reason];
}

void InstallScanner::countAcfFailure(const std::string &reason)
{
    std::lock_guard lock(m_countersMutex);
    ++m_acfFailures[reason];
}

std::map<std::string, std::uint64_t> InstallScanner::peFailures() const
{
    std::lock_guard lock(m_countersMutex);
    return m_peFailures;
}

std::map<std::string, std::uint64_t> InstallScanner::acfFailures() const
{
    std::lock_guard lock(m_countersMutex);
    return m_acfFailures;
}

int InstallScanner::readSmallFile(int dirFd, const std::string &rel, std::uint32_t maxBytes,
                                  std::vector<std::uint8_t> &out)
{
    IoRequest open;
    open.op = IoOp::Open;
    open.dirFd = dirFd;
    open.path = rel;
    IoResult opened = m_engine.run(std::move(open));
    if (opened.res < 0) {
        return opened.res;
    }
    const int fd = opened.res;
    int status = 0;
    struct stat st {};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        status = -EINVAL;
    } else if (static_cast<std::uint64_t>(st.st_size) > maxBytes) {
        status = -EFBIG;
    } else if (st.st_size > 0) {
        IoRequest read;
        read.op = IoOp::Read;
        read.fd = fd;
        read.length = static_cast<std::uint32_t>(st.st_size);
        IoResult data = m_engine.run(std::move(read));
        if (data.res < 0) {
            status = data.res;
        } else {
            out = std::move(data.data);
        }
    }
    IoRequest close;
    close.op = IoOp::Close;
    close.fd = fd;
    m_engine.run(std::move(close));
    return status;
}

std::optional<DiscoveredInstall> InstallScanner::readManifest(int rootFd, const std::string &library,
                                                              const std::string &manifestName,
                                                              std::uint32_t appId)
{
    const std::string steamapps = joinRel(library, "steamapps");
    DiscoveredInstall install;
    install.key.kind = InstallKind::Steam;
    install.key.libraryRelPath = library;
    install.key.steamAppId = appId;

    std::vector<std::uint8_t> bytes;
    const int rc = readSmallFile(rootFd, joinRel(steamapps, manifestName), m_config.maxAcfBytes, bytes);
    if (rc == -ENOENT) {
        return std::nullopt;
    }
    std::string error;
    SteamManifestResult manifest;
    if (rc == -EFBIG) {
        error = "TOO_LARGE";
    } else if (rc < 0) {
        error = "READ_FAILED";
    } else {
        manifest = parseSteamManifest(
            std::string_view(reinterpret_cast<const char *>(bytes.data()), bytes.size()), appId);
        if (!manifest.ok) {
            error = manifest.error;
        }
    }
    if (!error.empty()) {
        countAcfFailure(error);
        install.key.relPath = joinRel(steamapps, manifestName);
        install.manifestError = error;
        qInfo().noquote() << "library: invalid Steam manifest" << sanitizeRelPath(install.key.relPath).c_str()
                          << "reason" << error.c_str();
        return install;
    }
    install.steam = manifest.info;
    install.key.relPath = joinRel(joinRel(steamapps, "common"), manifest.info.installDir);
    const int fd = m_opener.openBeneath(rootFd, install.key.relPath, true);
    if (fd >= 0) {
        install.identity = identityOf(fd);
        ::close(fd);
    } else {
        install.installDirMissing = true;
    }
    return install;
}

void InstallScanner::processLibrary(int rootFd, const std::string &library, DiscoveryResult &out)
{
    out.steamLibraries.push_back(library);
    const int fd = m_opener.openBeneath(rootFd, joinRel(library, "steamapps"), true);
    if (fd < 0) {
        return;
    }
    UniqueFd dir(fd);
    std::vector<DirEntryRaw> entries;
    bool truncated = false;
    listDirectory(dir.get(), m_config.maxEntriesPerInstall, entries, truncated);
    out.truncated = out.truncated || truncated;
    for (const DirEntryRaw &entry : entries) {
        if (entry.type != DT_REG) {
            continue;
        }
        const auto appId = appIdFromManifestName(entry.name);
        if (!appId) {
            continue;
        }
        if (auto install = readManifest(rootFd, library, entry.name, *appId)) {
            out.installs.push_back(std::move(*install));
        }
    }
}

DiscoveryResult InstallScanner::discover(int rootFd, const CancelToken &token)
{
    DiscoveryResult out;
    UniqueFd root(m_opener.openBeneath(rootFd, "", true));
    if (!root.valid()) {
        out.error = root.get();
        return out;
    }
    std::vector<DirEntryRaw> entries;
    const int rc = listDirectory(root.get(), m_config.maxEntriesPerInstall, entries, out.truncated);
    if (rc < 0) {
        out.error = rc;
        return out;
    }
    for (const DirEntryRaw &entry : entries) {
        if (token && token->cancelled.load()) {
            break;
        }
        // Top-level symlinks are never install roots (§8.3).
        if (entry.type != DT_DIR || skipTopLevelName(entry.name)) {
            continue;
        }
        if (entry.name == "steamapps") {
            processLibrary(rootFd, "", out);
            continue;
        }
        const int steamapps = m_opener.openBeneath(rootFd, joinRel(entry.name, "steamapps"), true);
        if (steamapps >= 0) {
            ::close(steamapps);
            processLibrary(rootFd, entry.name, out);
            continue;
        }
        UniqueFd dir(m_opener.openBeneath(rootFd, entry.name, true));
        if (!dir.valid()) {
            continue;
        }
        DiscoveredInstall install;
        install.key.kind = InstallKind::Directory;
        install.key.relPath = entry.name;
        install.identity = identityOf(dir.get());
        out.installs.push_back(std::move(install));
    }
    return out;
}

std::optional<DiscoveredInstall> InstallScanner::discoverOne(int rootFd, const InstallKey &key)
{
    if (key.kind == InstallKind::Steam) {
        return readManifest(rootFd, key.libraryRelPath,
                            "appmanifest_" + std::to_string(key.steamAppId) + ".acf", key.steamAppId);
    }
    UniqueFd dir(m_opener.openBeneath(rootFd, key.relPath, true));
    if (!dir.valid()) {
        return std::nullopt;
    }
    DiscoveredInstall install;
    install.key = key;
    install.identity = identityOf(dir.get());
    return install;
}

InstallSnapshot InstallScanner::snapshot(int rootFd, const InstallKey &key)
{
    InstallSnapshot snap;
    if (key.kind == InstallKind::Steam) {
        const std::string downloading = joinRel(
            joinRel(key.libraryRelPath, "steamapps/downloading"), std::to_string(key.steamAppId));
        const int fd = m_opener.openBeneath(rootFd, downloading, true);
        if (fd >= 0) {
            ::close(fd);
            snap.tempMarkers = true;
        }
    }
    UniqueFd top(m_opener.openBeneath(rootFd, key.relPath, true));
    if (!top.valid()) {
        return snap;
    }
    snap.exists = true;
    std::deque<std::pair<UniqueFd, unsigned>> queue;
    queue.emplace_back(std::move(top), 0);
    std::size_t budget = m_config.maxSnapshotEntries;
    while (!queue.empty()) {
        auto [dir, depth] = std::move(queue.front());
        queue.pop_front();
        std::vector<DirEntryRaw> entries;
        bool truncated = false;
        listDirectory(dir.get(), budget, entries, truncated);
        budget -= std::min(budget, entries.size());
        snap.truncated = snap.truncated || truncated;
        for (const DirEntryRaw &entry : entries) {
            if (entry.type == DT_DIR) {
                if (depth + 1 <= m_config.maxWalkDepth && budget > 0) {
                    UniqueFd sub(m_opener.openBeneath(dir.get(), entry.name, true));
                    if (sub.valid()) {
                        queue.emplace_back(std::move(sub), depth + 1);
                    }
                }
                continue;
            }
            if (entry.type != DT_REG) {
                continue;
            }
            if (isTempMarkerName(entry.name)) {
                snap.tempMarkers = true;
            }
            struct statx stx {};
            if (::statx(dir.get(), entry.name.c_str(), AT_SYMLINK_NOFOLLOW,
                        STATX_SIZE | STATX_MTIME | STATX_CTIME, &stx) == 0) {
                ++snap.files;
                snap.totalSize += stx.stx_size;
                snap.maxMtimeNs = std::max(snap.maxMtimeNs, toNs(stx.stx_mtime));
                snap.maxCtimeNs = std::max(snap.maxCtimeNs, toNs(stx.stx_ctime));
            }
        }
    }
    return snap;
}

InstallScanResult InstallScanner::scan(int rootFd, const DiscoveredInstall &install,
                                       std::uint64_t generation,
                                       const std::map<std::string, PreviousCandidate> &previous,
                                       const CancelToken &token)
{
    InstallScanResult result;
    result.key = install.key;
    result.generation = generation;
    result.steam = install.steam;
    result.identity = install.identity;
    const bool steam = install.key.kind == InstallKind::Steam;
    const auto deadline = Clock::now() + m_config.installTimeout;
    auto cancelled = [&] { return token && token->cancelled.load(); };

    if (!install.manifestError.empty()) {
        result.state = GameState::Error;
        result.reason = "INVALID_MANIFEST";
        result.displayName = "Steam app " + std::to_string(install.key.steamAppId);
        result.displayNameSource = "steam_appid";
        return result;
    }

    const std::string dirName = sanitizeUtf8(lastComponent(install.key.relPath));
    const std::string gameName = steam && install.steam && !install.steam->name.empty()
        ? install.steam->name
        : dirName;

    const int openRc = m_opener.openBeneath(rootFd, install.key.relPath, true);
    if (openRc < 0) {
        if (openRc == -ENOENT && !steam) {
            result.vanished = true;
            result.notAGame = true;
            return result;
        }
        result.state = GameState::Error;
        result.reason = openRc == -EACCES ? "PERMISSION_DENIED"
            : openRc == -ENOENT           ? "INSTALLDIR_MISSING"
            : (openRc == -ELOOP || openRc == -EXDEV) ? "UNSAFE_PATH"
                                                     : "OPEN_FAILED";
        result.displayName = gameName;
        result.displayNameSource = steam ? "steam_acf" : "directory";
        return result;
    }
    UniqueFd installFd(openRc);
    result.identity = identityOf(installFd.get());

    // Walk (getdents64 on this worker) collecting .exe candidates.
    std::vector<PendingCandidate> pending;
    std::deque<std::pair<std::string, unsigned>> dirs;
    dirs.emplace_back(std::string(), 0);
    std::size_t entriesLeft = m_config.maxEntriesPerInstall;
    bool timedOut = false;
    while (!dirs.empty()) {
        if (cancelled()) {
            result.cancelled = true;
            return result;
        }
        if (Clock::now() > deadline) {
            timedOut = true;
            break;
        }
        auto [rel, depth] = std::move(dirs.front());
        dirs.pop_front();
        UniqueFd dir(rel.empty() ? ::fcntl(installFd.get(), F_DUPFD_CLOEXEC, 0)
                                 : m_opener.openBeneath(installFd.get(), rel, true));
        if (!dir.valid()) {
            continue;
        }
        std::vector<DirEntryRaw> entries;
        bool truncated = false;
        listDirectory(dir.get(), entriesLeft, entries, truncated);
        entriesLeft -= std::min(entriesLeft, entries.size());
        if (truncated || entriesLeft == 0) {
            result.entriesTruncated = true;
        }
        for (DirEntryRaw &entry : entries) {
            if (entry.type == DT_DIR) {
                if (depth + 1 <= m_config.maxCandidateDepth) {
                    dirs.emplace_back(joinRel(rel, entry.name), depth + 1);
                }
            } else if (entry.type == DT_REG) {
                if (isTempMarkerName(entry.name)) {
                    result.tempMarkers = true;
                }
                if (hasExeExtension(entry.name)) {
                    if (pending.size() >= m_config.maxCandidatesPerInstall) {
                        ++result.candidatesTruncated;
                    } else {
                        pending.push_back({joinRel(rel, entry.name), depth});
                    }
                }
            }
            // Symlinks, FIFOs, sockets and devices are never followed or read.
        }
        if (result.entriesTruncated) {
            break;
        }
    }

    const PeLimits limits{m_config.maxPeReadBytes, m_config.maxVersionResourceBytes,
                          m_config.preferredLanguage != 0 ? m_config.preferredLanguage
                                                          : systemLanguageId()};
    const std::size_t chunk = m_engine.perWorkerFdQuota();
    std::vector<ExeCandidate> candidates;
    for (std::size_t start = 0; start < pending.size() && !timedOut; start += chunk) {
        if (cancelled()) {
            result.cancelled = true;
            return result;
        }
        if (Clock::now() > deadline) {
            timedOut = true;
            break;
        }
        const std::size_t end = std::min(pending.size(), start + chunk);

        std::vector<IoRequest> statReqs;
        for (std::size_t i = start; i < end; ++i) {
            IoRequest r;
            r.op = IoOp::Statx;
            r.dirFd = installFd.get();
            r.path = pending[i].rel;
            r.token = token;
            statReqs.push_back(std::move(r));
        }
        std::vector<IoResult> stats = m_engine.runBatch(std::move(statReqs));

        std::vector<ExeCandidate> chunkCandidates;
        std::vector<std::size_t> needParse;
        for (std::size_t i = start; i < end; ++i) {
            const IoResult &st = stats[i - start];
            if (st.res < 0 || !S_ISREG(st.stx.stx_mode)) {
                continue;
            }
            ExeCandidate c;
            c.relPath = pending[i].rel;
            c.depth = pending[i].depth;
            c.size = st.stx.stx_size;
            c.mtimeNs = toNs(st.stx.stx_mtime);
            c.ino = st.stx.stx_ino;
            const auto prev = previous.find(c.relPath);
            if (prev != previous.end() && prev->second.size == c.size &&
                prev->second.mtimeNs == c.mtimeNs && prev->second.ino == c.ino) {
                c.pe = prev->second.pe;
                c.reusedMetadata = true;
            } else {
                needParse.push_back(chunkCandidates.size());
            }
            chunkCandidates.push_back(std::move(c));
        }

        std::vector<IoRequest> openReqs;
        for (std::size_t idx : needParse) {
            IoRequest r;
            r.op = IoOp::Open;
            r.dirFd = installFd.get();
            r.path = chunkCandidates[idx].relPath;
            r.token = token;
            openReqs.push_back(std::move(r));
        }
        std::vector<IoResult> opens = m_engine.runBatch(std::move(openReqs));

        std::vector<int> fds(needParse.size(), -1);
        std::vector<IoRequest> headReqs;
        std::vector<std::size_t> headOwners;
        for (std::size_t k = 0; k < needParse.size(); ++k) {
            ExeCandidate &c = chunkCandidates[needParse[k]];
            if (opens[k].res < 0) {
                c.pe.validPe = false;
                c.pe.parseError = opens[k].res == -EACCES ? "PERMISSION_DENIED"
                    : (opens[k].res == -ELOOP || opens[k].res == -EXDEV) ? "UNSAFE_PATH"
                                                                         : "OPEN_FAILED";
                continue;
            }
            fds[k] = opens[k].res;
            struct stat st {};
            // TOCTOU guard: the opened file must be the one statx saw.
            if (::fstat(fds[k], &st) != 0 || !S_ISREG(st.st_mode) || st.st_ino != c.ino) {
                c.pe.validPe = false;
                c.pe.parseError = "CHANGED_DURING_SCAN";
                continue;
            }
            IoRequest r;
            r.op = IoOp::Read;
            r.fd = fds[k];
            r.length = static_cast<std::uint32_t>(std::min<std::uint64_t>(c.size, kPeHeadBytes));
            r.token = token;
            headReqs.push_back(std::move(r));
            headOwners.push_back(k);
        }
        std::vector<IoResult> heads = m_engine.runBatch(std::move(headReqs));
        for (std::size_t h = 0; h < headOwners.size(); ++h) {
            const std::size_t k = headOwners[h];
            ExeCandidate &c = chunkCandidates[needParse[k]];
            if (heads[h].res < 0) {
                c.pe.validPe = false;
                c.pe.parseError = heads[h].timedOut ? "IO_TIMEOUT" : "IO_ERROR";
                continue;
            }
            EngineByteSource source(m_engine, fds[k], token);
            PeParseStats parseStats;
            c.pe = parsePe(source, c.size, limits, heads[h].data, &parseStats);
            result.peBytesRead += parseStats.bytesRequested + heads[h].data.size();
        }
        std::vector<IoRequest> closeReqs;
        for (int fd : fds) {
            if (fd >= 0) {
                IoRequest r;
                r.op = IoOp::Close;
                r.fd = fd;
                closeReqs.push_back(std::move(r));
            }
        }
        m_engine.runBatch(std::move(closeReqs));

        for (ExeCandidate &c : chunkCandidates) {
            if (!c.pe.parseError.empty() && !c.reusedMetadata) {
                countPeFailure(c.pe.parseError);
            }
            if (!c.pe.validPe) {
                continue; // not a PE: never a candidate
            }
            candidates.push_back(std::move(c));
        }
    }

    if (cancelled()) {
        result.cancelled = true;
        return result;
    }

    const auto &rules = rulesetV2();
    ScoreContext context{gameName, &rules};
    for (ExeCandidate &c : candidates) {
        c.excludedBy = hardExclusion(rules, c.relPath, c.pe);
        scoreCandidate(context, c);
    }
    const Decision decision =
        decideMainExecutable(candidates, m_config.minScore, m_config.ambiguityMargin);
    result.candidates = std::move(candidates);
    result.state = decision.state;
    result.reason = decision.reason;
    result.mainCandidate = decision.main;
    if (!steam && decision.state == GameState::Error && decision.reason == "NO_EXECUTABLE") {
        result.notAGame = true;
    }
    if (timedOut) {
        result.state = GameState::Error;
        result.reason = "TIMEOUT";
        result.mainCandidate.reset();
    }

    // Display name fallback chain (§7.3); user override is applied by the store.
    result.displayName.clear();
    if (steam && install.steam && !install.steam->name.empty()) {
        result.displayName = install.steam->name;
        result.displayNameSource = "steam_acf";
    }
    if (result.displayName.empty() && result.mainCandidate) {
        const PeMetadata &pe = result.candidates[*result.mainCandidate].pe;
        if (!pe.productName.empty() && !isGenericDisplayName(pe.productName)) {
            result.displayName = pe.productName;
            result.displayNameSource = "product_name";
        } else if (!pe.fileDescription.empty() && !isGenericDisplayName(pe.fileDescription)) {
            result.displayName = pe.fileDescription;
            result.displayNameSource = "file_description";
        }
    }
    if (result.displayName.empty() && !dirName.empty() && !isGenericDisplayName(dirName)) {
        result.displayName = readableFallbackName(dirName);
        result.displayNameSource = "directory";
    }
    if (result.displayName.empty() && result.mainCandidate) {
        const ExeCandidate &main = result.candidates[*result.mainCandidate];
        std::string stem = !main.pe.originalFilename.empty() ? main.pe.originalFilename
                                                             : sanitizeUtf8(lastComponent(main.relPath));
        if (asciiIEndsWith(stem, ".exe")) {
            stem.resize(stem.size() - 4);
        }
        result.displayName = readableFallbackName(stem);
        result.displayNameSource = "file_name";
    }
    if (result.displayName.empty()) {
        result.displayName = dirName.empty() ? std::string("?") : dirName;
        result.displayNameSource = "directory";
    }

    // Copies/updates in progress keep the install stabilizing (§4.4).
    if (steam && install.steam && !(install.steam->stateFlags & kSteamStateFullyInstalled)) {
        result.state = GameState::Stabilizing;
        result.reason = "STEAM_UPDATING";
    } else if (result.tempMarkers && result.state != GameState::Error) {
        result.state = GameState::Stabilizing;
        result.reason = "COPY_IN_PROGRESS";
    }
    return result;
}

} // namespace threesixty::daemon::library
