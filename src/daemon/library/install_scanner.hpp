#pragma once

// Discovery of installs under the root and scanning of a single install
// (walk -> statx -> openat2 -> read -> PE/ACF parsers -> score), §4.1, §5, §7.

#include "io_engine.hpp"
#include "library_store.hpp"
#include "library_types.hpp"
#include "safe_fs.hpp"

#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace threesixty::daemon::library {

struct DiscoveredInstall {
    InstallKey key;
    DirIdentity identity;
    std::optional<SteamInfo> steam;
    std::string manifestError; // set => install is ERROR(INVALID_MANIFEST)
    bool installDirMissing = false;
};

struct DiscoveryResult {
    int error = 0; // -errno when the root could not be listed
    std::vector<DiscoveredInstall> installs;
    std::vector<std::string> steamLibraries; // raw rel paths ("" = root)
    bool truncated = false;
};

struct InstallSnapshot {
    bool exists = false;
    std::uint64_t files = 0;
    std::uint64_t totalSize = 0;
    std::int64_t maxMtimeNs = 0;
    std::int64_t maxCtimeNs = 0;
    bool tempMarkers = false;
    bool truncated = false;
    bool operator==(const InstallSnapshot &) const = default;
};

bool isTempMarkerName(std::string_view name);

class InstallScanner
{
public:
    InstallScanner(const LibraryConfig &config, IoEngine &engine, const SafeOpener &opener);

    DiscoveryResult discover(int rootFd, const CancelToken &token);
    // Re-resolves one key (after events). nullopt when it no longer exists.
    std::optional<DiscoveredInstall> discoverOne(int rootFd, const InstallKey &key);

    InstallScanResult scan(int rootFd, const DiscoveredInstall &install, std::uint64_t generation,
                           const std::map<std::string, PreviousCandidate> &previous,
                           const CancelToken &token);

    InstallSnapshot snapshot(int rootFd, const InstallKey &key);

    std::map<std::string, std::uint64_t> peFailures() const;
    std::map<std::string, std::uint64_t> acfFailures() const;

private:
    void processLibrary(int rootFd, const std::string &library, DiscoveryResult &out);
    std::optional<DiscoveredInstall> readManifest(int rootFd, const std::string &library,
                                                  const std::string &manifestName,
                                                  std::uint32_t appId);
    int readSmallFile(int dirFd, const std::string &rel, std::uint32_t maxBytes,
                      std::vector<std::uint8_t> &out);
    void countPeFailure(const std::string &reason);
    void countAcfFailure(const std::string &reason);

    const LibraryConfig &m_config;
    IoEngine &m_engine;
    const SafeOpener &m_opener;
    mutable std::mutex m_countersMutex;
    std::map<std::string, std::uint64_t> m_peFailures;
    std::map<std::string, std::uint64_t> m_acfFailures;
};

} // namespace threesixty::daemon::library
