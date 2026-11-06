#pragma once

// Bounded, tolerant parser for Steam appmanifest_*.acf (text VDF), §7.1.

#include "library_types.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace threesixty::daemon::library {

struct VdfLimits {
    unsigned maxDepth = 16;
    std::size_t maxTokenBytes = 4096;
    std::size_t maxPairs = 4096;
};

struct VdfNode {
    std::string key;
    std::string value; // raw bytes, valid only when !isObject
    bool isObject = false;
    std::vector<VdfNode> children;

    // Case-insensitive lookup; duplicate keys: the first one wins.
    const VdfNode *child(std::string_view name) const;
};

struct VdfResult {
    bool ok = false;
    std::string error; // UNBALANCED, UNTERMINATED_STRING, LIMIT_DEPTH, LIMIT_TOKEN, LIMIT_PAIRS, EMPTY, MULTIPLE_ROOTS
    VdfNode root;
};

VdfResult parseVdf(std::string_view text, const VdfLimits &limits = {});

struct SteamManifestResult {
    bool ok = false;
    std::string error; // VDF errors + NO_APPSTATE, BAD_APPID, APPID_MISMATCH, INVALID_INSTALLDIR
    SteamInfo info;
};

// expectedAppId comes from the file name appmanifest_<digits>.acf.
SteamManifestResult parseSteamManifest(std::string_view text, std::uint32_t expectedAppId,
                                       const VdfLimits &limits = {});

// Returns the app id if name is exactly appmanifest_<digits>.acf (case-sensitive).
std::optional<std::uint32_t> appIdFromManifestName(std::string_view name);

// installdir must be one path component: no '/', '\\', NUL, "." or "..".
bool isSafeSingleComponent(std::string_view component);

inline constexpr std::uint32_t kSteamStateFullyInstalled = 4;

} // namespace threesixty::daemon::library
