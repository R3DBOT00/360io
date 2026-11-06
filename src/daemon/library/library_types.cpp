#include "library_types.hpp"

#include <array>

namespace threesixty::daemon::library {

namespace {

constexpr std::array<std::pair<GameState, std::string_view>, 7> kStates = {{
    {GameState::Discovered, "DISCOVERED"},
    {GameState::Stabilizing, "STABILIZING"},
    {GameState::Scanning, "SCANNING"},
    {GameState::Ready, "READY"},
    {GameState::Ambiguous, "AMBIGUOUS"},
    {GameState::Error, "ERROR"},
    {GameState::Removed, "REMOVED"},
}};

} // namespace

const char *gameStateName(GameState state)
{
    for (const auto &[value, name] : kStates) {
        if (value == state) {
            return name.data();
        }
    }
    return "ERROR";
}

std::optional<GameState> gameStateFromName(std::string_view name)
{
    for (const auto &[value, known] : kStates) {
        if (known == name) {
            return value;
        }
    }
    return std::nullopt;
}

const char *installKindName(InstallKind kind)
{
    return kind == InstallKind::Steam ? "steam" : "directory";
}

const char *watchCoverageName(WatchCoverage coverage)
{
    switch (coverage) {
    case WatchCoverage::Full:
        return "FULL";
    case WatchCoverage::Partial:
        return "PARTIAL";
    case WatchCoverage::None:
        return "NONE";
    }
    return "NONE";
}

std::string InstallKey::mapKey() const
{
    if (kind == InstallKind::Steam) {
        return "steam:" + libraryRelPath + ":" + std::to_string(steamAppId);
    }
    return "dir:" + relPath;
}

std::int64_t unixMillisNow()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

} // namespace threesixty::daemon::library
