#pragma once

// Executable filter ruleset v2 (§7.2) and main-executable scorer (§7.5).

#include "library_types.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace threesixty::daemon::library {

enum class RuleKind { FilenameGlob, PathSegmentGlob, PeFieldMatch };
enum class RuleAction { Exclude, Penalize, Boost };

struct ExeRule {
    std::string id;
    RuleKind kind;
    std::string pattern;
    RuleAction action;
    int weight = 0;
};

const std::vector<ExeRule> &rulesetV2();

// ".exe" by ASCII case-insensitive comparison on the raw file name.
bool hasExeExtension(std::string_view fileName);

// Returns the id of the first hard-exclusion rule matching, or "" if none.
// DLLs are excluded with id "pe-dll".
std::string hardExclusion(const std::vector<ExeRule> &rules, std::string_view relPath,
                          const PeMetadata &pe);

struct ScoreContext {
    std::string gameName;       // ACF name or install directory name (sanitized)
    const std::vector<ExeRule> *rules = nullptr;
};

// Fills candidate.score and candidate.featuresJson (deterministic).
void scoreCandidate(const ScoreContext &context, ExeCandidate &candidate);

// Lower-case alphanumeric tokens with camelCase/digit splitting and stop
// words ("exe", "win64", "shipping", ...) removed.
std::vector<std::string> nameTokens(std::string_view text);
double jaccard(const std::vector<std::string> &a, const std::vector<std::string> &b);

struct Decision {
    GameState state = GameState::Error;
    std::string reason;
    std::optional<std::size_t> main;
};

// candidates must already be scored; excluded ones are ignored. Sorts the
// vector (non-excluded first, score desc, rel_path asc).
Decision decideMainExecutable(std::vector<ExeCandidate> &candidates, int minScore,
                              int ambiguityMargin);

} // namespace threesixty::daemon::library
