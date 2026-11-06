#include "exe_rules.hpp"

#include "pe_parser.hpp"
#include "sanitize.hpp"

#include <QJsonDocument>
#include <QJsonObject>

#include <algorithm>
#include <cmath>
#include <set>

namespace threesixty::daemon::library {

namespace {

std::vector<std::string_view> pathSegments(std::string_view relPath)
{
    std::vector<std::string_view> segments;
    std::size_t start = 0;
    while (start <= relPath.size()) {
        const std::size_t slash = relPath.find('/', start);
        const std::size_t end = slash == std::string_view::npos ? relPath.size() : slash;
        if (end > start) {
            segments.push_back(relPath.substr(start, end - start));
        }
        if (slash == std::string_view::npos) {
            break;
        }
        start = slash + 1;
    }
    return segments;
}

std::string_view fileNameOf(std::string_view relPath)
{
    const std::size_t slash = relPath.rfind('/');
    return slash == std::string_view::npos ? relPath : relPath.substr(slash + 1);
}

bool ruleMatches(const ExeRule &rule, std::string_view relPath, const PeMetadata &pe)
{
    switch (rule.kind) {
    case RuleKind::FilenameGlob:
        return globMatchCaseInsensitive(rule.pattern, fileNameOf(relPath));
    case RuleKind::PathSegmentGlob: {
        const auto segments = pathSegments(relPath);
        // Only directory segments; the file name has its own rule kind.
        for (std::size_t i = 0; i + 1 < segments.size(); ++i) {
            if (globMatchCaseInsensitive(rule.pattern, segments[i])) {
                return true;
            }
        }
        return false;
    }
    case RuleKind::PeFieldMatch:
        return globMatchCaseInsensitive(rule.pattern, pe.productName) ||
            globMatchCaseInsensitive(rule.pattern, pe.fileDescription);
    }
    return false;
}

} // namespace

const std::vector<ExeRule> &rulesetV2()
{
    static const std::vector<ExeRule> kRules = [] {
        std::vector<ExeRule> rules = {
            {"exclude-unity-crash-handler", RuleKind::FilenameGlob, "UnityCrashHandler*.exe",
             RuleAction::Exclude, 0},
            {"exclude-uninstaller", RuleKind::FilenameGlob, "unins*.exe", RuleAction::Exclude, 0},
            {"exclude-dxsetup", RuleKind::FilenameGlob, "DXSETUP.exe", RuleAction::Exclude, 0},
            {"exclude-vcredist", RuleKind::FilenameGlob, "vcredist*.exe", RuleAction::Exclude, 0},
        };
        // v2: runtime installers and engine helpers that ship next to games
        // but are never the game itself.
        static const std::pair<const char *, const char *> kRedistNames[] = {
            {"vc-redist", "vc_redist*.exe"},
            {"dxwebsetup", "dxwebsetup.exe"},
            {"dotnetfx", "dotNetFx*.exe"},
            {"ndp", "NDP4*.exe"},
            {"dotnet-runtime", "*dotnet*-runtime-*.exe"},
            {"windowsdesktop-runtime", "windowsdesktop-runtime-*.exe"},
            {"xnafx", "xnafx*.exe"},
            {"openal", "oalinst.exe"},
            {"physx", "PhysX*.exe"},
            {"ue-prereq", "UE*PrereqSetup*.exe"},
            {"ue-crash-report", "CrashReportClient*.exe"},
            {"eac-setup", "EasyAntiCheat*Setup*.exe"},
            {"battleye-service", "BEService*.exe"},
        };
        for (const auto &[id, pattern] : kRedistNames) {
            rules.push_back({std::string("exclude-") + id, RuleKind::FilenameGlob, pattern,
                             RuleAction::Exclude, 0});
        }
        for (const char *segment : {"_CommonRedist", "CommonRedist", "Redist", "_Redist",
                                    "Redistributable*", "__Installer", "Prerequisites", "vcredist*"}) {
            rules.push_back({std::string("exclude-segment-") + asciiLower(segment),
                             RuleKind::PathSegmentGlob, segment, RuleAction::Exclude, 0});
        }
        for (const char *segment : {"DirectX", "Support", "Installer*", "Prereq*"}) {
            rules.push_back({std::string("penalize-segment-") + asciiLower(segment),
                             RuleKind::PathSegmentGlob, segment, RuleAction::Penalize, -30});
        }
        for (const char *word : {"launcher", "setup", "config", "settings", "crash", "report",
                                 "helper", "server", "editor", "benchmark", "install"}) {
            rules.push_back({std::string("penalize-name-") + word, RuleKind::FilenameGlob,
                             std::string("*") + word + "*", RuleAction::Penalize, -15});
        }
        rules.push_back({"boost-win64-shipping", RuleKind::FilenameGlob, "*-Win64-Shipping.exe",
                         RuleAction::Boost, 15});
        return rules;
    }();
    return kRules;
}

bool hasExeExtension(std::string_view fileName)
{
    return fileName.size() > 4 && asciiIEndsWith(fileName, ".exe");
}

std::string hardExclusion(const std::vector<ExeRule> &rules, std::string_view relPath,
                          const PeMetadata &pe)
{
    for (const ExeRule &rule : rules) {
        if (rule.action == RuleAction::Exclude && ruleMatches(rule, relPath, pe)) {
            return rule.id;
        }
    }
    if (pe.validPe && pe.isDll) {
        return "pe-dll";
    }
    return {};
}

std::vector<std::string> nameTokens(std::string_view text)
{
    static const std::set<std::string> kStopWords = {
        "exe", "x64", "x86", "win64", "win32", "shipping", "the", "64", "32", "bin", "binaries",
    };
    std::vector<std::string> tokens;
    auto keep = [&](const std::string &token) {
        const std::string lower = asciiLower(token);
        if (!lower.empty() && !kStopWords.contains(lower)) {
            tokens.push_back(lower);
        }
    };
    // Words split on separators and camelCase; a stop word is checked on the
    // whole word ("Win64") before letters and digits are split ("Game2").
    auto flushWord = [&](std::string &word) {
        if (word.empty()) {
            return;
        }
        if (!kStopWords.contains(asciiLower(word))) {
            std::string part;
            bool partDigit = false;
            for (char c : word) {
                const bool digit = c >= '0' && c <= '9';
                if (!part.empty() && digit != partDigit) {
                    keep(part);
                    part.clear();
                }
                part.push_back(c);
                partDigit = digit;
            }
            keep(part);
        }
        word.clear();
    };
    std::string word;
    char previous = 0;
    for (char c : text) {
        const bool upper = c >= 'A' && c <= 'Z';
        const bool lower = c >= 'a' && c <= 'z';
        const bool digit = c >= '0' && c <= '9';
        const bool nonAscii = (static_cast<unsigned char>(c) & 0x80) != 0;
        if (!(upper || lower || digit || nonAscii)) {
            flushWord(word);
            previous = 0;
            continue;
        }
        const bool prevLower = previous >= 'a' && previous <= 'z';
        const bool prevDigit = previous >= '0' && previous <= '9';
        if ((upper && prevLower) || (upper && prevDigit)) {
            flushWord(word);
        }
        word.push_back(c);
        previous = c;
    }
    flushWord(word);
    std::sort(tokens.begin(), tokens.end());
    tokens.erase(std::unique(tokens.begin(), tokens.end()), tokens.end());
    return tokens;
}

double jaccard(const std::vector<std::string> &a, const std::vector<std::string> &b)
{
    if (a.empty() || b.empty()) {
        return 0.0;
    }
    std::vector<std::string> common;
    std::set_intersection(a.begin(), a.end(), b.begin(), b.end(), std::back_inserter(common));
    const double unionSize = double(a.size() + b.size() - common.size());
    return unionSize > 0 ? double(common.size()) / unionSize : 0.0;
}

void scoreCandidate(const ScoreContext &context, ExeCandidate &candidate)
{
    const std::string_view fileName = fileNameOf(candidate.relPath);
    const std::string stem = sanitizeUtf8(fileName.substr(0, fileName.size() - 4));
    const auto stemTokens = nameTokens(stem);

    QJsonObject features;
    int score = 0;

    const int nameSimilarity =
        int(std::lround(40.0 * jaccard(stemTokens, nameTokens(context.gameName))));
    score += nameSimilarity;
    features.insert(QStringLiteral("name_similarity"), nameSimilarity);

    int productSimilarity = 0;
    if (!candidate.pe.productName.empty()) {
        productSimilarity = int(std::lround(
            20.0 * jaccard(nameTokens(candidate.pe.productName), nameTokens(context.gameName))));
    }
    score += productSimilarity;
    features.insert(QStringLiteral("product_similarity"), productSimilarity);

    const int gui = candidate.pe.subsystem == kSubsystemWindowsGui ? 10 : 0;
    score += gui;
    features.insert(QStringLiteral("gui_subsystem"), gui);

    int arch = 0;
    switch (candidate.pe.machine) {
    case kMachineAmd64:
        arch = 8;
        break;
    case kMachineI386:
        arch = 4;
        break;
    case kMachineArm64:
        arch = 2;
        break;
    default:
        break;
    }
    score += arch;
    features.insert(QStringLiteral("arch"), arch);

    const std::string lowerPath = asciiLower(candidate.relPath);
    const int binariesWin64 = lowerPath.find("binaries/win64/") != std::string::npos ? 15 : 0;

    const int depth = 10 - 3 * int(candidate.depth);
    score += depth;
    features.insert(QStringLiteral("depth"), depth);

    const double mib = double(candidate.size) / (1024.0 * 1024.0);
    const int sizeScore =
        mib < 1.0 ? 0 : int(std::lround(std::log2(std::min(mib, 256.0))));
    score += sizeScore;
    features.insert(QStringLiteral("size"), sizeScore);

    int penalties = 0;
    int boosts = binariesWin64;
    QJsonObject matched;
    if (context.rules != nullptr) {
        for (const ExeRule &rule : *context.rules) {
            if (rule.action == RuleAction::Exclude || !ruleMatches(rule, candidate.relPath, candidate.pe)) {
                continue;
            }
            if (rule.action == RuleAction::Penalize) {
                penalties += rule.weight;
            } else if (rule.id != "boost-win64-shipping" || binariesWin64 == 0) {
                boosts += rule.weight; // Shipping name and Binaries/Win64 share one +15
            }
            matched.insert(QString::fromStdString(rule.id), rule.weight);
        }
    }
    score += penalties + boosts;
    features.insert(QStringLiteral("win64_shipping"), boosts);
    features.insert(QStringLiteral("penalties"), penalties);
    if (!matched.isEmpty()) {
        features.insert(QStringLiteral("rules"), matched);
    }
    features.insert(QStringLiteral("ruleset_version"), kRulesetVersion);
    features.insert(QStringLiteral("scorer_version"), kScorerVersion);

    candidate.score = score;
    candidate.featuresJson =
        QJsonDocument(features).toJson(QJsonDocument::Compact).toStdString();
}

Decision decideMainExecutable(std::vector<ExeCandidate> &candidates, int minScore,
                              int ambiguityMargin)
{
    std::stable_sort(candidates.begin(), candidates.end(),
                     [](const ExeCandidate &a, const ExeCandidate &b) {
                         const bool ea = !a.excludedBy.empty();
                         const bool eb = !b.excludedBy.empty();
                         if (ea != eb) {
                             return !ea;
                         }
                         if (a.score != b.score) {
                             return a.score > b.score;
                         }
                         return a.relPath < b.relPath;
                     });
    std::size_t eligible = 0;
    while (eligible < candidates.size() && candidates[eligible].excludedBy.empty()) {
        ++eligible;
    }
    Decision decision;
    if (eligible == 0) {
        decision.state = GameState::Error;
        decision.reason = "NO_EXECUTABLE";
        return decision;
    }
    if (eligible == 1) {
        // One eligible executable: there is nothing to disambiguate, but a
        // low score is surfaced instead of being hidden.
        decision.state = GameState::Ready;
        decision.main = 0;
        decision.reason = candidates[0].score >= minScore ? "" : "LOW_CONFIDENCE";
        return decision;
    }
    const int top1 = candidates[0].score;
    const int top2 = candidates[1].score;
    if (top1 >= minScore && top1 - top2 >= ambiguityMargin) {
        decision.state = GameState::Ready;
        decision.main = 0;
        return decision;
    }
    decision.state = GameState::Ambiguous;
    decision.reason = top1 < minScore ? "LOW_SCORE" : "CLOSE_SCORES";
    return decision;
}

} // namespace threesixty::daemon::library
