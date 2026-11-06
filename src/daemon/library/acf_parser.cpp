#include "acf_parser.hpp"

#include "sanitize.hpp"

#include <charconv>

namespace threesixty::daemon::library {

namespace {

enum class TokenKind { End, Open, Close, String };

struct Token {
    TokenKind kind = TokenKind::End;
    std::string text;
};

class Tokenizer
{
public:
    Tokenizer(std::string_view text, const VdfLimits &limits)
        : m_text(text)
        , m_limits(limits)
    {
        if (m_text.substr(0, 3) == "\xEF\xBB\xBF") {
            m_pos = 3;
        }
    }

    // Returns false and sets error on a fatal lexical problem.
    bool next(Token &token, std::string &error)
    {
        skipTrivia();
        token.text.clear();
        if (m_pos >= m_text.size()) {
            token.kind = TokenKind::End;
            return true;
        }
        const char c = m_text[m_pos];
        if (c == '{') {
            ++m_pos;
            token.kind = TokenKind::Open;
            return true;
        }
        if (c == '}') {
            ++m_pos;
            token.kind = TokenKind::Close;
            return true;
        }
        token.kind = TokenKind::String;
        if (c == '"') {
            ++m_pos;
            while (true) {
                if (m_pos >= m_text.size()) {
                    error = "UNTERMINATED_STRING";
                    return false;
                }
                char ch = m_text[m_pos++];
                if (ch == '"') {
                    break;
                }
                if (ch == '\\' && m_pos < m_text.size()) {
                    const char esc = m_text[m_pos];
                    if (esc == '"' || esc == '\\') {
                        ch = esc;
                        ++m_pos;
                    } else if (esc == 'n') {
                        ch = '\n';
                        ++m_pos;
                    } else if (esc == 't') {
                        ch = '\t';
                        ++m_pos;
                    }
                }
                if (token.text.size() >= m_limits.maxTokenBytes) {
                    error = "LIMIT_TOKEN";
                    return false;
                }
                token.text.push_back(ch);
            }
            return true;
        }
        while (m_pos < m_text.size()) {
            const char ch = m_text[m_pos];
            if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '{' ||
                ch == '}' || ch == '"') {
                break;
            }
            if (token.text.size() >= m_limits.maxTokenBytes) {
                error = "LIMIT_TOKEN";
                return false;
            }
            token.text.push_back(ch);
            ++m_pos;
        }
        return true;
    }

private:
    void skipTrivia()
    {
        while (m_pos < m_text.size()) {
            const char c = m_text[m_pos];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\0') {
                ++m_pos;
            } else if (c == '/' && m_pos + 1 < m_text.size() && m_text[m_pos + 1] == '/') {
                while (m_pos < m_text.size() && m_text[m_pos] != '\n') {
                    ++m_pos;
                }
            } else if (c == '[' && m_pos + 1 < m_text.size() && m_text[m_pos + 1] == '$') {
                while (m_pos < m_text.size() && m_text[m_pos] != ']' &&
                       m_text[m_pos] != '\n') {
                    ++m_pos;
                }
                if (m_pos < m_text.size() && m_text[m_pos] == ']') {
                    ++m_pos;
                }
            } else {
                break;
            }
        }
    }

    std::string_view m_text;
    const VdfLimits &m_limits;
    std::size_t m_pos = 0;
};

class Parser
{
public:
    Parser(std::string_view text, const VdfLimits &limits)
        : m_tokens(text, limits)
        , m_limits(limits)
    {
    }

    VdfResult run()
    {
        VdfResult result;
        result.root.isObject = true;
        bool haveRoot = false;
        while (true) {
            Token key;
            if (!m_tokens.next(key, result.error)) {
                return result;
            }
            if (key.kind == TokenKind::End) {
                break;
            }
            if (key.kind != TokenKind::String) {
                result.error = "UNBALANCED";
                return result;
            }
            if (haveRoot) {
                result.error = "MULTIPLE_ROOTS";
                return result;
            }
            Token open;
            if (!m_tokens.next(open, result.error)) {
                return result;
            }
            if (open.kind != TokenKind::Open) {
                result.error = "UNBALANCED";
                return result;
            }
            VdfNode node;
            node.key = std::move(key.text);
            node.isObject = true;
            if (!parseObject(node, 1, result.error)) {
                return result;
            }
            result.root.children.push_back(std::move(node));
            haveRoot = true;
        }
        if (!haveRoot) {
            result.error = "EMPTY";
            return result;
        }
        result.ok = true;
        return result;
    }

private:
    bool parseObject(VdfNode &object, unsigned depth, std::string &error)
    {
        if (depth > m_limits.maxDepth) {
            error = "LIMIT_DEPTH";
            return false;
        }
        while (true) {
            Token key;
            if (!m_tokens.next(key, error)) {
                return false;
            }
            if (key.kind == TokenKind::Close) {
                return true;
            }
            if (key.kind != TokenKind::String) {
                error = "UNBALANCED";
                return false;
            }
            if (++m_pairs > m_limits.maxPairs) {
                error = "LIMIT_PAIRS";
                return false;
            }
            Token value;
            if (!m_tokens.next(value, error)) {
                return false;
            }
            VdfNode child;
            child.key = std::move(key.text);
            if (value.kind == TokenKind::Open) {
                child.isObject = true;
                if (!parseObject(child, depth + 1, error)) {
                    return false;
                }
            } else if (value.kind == TokenKind::String) {
                child.value = std::move(value.text);
            } else {
                error = "UNBALANCED";
                return false;
            }
            object.children.push_back(std::move(child));
        }
    }

    Tokenizer m_tokens;
    const VdfLimits &m_limits;
    std::size_t m_pairs = 0;
};

template <typename T>
bool parseUnsigned(std::string_view text, T &out)
{
    if (text.empty()) {
        return false;
    }
    const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), out);
    return ec == std::errc() && ptr == text.data() + text.size();
}

} // namespace

const VdfNode *VdfNode::child(std::string_view name) const
{
    for (const VdfNode &node : children) {
        if (asciiIEquals(node.key, name)) {
            return &node;
        }
    }
    return nullptr;
}

VdfResult parseVdf(std::string_view text, const VdfLimits &limits)
{
    return Parser(text, limits).run();
}

bool isSafeSingleComponent(std::string_view component)
{
    if (component.empty() || component == "." || component == "..") {
        return false;
    }
    for (char c : component) {
        if (c == '/' || c == '\\' || c == '\0') {
            return false;
        }
    }
    return component.size() <= 255;
}

std::optional<std::uint32_t> appIdFromManifestName(std::string_view name)
{
    constexpr std::string_view kPrefix = "appmanifest_";
    constexpr std::string_view kSuffix = ".acf";
    if (name.size() <= kPrefix.size() + kSuffix.size() || name.substr(0, kPrefix.size()) != kPrefix ||
        name.substr(name.size() - kSuffix.size()) != kSuffix) {
        return std::nullopt;
    }
    const std::string_view digits =
        name.substr(kPrefix.size(), name.size() - kPrefix.size() - kSuffix.size());
    for (char c : digits) {
        if (c < '0' || c > '9') {
            return std::nullopt;
        }
    }
    std::uint32_t appId = 0;
    if (!parseUnsigned(digits, appId) || appId == 0) {
        return std::nullopt;
    }
    return appId;
}

SteamManifestResult parseSteamManifest(std::string_view text, std::uint32_t expectedAppId,
                                       const VdfLimits &limits)
{
    SteamManifestResult result;
    const VdfResult vdf = parseVdf(text, limits);
    if (!vdf.ok) {
        result.error = vdf.error;
        return result;
    }
    const VdfNode *appState = vdf.root.child("AppState");
    if (appState == nullptr || !appState->isObject) {
        result.error = "NO_APPSTATE";
        return result;
    }
    auto scalar = [appState](std::string_view key) -> std::string_view {
        const VdfNode *node = appState->child(key);
        return (node != nullptr && !node->isObject) ? std::string_view(node->value)
                                                    : std::string_view();
    };

    std::uint32_t appId = 0;
    if (!parseUnsigned(scalar("appid"), appId) || appId == 0) {
        result.error = "BAD_APPID";
        return result;
    }
    if (expectedAppId != 0 && appId != expectedAppId) {
        result.error = "APPID_MISMATCH";
        return result;
    }
    const std::string_view installDir = scalar("installdir");
    if (!isSafeSingleComponent(installDir)) {
        result.error = "INVALID_INSTALLDIR";
        return result;
    }

    SteamInfo &info = result.info;
    info.appId = appId;
    info.installDir = std::string(installDir);
    info.name = sanitizeUtf8(scalar("name"));
    parseUnsigned(scalar("StateFlags"), info.stateFlags);
    std::uint64_t lastUpdated = 0;
    if (parseUnsigned(scalar("LastUpdated"), lastUpdated) && lastUpdated < (1ull << 62)) {
        info.lastUpdated = static_cast<std::int64_t>(lastUpdated);
    }
    parseUnsigned(scalar("SizeOnDisk"), info.sizeOnDisk);
    info.buildId = sanitizeUtf8(scalar("buildid"), 32);
    result.ok = true;
    return result;
}

} // namespace threesixty::daemon::library
