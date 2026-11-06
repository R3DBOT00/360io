#include "sanitize.hpp"

#include <cstring>

#include <QList>
#include <QString>

#include <array>
#include <vector>

namespace threesixty::daemon::library {

namespace {

constexpr char32_t kReplacement = 0xFFFD;

bool isStrippedCodePoint(char32_t cp)
{
    if (cp < 0x20 && cp != U'\t' && cp != U'\n' && cp != U'\r') {
        return true; // C0 (whitespace controls are collapsed later instead)
    }
    if (cp == 0x7F || (cp >= 0x80 && cp <= 0x9F)) {
        return true; // DEL + C1
    }
    if (cp >= 0x202A && cp <= 0x202E) {
        return true; // bidi embeddings/overrides
    }
    if (cp >= 0x2066 && cp <= 0x2069) {
        return true; // bidi isolates
    }
    if (cp >= 0x200B && cp <= 0x200F) {
        return true; // zero-width + LRM/RLM
    }
    return cp == 0xFEFF;
}

std::u32string decodeUtf8Strict(std::string_view raw)
{
    std::u32string out;
    out.reserve(raw.size());
    const auto *bytes = reinterpret_cast<const unsigned char *>(raw.data());
    const std::size_t size = raw.size();
    std::size_t i = 0;
    while (i < size) {
        const unsigned char lead = bytes[i];
        if (lead < 0x80) {
            out.push_back(lead);
            ++i;
            continue;
        }
        int extra = 0;
        char32_t cp = 0;
        char32_t minimum = 0;
        if (lead >= 0xC2 && lead <= 0xDF) {
            extra = 1;
            cp = lead & 0x1F;
            minimum = 0x80;
        } else if (lead >= 0xE0 && lead <= 0xEF) {
            extra = 2;
            cp = lead & 0x0F;
            minimum = 0x800;
        } else if (lead >= 0xF0 && lead <= 0xF4) {
            extra = 3;
            cp = lead & 0x07;
            minimum = 0x10000;
        } else {
            out.push_back(kReplacement);
            ++i;
            continue;
        }
        int consumed = 1;
        bool valid = true;
        for (int k = 1; k <= extra; ++k) {
            if (i + static_cast<std::size_t>(k) >= size) {
                valid = false;
                break;
            }
            const unsigned char cont = bytes[i + static_cast<std::size_t>(k)];
            if ((cont & 0xC0) != 0x80) {
                valid = false;
                break;
            }
            cp = (cp << 6) | (cont & 0x3F);
            ++consumed;
        }
        if (!valid || cp < minimum || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
            out.push_back(kReplacement);
            i += static_cast<std::size_t>(consumed);
            continue;
        }
        out.push_back(cp);
        i += static_cast<std::size_t>(consumed);
    }
    return out;
}

std::string finish(const std::u32string &decoded, std::size_t maxChars)
{
    std::u32string filtered;
    filtered.reserve(decoded.size());
    for (char32_t cp : decoded) {
        if (!isStrippedCodePoint(cp)) {
            filtered.push_back(cp);
        }
    }
    const QString normalized =
        QString::fromUcs4(filtered.data(), static_cast<qsizetype>(filtered.size()))
            .normalized(QString::NormalizationForm_C);
    const QList<uint> ucs4 = normalized.toUcs4();

    std::u32string collapsed;
    collapsed.reserve(static_cast<std::size_t>(ucs4.size()));
    bool pendingSpace = false;
    for (uint value : ucs4) {
        const char32_t cp = value;
        if (QChar::isSpace(cp)) {
            pendingSpace = !collapsed.empty();
            continue;
        }
        if (pendingSpace) {
            if (collapsed.size() >= maxChars) {
                break;
            }
            collapsed.push_back(U' ');
            pendingSpace = false;
        }
        if (collapsed.size() >= maxChars) {
            break;
        }
        collapsed.push_back(cp);
    }
    return QString::fromUcs4(collapsed.data(), static_cast<qsizetype>(collapsed.size()))
        .toStdString();
}

} // namespace

std::string sanitizeUtf8(std::string_view raw, std::size_t maxChars)
{
    return finish(decodeUtf8Strict(raw), maxChars);
}

std::string sanitizeUtf16Le(const std::uint8_t *data, std::size_t bytes, std::size_t maxChars)
{
    std::u32string decoded;
    const std::size_t units = bytes / 2;
    decoded.reserve(units);
    for (std::size_t i = 0; i < units; ++i) {
        const char16_t unit = static_cast<char16_t>(data[2 * i] | (data[2 * i + 1] << 8));
        if (unit == 0) {
            break;
        }
        if (unit >= 0xD800 && unit <= 0xDBFF) {
            if (i + 1 < units) {
                const char16_t low =
                    static_cast<char16_t>(data[2 * i + 2] | (data[2 * i + 3] << 8));
                if (low >= 0xDC00 && low <= 0xDFFF) {
                    decoded.push_back(0x10000 + ((char32_t(unit) - 0xD800) << 10) +
                                      (char32_t(low) - 0xDC00));
                    ++i;
                    continue;
                }
            }
            decoded.push_back(kReplacement);
            continue;
        }
        if (unit >= 0xDC00 && unit <= 0xDFFF) {
            decoded.push_back(kReplacement);
            continue;
        }
        decoded.push_back(unit);
    }
    return finish(decoded, maxChars);
}

std::string readableFallbackName(std::string_view sanitized)
{
    std::string name(sanitized);
    for (const char *suffix : {"-Win64-Shipping", "-Win32-Shipping", "-WinGDK-Shipping", "_x64", "_x86",
                               "-x64", "-x86"}) {
        if (name.size() > std::strlen(suffix) && asciiIEndsWith(name, suffix)) {
            name.resize(name.size() - std::strlen(suffix));
            break;
        }
    }
    const bool hadSpace = name.find(' ') != std::string::npos;
    std::string spaced;
    for (char c : name) {
        spaced.push_back(c == '_' || (c == '.' && !hadSpace) ? ' ' : c);
    }
    // camelCase split only for single-token names ("HollowKnight").
    std::string out;
    const bool singleToken = spaced.find(' ') == std::string::npos;
    char previous = 0;
    for (char c : spaced) {
        const bool upper = c >= 'A' && c <= 'Z';
        const bool prevLower = previous >= 'a' && previous <= 'z';
        if (singleToken && upper && prevLower) {
            out.push_back(' ');
        }
        if (c == ' ' && (out.empty() || out.back() == ' ')) {
            previous = c;
            continue;
        }
        out.push_back(c);
        previous = c;
    }
    while (!out.empty() && out.back() == ' ') {
        out.pop_back();
    }
    return out.empty() ? std::string(sanitized) : out;
}

bool isGenericDisplayName(std::string_view sanitized)
{
    static constexpr std::array<std::string_view, 9> kGeneric = {
        "unity", "ue4 game", "ue5 game", "ue4", "game", "launcher",
        "unreal engine", "application", "setup",
    };
    const std::string lower = asciiLower(sanitized);
    for (std::string_view generic : kGeneric) {
        if (lower == generic) {
            return true;
        }
    }
    return false;
}

std::string asciiLower(std::string_view text)
{
    std::string out(text);
    for (char &c : out) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return out;
}

bool asciiIEquals(std::string_view a, std::string_view b)
{
    return a.size() == b.size() && asciiLower(a) == asciiLower(b);
}

bool asciiIEndsWith(std::string_view text, std::string_view suffix)
{
    return text.size() >= suffix.size() &&
        asciiIEquals(text.substr(text.size() - suffix.size()), suffix);
}

bool globMatchCaseInsensitive(std::string_view pattern, std::string_view text)
{
    const std::string p = asciiLower(pattern);
    const std::string t = asciiLower(text);
    std::size_t pi = 0;
    std::size_t ti = 0;
    std::size_t starP = std::string::npos;
    std::size_t starT = 0;
    while (ti < t.size()) {
        if (pi < p.size() && (p[pi] == '?' || p[pi] == t[ti])) {
            ++pi;
            ++ti;
        } else if (pi < p.size() && p[pi] == '*') {
            starP = pi++;
            starT = ti;
        } else if (starP != std::string::npos) {
            pi = starP + 1;
            ti = ++starT;
        } else {
            return false;
        }
    }
    while (pi < p.size() && p[pi] == '*') {
        ++pi;
    }
    return pi == p.size();
}

} // namespace threesixty::daemon::library
