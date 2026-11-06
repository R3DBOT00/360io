#pragma once

// Display-string sanitization (§8.4). Raw filesystem names are kept as bytes
// for path operations; the strings produced here are only for display, logs
// and API payloads and are never turned back into paths.

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace threesixty::daemon::library {

inline constexpr std::size_t kMaxDisplayChars = 256;

// Strict UTF-8 decode (overlongs, surrogates and > U+10FFFF become U+FFFD),
// strip C0/C1 controls, bidi overrides/isolates, zero-width marks and BOM,
// NFC-normalize, collapse whitespace and cut to maxChars code points.
std::string sanitizeUtf8(std::string_view raw, std::size_t maxChars = kMaxDisplayChars);

// Same pipeline for UTF-16LE input (PE resources); unpaired surrogates become
// U+FFFD. Stops at the first NUL code unit.
std::string sanitizeUtf16Le(const std::uint8_t *data, std::size_t bytes,
                            std::size_t maxChars = kMaxDisplayChars);

// Sanitized form of a raw relative path for logs/API ("a/b/c").
inline std::string sanitizeRelPath(std::string_view raw) { return sanitizeUtf8(raw, 1024); }

// Values such as "Unity", "UE4 Game" or "Launcher" that must not become a
// display name (§7.3).
bool isGenericDisplayName(std::string_view sanitized);

// Readable fallback for names taken from a directory or file name:
// "Hollow_Knight" -> "Hollow Knight", "The.Long.Dark" -> "The Long Dark",
// "SpaceGame-Win64-Shipping" -> "Space Game". Input must be sanitized.
std::string readableFallbackName(std::string_view sanitized);

std::string asciiLower(std::string_view text);
bool asciiIEquals(std::string_view a, std::string_view b);
bool asciiIEndsWith(std::string_view text, std::string_view suffix);

// ASCII case-insensitive glob with '*' and '?' only.
bool globMatchCaseInsensitive(std::string_view pattern, std::string_view text);

} // namespace threesixty::daemon::library
