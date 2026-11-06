#pragma once

// Shared helpers for the library scanner tests. Everything happens in
// mkdtemp() directories under $TMPDIR (or /tmp); nothing touches /games.

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <unistd.h>

namespace libtest {

inline int failures = 0;

#define CHECK(cond)                                                                        \
    do {                                                                                   \
        if (!(cond)) {                                                                     \
            std::fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
            ++::libtest::failures;                                                         \
        }                                                                                  \
    } while (0)

#define CHECK_EQ(a, b)                                                                     \
    do {                                                                                   \
        const auto &va_ = (a);                                                             \
        const auto &vb_ = (b);                                                             \
        if (!(va_ == vb_)) {                                                               \
            std::fprintf(stderr, "%s:%d: CHECK_EQ failed: %s == %s\n", __FILE__, __LINE__, \
                         #a, #b);                                                          \
            ++::libtest::failures;                                                         \
        }                                                                                  \
    } while (0)

inline void section(const char *name)
{
    std::fprintf(stderr, "-- %s\n", name);
}

inline int finish(const char *suite)
{
    if (failures == 0) {
        std::fprintf(stderr, "PASS %s\n", suite);
        return 0;
    }
    std::fprintf(stderr, "FAIL %s: %d check(s) failed\n", suite, failures);
    return 1;
}

namespace fs = std::filesystem;

class TempDir
{
public:
    explicit TempDir(const char *prefix = "360io-libtest")
    {
        const char *base = std::getenv("TMPDIR");
        std::string templ = std::string(base != nullptr && *base ? base : "/tmp") + "/" + prefix + "-XXXXXX";
        std::vector<char> buffer(templ.begin(), templ.end());
        buffer.push_back('\0');
        if (::mkdtemp(buffer.data()) == nullptr) {
            std::perror("mkdtemp");
            std::abort();
        }
        m_path = buffer.data();
    }
    ~TempDir()
    {
        std::error_code ec;
        fs::remove_all(m_path, ec);
    }
    const std::string &path() const { return m_path; }
    std::string operator/(const std::string &rel) const { return m_path + "/" + rel; }

private:
    std::string m_path;
};

inline void writeFile(const std::string &path, const std::string &content)
{
    fs::create_directories(fs::path(path).parent_path());
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
}

inline void writeBytes(const std::string &path, const std::vector<std::uint8_t> &bytes)
{
    writeFile(path, std::string(bytes.begin(), bytes.end()));
}

inline std::vector<std::uint8_t> readBytes(const std::string &path)
{
    std::ifstream in(path, std::ios::binary);
    return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

inline bool waitFor(const std::function<bool()> &predicate, std::chrono::milliseconds timeout)
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return predicate();
}

// ------------------------------------------------------------------ PE ---

inline void put16(std::vector<std::uint8_t> &b, std::size_t off, std::uint16_t v)
{
    if (b.size() < off + 2) {
        b.resize(off + 2);
    }
    b[off] = std::uint8_t(v);
    b[off + 1] = std::uint8_t(v >> 8);
}

inline void put32(std::vector<std::uint8_t> &b, std::size_t off, std::uint32_t v)
{
    if (b.size() < off + 4) {
        b.resize(off + 4);
    }
    for (int i = 0; i < 4; ++i) {
        b[off + std::size_t(i)] = std::uint8_t(v >> (8 * i));
    }
}

inline void appendUtf16(std::vector<std::uint8_t> &b, const std::u16string &s, bool nul = true)
{
    for (char16_t c : s) {
        b.push_back(std::uint8_t(c));
        b.push_back(std::uint8_t(c >> 8));
    }
    if (nul) {
        b.push_back(0);
        b.push_back(0);
    }
}

inline void pad4(std::vector<std::uint8_t> &b)
{
    while (b.size() % 4 != 0) {
        b.push_back(0);
    }
}

inline std::u16string u16(const std::string &ascii)
{
    return std::u16string(ascii.begin(), ascii.end());
}

// One VS_VERSIONINFO-style block (wLength, wValueLength, wType, szKey, value, children).
inline std::vector<std::uint8_t> versionBlock(const std::u16string &key, const std::vector<std::uint8_t> &value,
                                              bool text, std::uint16_t valueLength,
                                              const std::vector<std::vector<std::uint8_t>> &children)
{
    std::vector<std::uint8_t> b(6, 0);
    appendUtf16(b, key);
    pad4(b);
    b.insert(b.end(), value.begin(), value.end());
    for (const auto &child : children) {
        pad4(b);
        b.insert(b.end(), child.begin(), child.end());
    }
    put16(b, 0, std::uint16_t(b.size()));
    put16(b, 2, valueLength);
    put16(b, 4, text ? 1 : 0);
    return b;
}

inline std::vector<std::uint8_t> stringEntry(const std::string &key, const std::u16string &value)
{
    std::vector<std::uint8_t> v;
    appendUtf16(v, value);
    return versionBlock(u16(key), v, true, std::uint16_t(value.size() + 1), {});
}

struct PeSpec {
    std::uint16_t machine = 0x8664;
    std::uint16_t subsystem = 2;
    bool dll = false;
    bool pe32plus = true;
    bool withVersion = true;
    std::uint32_t timestamp = 0x5F000000;
    // table key ("040904b0") -> ordered (name, value)
    std::vector<std::pair<std::string, std::vector<std::pair<std::string, std::u16string>>>> tables = {
        {"040904b0", {{"CompanyName", u"Fixture Studio"}, {"ProductName", u"Fixture Quest"},
                      {"FileDescription", u"Fixture Quest Game"}, {"ProductVersion", u"1.2"},
                      {"OriginalFilename", u"FixtureQuest.exe"}}}};
    std::vector<std::uint32_t> translations = {0x04B00409};
    std::size_t padTo = 0; // grow the file (size feature)
};

inline std::vector<std::uint8_t> buildVersionInfo(const PeSpec &spec)
{
    std::vector<std::vector<std::uint8_t>> tables;
    for (const auto &[key, entries] : spec.tables) {
        std::vector<std::vector<std::uint8_t>> strings;
        for (const auto &[name, value] : entries) {
            strings.push_back(stringEntry(name, value));
        }
        tables.push_back(versionBlock(u16(key), {}, true, 0, strings));
    }
    std::vector<std::uint8_t> translation;
    for (std::uint32_t t : spec.translations) {
        put32(translation, translation.size(), t);
    }
    auto varInfo = versionBlock(u"VarFileInfo", {}, true, 0,
                                {versionBlock(u"Translation", translation, false,
                                              std::uint16_t(translation.size()), {})});
    auto stringInfo = versionBlock(u"StringFileInfo", {}, true, 0, tables);
    std::vector<std::uint8_t> fixed(52, 0);
    put32(fixed, 0, 0xFEEF04BD);
    put32(fixed, 4, 0x00010000);
    put32(fixed, 8, 0x00010002);
    put32(fixed, 12, 0x00030004);
    return versionBlock(u"VS_VERSION_INFO", fixed, false, 52, {stringInfo, varInfo});
}

struct PeLayout {
    std::size_t lfanew = 0x80;
    std::size_t optionalHeader = 0;
    std::size_t sectionTable = 0;
    std::size_t rsrcFileOffset = 0x400;
    std::uint32_t rsrcRva = 0x1000;
    std::size_t versionOffset = 0; // file offset of the VS_VERSIONINFO blob
};

inline std::vector<std::uint8_t> buildPe(const PeSpec &spec, PeLayout *layoutOut = nullptr)
{
    PeLayout layout;
    std::vector<std::uint8_t> b(0x400, 0);
    b[0] = 'M';
    b[1] = 'Z';
    put32(b, 0x3C, std::uint32_t(layout.lfanew));
    const std::size_t nt = layout.lfanew;
    put32(b, nt, 0x00004550);
    put16(b, nt + 4, spec.machine);
    put16(b, nt + 6, 1);
    put32(b, nt + 8, spec.timestamp);
    const std::uint16_t optSize = spec.pe32plus ? 240 : 224;
    put16(b, nt + 20, optSize);
    put16(b, nt + 22, std::uint16_t(0x0022 | (spec.dll ? 0x2000 : 0)));
    const std::size_t opt = nt + 24;
    layout.optionalHeader = opt;
    put16(b, opt, spec.pe32plus ? 0x20B : 0x10B);
    put16(b, opt + 68, spec.subsystem);
    const std::size_t dirBase = spec.pe32plus ? 112 : 96;
    put32(b, opt + dirBase - 4, 16);

    std::vector<std::uint8_t> rsrc;
    if (spec.withVersion) {
        const auto version = buildVersionInfo(spec);
        rsrc.resize(0x58, 0);
        put16(rsrc, 14, 1);                 // root: 1 id entry
        put32(rsrc, 16, 16);                // RT_VERSION
        put32(rsrc, 20, 0x80000000u | 0x18);
        put16(rsrc, 0x18 + 14, 1);          // name level
        put32(rsrc, 0x18 + 16, 1);
        put32(rsrc, 0x18 + 20, 0x80000000u | 0x30);
        put16(rsrc, 0x30 + 14, 1);          // language level
        put32(rsrc, 0x30 + 16, 0x0409);
        put32(rsrc, 0x30 + 20, 0x48);       // data entry
        put32(rsrc, 0x48, layout.rsrcRva + 0x58);
        put32(rsrc, 0x48 + 4, std::uint32_t(version.size()));
        rsrc.insert(rsrc.end(), version.begin(), version.end());
        layout.versionOffset = layout.rsrcFileOffset + 0x58;
    } else {
        rsrc.resize(16, 0);
    }
    pad4(rsrc);
    if (spec.withVersion) {
        put32(b, opt + dirBase + 16, layout.rsrcRva);
        put32(b, opt + dirBase + 20, std::uint32_t(rsrc.size()));
    }
    const std::size_t sec = opt + optSize;
    layout.sectionTable = sec;
    std::memcpy(&b[sec], ".rsrc\0\0\0", 8);
    put32(b, sec + 8, std::uint32_t(rsrc.size()));   // VirtualSize
    put32(b, sec + 12, layout.rsrcRva);             // VirtualAddress
    put32(b, sec + 16, std::uint32_t(rsrc.size()));  // SizeOfRawData
    put32(b, sec + 20, std::uint32_t(layout.rsrcFileOffset));
    b.resize(layout.rsrcFileOffset);
    b.insert(b.end(), rsrc.begin(), rsrc.end());
    if (spec.padTo > b.size()) {
        b.resize(spec.padTo, 0);
    }
    if (layoutOut != nullptr) {
        *layoutOut = layout;
    }
    return b;
}

inline std::string acf(std::uint32_t appId, const std::string &name, const std::string &installDir,
                       std::uint32_t stateFlags = 4)
{
    return "\"AppState\"\n{\n\t\"appid\"\t\t\"" + std::to_string(appId) + "\"\n\t\"Universe\"\t\t\"1\"\n\t\"name\"\t\t\"" +
        name + "\"\n\t\"StateFlags\"\t\t\"" + std::to_string(stateFlags) + "\"\n\t\"installdir\"\t\t\"" +
        installDir + "\"\n\t\"LastUpdated\"\t\t\"1700000000\"\n\t\"SizeOnDisk\"\t\t\"123456\"\n\t\"buildid\"\t\t\"42\"\n}\n";
}

#ifdef THREESIXTY_PE_FIXTURE_DIR
inline std::string peFixture(const char *name)
{
    return std::string(THREESIXTY_PE_FIXTURE_DIR) + "/" + name;
}
#endif

} // namespace libtest
