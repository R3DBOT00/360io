#include "pe_parser.hpp"

#include "sanitize.hpp"

#include <cstdlib>
#include <cstring>
#include <set>
#include <string_view>

namespace threesixty::daemon::library {

namespace {

constexpr std::uint32_t kMaxLfanew = 1024 * 1024;
constexpr std::uint16_t kMaxSections = 96;
constexpr std::uint32_t kMaxResourceEntries = 512;
constexpr std::uint32_t kRtVersion = 16;
constexpr std::uint32_t kFixedFileInfoSignature = 0xFEEF04BD;
constexpr unsigned kMaxVersionDepth = 4;
constexpr unsigned kMaxVersionChildren = 256;

std::uint16_t u16(const std::uint8_t *p) { return static_cast<std::uint16_t>(p[0] | (p[1] << 8)); }

std::uint32_t u32(const std::uint8_t *p)
{
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
        (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}

struct Section {
    std::uint32_t va = 0;
    std::uint32_t vsize = 0;
    std::uint32_t rawPtr = 0;
    std::uint32_t rawSize = 0;
};

struct ParseFailure {
    const char *reason;
};

class BudgetedReader
{
public:
    BudgetedReader(PeByteSource &source, std::uint64_t fileSize, std::uint32_t budget,
                   std::span<const std::uint8_t> head)
        : m_source(source)
        , m_fileSize(fileSize)
        , m_budget(budget)
        , m_head(head)
    {
    }

    std::vector<std::uint8_t> read(std::uint64_t offset, std::uint32_t len)
    {
        if (offset > m_fileSize || len > m_fileSize - offset) {
            throw ParseFailure{"TRUNCATED"};
        }
        std::vector<std::uint8_t> out;
        if (offset + len <= m_head.size()) {
            out.assign(m_head.begin() + static_cast<std::ptrdiff_t>(offset),
                       m_head.begin() + static_cast<std::ptrdiff_t>(offset + len));
            return out;
        }
        if (std::uint64_t(m_used) + len > m_budget) {
            throw ParseFailure{"READ_BUDGET"};
        }
        m_used += len;
        if (!m_source.readAt(offset, len, out) || out.size() != len) {
            throw ParseFailure{"IO_ERROR"};
        }
        return out;
    }

    std::uint64_t used() const { return m_used; }

private:
    PeByteSource &m_source;
    std::uint64_t m_fileSize;
    std::uint32_t m_budget;
    std::uint32_t m_used = 0;
    std::span<const std::uint8_t> m_head;
};

struct VersionBlock {
    std::size_t end = 0;
    std::u16string key;
    std::size_t valueOff = 0;
    std::size_t valueLen = 0;
    std::uint16_t type = 0;
    std::size_t childrenOff = 0;
};

std::size_t align4(std::size_t v) { return (v + 3) & ~static_cast<std::size_t>(3); }

bool parseBlock(const std::vector<std::uint8_t> &v, std::size_t off, std::size_t limit,
                VersionBlock &block)
{
    if (off + 6 > limit) {
        return false;
    }
    const std::uint16_t wLength = u16(&v[off]);
    const std::uint16_t wValueLength = u16(&v[off + 2]);
    block.type = u16(&v[off + 4]);
    if (wLength < 6 || off + wLength > limit) {
        return false;
    }
    block.end = off + wLength;
    std::size_t p = off + 6;
    block.key.clear();
    while (true) {
        if (p + 2 > block.end) {
            return false;
        }
        const char16_t ch = static_cast<char16_t>(u16(&v[p]));
        p += 2;
        if (ch == 0) {
            break;
        }
        if (block.key.size() >= 64) {
            return false;
        }
        block.key.push_back(ch);
    }
    block.valueOff = std::min(align4(p), block.end);
    std::size_t valueLen = block.type == 1 ? std::size_t(wValueLength) * 2 : wValueLength;
    if (block.valueOff + valueLen > block.end) {
        if (block.type != 1) {
            return false;
        }
        valueLen = block.end - block.valueOff; // tolerate byte-counted text lengths
    }
    block.valueLen = valueLen;
    block.childrenOff = std::min(align4(block.valueOff + valueLen), block.end);
    return true;
}

template <typename Fn>
bool forEachChild(const std::vector<std::uint8_t> &v, const VersionBlock &parent, Fn &&fn)
{
    std::size_t off = parent.childrenOff;
    unsigned count = 0;
    while (off + 6 <= parent.end) {
        if (++count > kMaxVersionChildren) {
            return false;
        }
        VersionBlock child;
        if (!parseBlock(v, off, parent.end, child)) {
            // Zero padding at the end of a block is legal; anything else is not.
            return u16(&v[off]) == 0;
        }
        fn(child);
        off = align4(child.end);
    }
    return true;
}

bool keyIs(const std::u16string &key, std::string_view ascii)
{
    if (key.size() != ascii.size()) {
        return false;
    }
    for (std::size_t i = 0; i < key.size(); ++i) {
        if (key[i] != static_cast<char16_t>(ascii[i])) {
            return false;
        }
    }
    return true;
}

std::string asciiKey(const std::u16string &key)
{
    std::string out;
    for (char16_t c : key) {
        out.push_back(c < 0x80 ? static_cast<char>(c) : '?');
    }
    return out;
}

struct StringTable {
    std::uint16_t lang = 0;
    std::vector<std::pair<std::string, std::string>> values;
};

void parseVersionInfo(const std::vector<std::uint8_t> &v, std::uint16_t preferredLang,
                      PeMetadata &meta)
{
    VersionBlock root;
    if (!parseBlock(v, 0, v.size(), root) || !keyIs(root.key, "VS_VERSION_INFO")) {
        throw ParseFailure{"VERSION_MALFORMED"};
    }
    if (root.valueLen < 52 || u32(&v[root.valueOff]) != kFixedFileInfoSignature) {
        throw ParseFailure{"VERSION_MALFORMED"};
    }

    std::vector<StringTable> tables;
    std::vector<std::uint16_t> translations;
    bool ok = forEachChild(v, root, [&](const VersionBlock &child) {
        if (keyIs(child.key, "StringFileInfo")) {
            forEachChild(v, child, [&](const VersionBlock &tableBlock) {
                StringTable table;
                const std::string key = asciiKey(tableBlock.key);
                if (key.size() == 8) {
                    table.lang = static_cast<std::uint16_t>(
                        std::strtoul(key.substr(0, 4).c_str(), nullptr, 16));
                }
                forEachChild(v, tableBlock, [&](const VersionBlock &entry) {
                    std::string value;
                    if (entry.valueLen > 0) {
                        value = sanitizeUtf16Le(&v[entry.valueOff],
                                                std::min(entry.valueLen, entry.end - entry.valueOff));
                    }
                    table.values.emplace_back(asciiKey(entry.key), std::move(value));
                });
                tables.push_back(std::move(table));
            });
        } else if (keyIs(child.key, "VarFileInfo")) {
            forEachChild(v, child, [&](const VersionBlock &var) {
                if (!keyIs(var.key, "Translation")) {
                    return;
                }
                for (std::size_t p = var.valueOff; p + 4 <= var.valueOff + var.valueLen; p += 4) {
                    translations.push_back(u16(&v[p]));
                }
            });
        }
    });
    if (!ok) {
        throw ParseFailure{"VERSION_MALFORMED"};
    }

    const StringTable *chosen = nullptr;
    auto findLang = [&](std::uint16_t lang) -> const StringTable * {
        for (const StringTable &table : tables) {
            if (table.lang == lang) {
                return &table;
            }
        }
        return nullptr;
    };
    for (std::uint16_t lang : {preferredLang, std::uint16_t(0x0409), std::uint16_t(0x0000)}) {
        if (chosen == nullptr) {
            chosen = findLang(lang);
        }
    }
    if (chosen == nullptr && !translations.empty()) {
        chosen = findLang(translations.front());
    }
    if (chosen == nullptr && !tables.empty()) {
        chosen = &tables.front();
    }
    meta.hasVersionInfo = true;
    if (chosen == nullptr) {
        return;
    }
    for (const auto &[key, value] : chosen->values) {
        std::string *slot = nullptr;
        if (key == "ProductName") {
            slot = &meta.productName;
        } else if (key == "FileDescription") {
            slot = &meta.fileDescription;
        } else if (key == "CompanyName") {
            slot = &meta.companyName;
        } else if (key == "ProductVersion") {
            slot = &meta.productVersion;
        } else if (key == "FileVersion") {
            slot = &meta.fileVersion;
        } else if (key == "OriginalFilename") {
            slot = &meta.originalFilename;
        } else if (key == "InternalName") {
            slot = &meta.internalName;
        }
        if (slot != nullptr && slot->empty()) {
            *slot = value;
        }
    }
}

class PeParser
{
public:
    PeParser(BudgetedReader &reader, std::uint64_t fileSize, const PeLimits &limits)
        : m_reader(reader)
        , m_fileSize(fileSize)
        , m_limits(limits)
    {
    }

    void parseHeaders(PeMetadata &meta)
    {
        if (m_fileSize < 64) {
            throw ParseFailure{"TRUNCATED"};
        }
        const auto dos = m_reader.read(0, 64);
        if (dos[0] != 'M' || dos[1] != 'Z') {
            throw ParseFailure{"BAD_MZ"};
        }
        const std::uint32_t lfanew = u32(&dos[0x3C]);
        if ((lfanew & 3) != 0 || lfanew < 64 ||
            lfanew >= std::min<std::uint64_t>(m_fileSize, kMaxLfanew)) {
            throw ParseFailure{"BAD_LFANEW"};
        }
        const auto nt = m_reader.read(lfanew, 24);
        if (u32(&nt[0]) != 0x00004550) {
            throw ParseFailure{"BAD_PE_SIG"};
        }
        meta.machine = u16(&nt[4]);
        const std::uint16_t sections = u16(&nt[6]);
        meta.timestamp = u32(&nt[8]);
        const std::uint16_t optSize = u16(&nt[20]);
        meta.characteristics = u16(&nt[22]);
        meta.isDll = (meta.characteristics & kImageFileDll) != 0;
        if (sections == 0 || sections > kMaxSections) {
            throw ParseFailure{"BAD_SECTIONS"};
        }
        if (optSize < 2) {
            throw ParseFailure{"BAD_OPTIONAL_HEADER"};
        }
        const auto opt = m_reader.read(std::uint64_t(lfanew) + 24, optSize);
        const std::uint16_t magic = u16(&opt[0]);
        std::size_t dirBase = 0;
        if (magic == 0x10B) {
            dirBase = 96;
        } else if (magic == 0x20B) {
            dirBase = 112;
        } else {
            throw ParseFailure{"BAD_OPTIONAL_HEADER"};
        }
        if (optSize < dirBase || optSize < 70) {
            throw ParseFailure{"BAD_OPTIONAL_HEADER"};
        }
        meta.subsystem = u16(&opt[68]);
        const std::uint32_t rvaCount = u32(&opt[dirBase - 4]);
        if (rvaCount > 16 || dirBase + std::size_t(rvaCount) * 8 > optSize) {
            throw ParseFailure{"BAD_OPTIONAL_HEADER"};
        }
        if (rvaCount > 2) {
            m_rsrcRva = u32(&opt[dirBase + 16]);
            m_rsrcSize = u32(&opt[dirBase + 20]);
        }
        const std::uint64_t sectionTable = std::uint64_t(lfanew) + 24 + optSize;
        const auto table = m_reader.read(sectionTable, std::uint32_t(sections) * 40);
        m_sections.reserve(sections);
        for (std::uint16_t i = 0; i < sections; ++i) {
            const std::uint8_t *s = &table[std::size_t(i) * 40];
            m_sections.push_back(Section{u32(s + 12), u32(s + 8), u32(s + 20), u32(s + 16)});
        }
        meta.validPe = true;
        // Hostile layouts: raw data past the end of the file or overlapping
        // virtual ranges. The header is still a PE, but no metadata is trusted.
        for (std::size_t i = 0; i < m_sections.size(); ++i) {
            const Section &a = m_sections[i];
            if (a.rawSize != 0 && std::uint64_t(a.rawPtr) + a.rawSize > m_fileSize) {
                throw ParseFailure{"SECTION_BOUNDS"};
            }
            const std::uint64_t aEnd = std::uint64_t(a.va) + std::max(a.vsize, a.rawSize);
            for (std::size_t j = i + 1; j < m_sections.size(); ++j) {
                const Section &b = m_sections[j];
                const std::uint64_t bEnd = std::uint64_t(b.va) + std::max(b.vsize, b.rawSize);
                if (a.va < bEnd && b.va < aEnd) {
                    throw ParseFailure{"SECTION_OVERLAP"};
                }
            }
        }
    }

    // Maps [rva, rva+len) to a file offset fully backed by raw section data.
    std::uint64_t mapRva(std::uint64_t rva, std::uint64_t len) const
    {
        for (const Section &s : m_sections) {
            const std::uint64_t span = std::max<std::uint64_t>(s.vsize, s.rawSize);
            if (rva < s.va || rva >= std::uint64_t(s.va) + span) {
                continue;
            }
            const std::uint64_t delta = rva - s.va;
            if (delta + len > s.rawSize) {
                throw ParseFailure{"RVA_UNMAPPED"};
            }
            const std::uint64_t offset = std::uint64_t(s.rawPtr) + delta;
            if (offset + len > m_fileSize) {
                throw ParseFailure{"RVA_UNMAPPED"};
            }
            return offset;
        }
        throw ParseFailure{"RVA_UNMAPPED"};
    }

    std::vector<std::uint8_t> readResource(std::uint32_t rel, std::uint32_t len)
    {
        if (std::uint64_t(rel) + len > m_rsrcSize) {
            throw ParseFailure{"RESOURCE_BOUNDS"};
        }
        return m_reader.read(mapRva(std::uint64_t(m_rsrcRva) + rel, len), len);
    }

    struct DirEntry {
        std::uint32_t name;
        std::uint32_t target;
    };

    std::vector<DirEntry> readDirectory(std::uint32_t rel)
    {
        if (!m_visited.insert(rel).second) {
            throw ParseFailure{"RESOURCE_LOOP"};
        }
        const auto header = readResource(rel, 16);
        const std::uint32_t count = std::uint32_t(u16(&header[12])) + u16(&header[14]);
        if (count > kMaxResourceEntries) {
            throw ParseFailure{"RESOURCE_LIMIT"};
        }
        std::vector<DirEntry> entries;
        if (count == 0) {
            return entries;
        }
        const auto raw = readResource(rel + 16, count * 8);
        for (std::uint32_t i = 0; i < count; ++i) {
            entries.push_back({u32(&raw[i * 8]), u32(&raw[i * 8 + 4])});
        }
        return entries;
    }

    void parseVersion(PeMetadata &meta)
    {
        if (m_rsrcRva == 0 || m_rsrcSize < 16) {
            return;
        }
        const auto types = readDirectory(0);
        const DirEntry *versionType = nullptr;
        for (const DirEntry &e : types) {
            if ((e.name & 0x80000000u) == 0 && e.name == kRtVersion) {
                versionType = &e;
                break;
            }
        }
        if (versionType == nullptr) {
            return;
        }
        if ((versionType->target & 0x80000000u) == 0) {
            throw ParseFailure{"RESOURCE_MALFORMED"};
        }
        const auto names = readDirectory(versionType->target & 0x7FFFFFFFu);
        if (names.empty() || (names.front().target & 0x80000000u) == 0) {
            throw ParseFailure{"RESOURCE_MALFORMED"};
        }
        const auto langs = readDirectory(names.front().target & 0x7FFFFFFFu);
        if (langs.empty() || (langs.front().target & 0x80000000u) != 0) {
            throw ParseFailure{"RESOURCE_MALFORMED"};
        }
        const auto dataEntry = readResource(langs.front().target, 16);
        const std::uint32_t dataRva = u32(&dataEntry[0]);
        const std::uint32_t dataSize = u32(&dataEntry[4]);
        if (dataSize > m_limits.maxVersionBytes) {
            throw ParseFailure{"VERSION_TOO_LARGE"};
        }
        if (dataSize < 6) {
            throw ParseFailure{"VERSION_MALFORMED"};
        }
        const auto versionBytes = m_reader.read(mapRva(dataRva, dataSize), dataSize);
        parseVersionInfo(versionBytes, m_limits.preferredLanguage, meta);
    }

private:
    BudgetedReader &m_reader;
    std::uint64_t m_fileSize;
    const PeLimits &m_limits;
    std::vector<Section> m_sections;
    std::uint32_t m_rsrcRva = 0;
    std::uint32_t m_rsrcSize = 0;
    std::set<std::uint32_t> m_visited;
};

} // namespace

bool BufferByteSource::readAt(std::uint64_t offset, std::uint32_t len, std::vector<std::uint8_t> &out)
{
    if (offset > m_bytes.size() || len > m_bytes.size() - offset) {
        return false;
    }
    out.assign(m_bytes.begin() + static_cast<std::ptrdiff_t>(offset),
               m_bytes.begin() + static_cast<std::ptrdiff_t>(offset + len));
    return true;
}

PeMetadata parsePe(PeByteSource &source, std::uint64_t fileSize, const PeLimits &limits,
                   std::span<const std::uint8_t> head, PeParseStats *stats)
{
    PeMetadata meta;
    BudgetedReader reader(source, fileSize, limits.maxReadBytes, head);
    PeParser parser(reader, fileSize, limits);
    try {
        parser.parseHeaders(meta);
    } catch (const ParseFailure &failure) {
        meta.validPe = false;
        meta.parseError = failure.reason;
        if (stats != nullptr) {
            stats->bytesRequested = reader.used();
        }
        return meta;
    }
    try {
        parser.parseVersion(meta);
    } catch (const ParseFailure &failure) {
        // Metadata failures keep the candidate; only features are zeroed.
        const PeMetadata headers = meta;
        meta = PeMetadata{};
        meta.validPe = true;
        meta.machine = headers.machine;
        meta.subsystem = headers.subsystem;
        meta.characteristics = headers.characteristics;
        meta.timestamp = headers.timestamp;
        meta.isDll = headers.isDll;
        meta.parseError = failure.reason;
    }
    if (stats != nullptr) {
        stats->bytesRequested = reader.used();
    }
    return meta;
}

const char *machineName(std::uint16_t machine)
{
    switch (machine) {
    case kMachineI386:
        return "i386";
    case kMachineAmd64:
        return "amd64";
    case kMachineArm64:
        return "arm64";
    default:
        return "other";
    }
}

std::uint16_t systemLanguageId()
{
    const char *lang = std::getenv("LC_ALL");
    if (lang == nullptr || *lang == '\0') {
        lang = std::getenv("LANG");
    }
    if (lang == nullptr) {
        return 0x0409;
    }
    const std::string_view value(lang);
    struct Mapping {
        std::string_view prefix;
        std::uint16_t id;
    };
    static constexpr Mapping kMap[] = {
        {"pt_BR", 0x0416}, {"pt_PT", 0x0816}, {"en_GB", 0x0809}, {"en", 0x0409},
        {"es_MX", 0x080A}, {"es", 0x0C0A},    {"fr", 0x040C},    {"de", 0x0407},
        {"it", 0x0410},    {"ja", 0x0411},    {"ko", 0x0412},    {"zh_TW", 0x0404},
        {"zh", 0x0804},    {"ru", 0x0419},    {"pl", 0x0415},    {"pt", 0x0416},
    };
    for (const Mapping &m : kMap) {
        if (value.substr(0, m.prefix.size()) == m.prefix) {
            return m.id;
        }
    }
    return 0x0409;
}

} // namespace threesixty::daemon::library
