#pragma once

// Read-only, bounded PE header + VS_VERSION_INFO parser (§7.3). It never maps
// or executes the file; bytes arrive through a PeByteSource that enforces
// the per-file read budget.

#include "library_types.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace threesixty::daemon::library {

inline constexpr std::uint16_t kMachineI386 = 0x014C;
inline constexpr std::uint16_t kMachineAmd64 = 0x8664;
inline constexpr std::uint16_t kMachineArm64 = 0xAA64;
inline constexpr std::uint16_t kSubsystemWindowsGui = 2;
inline constexpr std::uint16_t kSubsystemWindowsCui = 3;
inline constexpr std::uint16_t kImageFileDll = 0x2000;
inline constexpr std::uint32_t kPeHeadBytes = 4096;

class PeByteSource
{
public:
    virtual ~PeByteSource() = default;
    // Reads exactly len bytes at offset into out; false on I/O error/short read.
    virtual bool readAt(std::uint64_t offset, std::uint32_t len, std::vector<std::uint8_t> &out) = 0;
};

class BufferByteSource final : public PeByteSource
{
public:
    explicit BufferByteSource(std::span<const std::uint8_t> bytes)
        : m_bytes(bytes)
    {
    }
    bool readAt(std::uint64_t offset, std::uint32_t len, std::vector<std::uint8_t> &out) override;

private:
    std::span<const std::uint8_t> m_bytes;
};

struct PeLimits {
    std::uint32_t maxReadBytes = 2u * 1024 * 1024;
    std::uint32_t maxVersionBytes = 64u * 1024;
    std::uint16_t preferredLanguage = 0x0409;
};

struct PeParseStats {
    std::uint64_t bytesRequested = 0;
};

// head: optional prefetched bytes from offset 0 (e.g. a batched first read).
PeMetadata parsePe(PeByteSource &source, std::uint64_t fileSize, const PeLimits &limits,
                   std::span<const std::uint8_t> head = {}, PeParseStats *stats = nullptr);

const char *machineName(std::uint16_t machine);

// LANGID for the current LANG/LC_ALL (e.g. pt_BR -> 0x0416); 0x0409 fallback.
std::uint16_t systemLanguageId();

} // namespace threesixty::daemon::library
