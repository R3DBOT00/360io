#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// Boot-time recovery request detection. Kept free of I/O policy so the
// decision logic is unit-testable without evdev devices or /run.
namespace threesixty::recovery {

inline constexpr std::string_view kCmdlineToken = "360io.recovery=1";
inline constexpr std::string_view kFlagName = "recovery-requested";

enum class Reason {
    None,
    Cmdline,
    Shift,
};

std::string_view reasonName(Reason reason);

// True when the kernel command line carries 360io.recovery=1 as a whole word.
bool cmdlineRequestsRecovery(std::string_view cmdline);

// Test a key code in an EVIOCGKEY/EVIOCGBIT(EV_KEY) bitmap.
bool testKeyBit(std::span<const std::uint8_t> bits, unsigned code);

// Left or right Shift held in an EVIOCGKEY state bitmap.
bool shiftHeld(std::span<const std::uint8_t> keyState);

// Device advertises at least one Shift key in its EV_KEY capability bitmap.
bool hasShiftKey(std::span<const std::uint8_t> keyCaps);

struct DeviceProbe {
    bool opened = false;
    std::vector<std::uint8_t> caps;
    std::vector<std::uint8_t> state;
};

struct ScanResult {
    bool shift = false;
    int devicesOpened = 0;
    int keyboards = 0;
    int rounds = 0;
};

// Polls the devices returned by listDevices() until a Shift is seen or the
// deadline passes. Devices may appear late (udev), so the list is refreshed
// every round.
struct ScanOptions {
    std::chrono::milliseconds timeout{1500};
    std::chrono::milliseconds interval{50};
    std::function<std::vector<std::string>()> listDevices;
    std::function<DeviceProbe(const std::string &)> probe;
    std::function<void(std::chrono::milliseconds)> sleep;
    std::function<std::chrono::steady_clock::time_point()> now;
};

ScanResult scanForShift(const ScanOptions &options);

// evdev implementations for ScanOptions.
std::vector<std::string> listEventDevices(const std::string &inputDir);
DeviceProbe probeEventDevice(const std::string &path);

// Creates <runDir>/360io/recovery-requested atomically; never follows
// symlinks. Returns an error message on failure.
std::optional<std::string> writeFlag(const std::string &runDir, Reason reason);

} // namespace threesixty::recovery
