// Unit tests for the recovery detection logic; no evdev, /run or XFCE needed.
#include "recovery_detect.hpp"

#include <linux/input.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>

#include <unistd.h>

using namespace threesixty::recovery;
using namespace std::chrono;
namespace fs = std::filesystem;

namespace {

int failures = 0;

#define CHECK(cond)                                                                 \
    do {                                                                            \
        if (!(cond)) {                                                              \
            std::fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
            ++failures;                                                             \
        }                                                                           \
    } while (0)

std::vector<std::uint8_t> bits(std::initializer_list<unsigned> codes)
{
    std::vector<std::uint8_t> out((KEY_MAX + 8) / 8, 0);
    for (unsigned code : codes)
        out[code / 8] |= std::uint8_t(1u << (code % 8));
    return out;
}

// Fake clock and device table driving scanForShift deterministically.
struct FakeBoot {
    steady_clock::time_point clock{};
    std::map<std::string, DeviceProbe> devices;
    std::function<void(int)> onRound;
    int round = 0;

    ScanOptions options(milliseconds timeout)
    {
        ScanOptions o;
        o.timeout = timeout;
        o.interval = milliseconds(50);
        o.now = [this] { return clock; };
        o.sleep = [this](milliseconds ms) { clock += ms; };
        o.listDevices = [this] {
            if (onRound)
                onRound(round);
            ++round;
            std::vector<std::string> out;
            for (const auto &[path, probe] : devices)
                out.push_back(path);
            return out;
        };
        o.probe = [this](const std::string &path) { return devices.at(path); };
        return o;
    }
};

DeviceProbe keyboard(std::initializer_list<unsigned> held)
{
    return {true, bits({KEY_A, KEY_LEFTSHIFT, KEY_RIGHTSHIFT}), bits(held)};
}

void cmdline()
{
    CHECK(cmdlineRequestsRecovery("BOOT_IMAGE=/vmlinuz root=UUID=x 360io.recovery=1 quiet"));
    CHECK(cmdlineRequestsRecovery("360io.recovery=1"));
    CHECK(cmdlineRequestsRecovery("quiet\t360io.recovery=1\n"));
    CHECK(!cmdlineRequestsRecovery("360io.recovery=0"));
    CHECK(!cmdlineRequestsRecovery("x360io.recovery=1"));
    CHECK(!cmdlineRequestsRecovery("360io.recovery=10"));
    CHECK(!cmdlineRequestsRecovery(""));
}

void keyBits()
{
    CHECK(shiftHeld(bits({KEY_LEFTSHIFT})));
    CHECK(shiftHeld(bits({KEY_RIGHTSHIFT})));
    CHECK(!shiftHeld(bits({KEY_LEFTCTRL, KEY_A})));
    CHECK(!shiftHeld({}));
    CHECK(hasShiftKey(bits({KEY_RIGHTSHIFT})));
    CHECK(!hasShiftKey(bits({BTN_LEFT})));
    const std::uint8_t tiny[1] = {0xff};
    CHECK(!testKeyBit(tiny, KEY_LEFTSHIFT)); // out of range is "not set"
}

void scan()
{
    { // Right Shift held on a keyboard: found on first round.
        FakeBoot boot;
        boot.devices["/dev/input/event0"] = {true, bits({BTN_LEFT}), bits({BTN_LEFT})};
        boot.devices["/dev/input/event3"] = keyboard({KEY_RIGHTSHIFT});
        const ScanResult r = scanForShift(boot.options(milliseconds(1500)));
        CHECK(r.shift && r.rounds == 1 && r.keyboards == 1 && r.devicesOpened == 2);
    }
    { // Nothing held: stops at the deadline, never earlier and never beyond.
        FakeBoot boot;
        boot.devices["/dev/input/event0"] = keyboard({KEY_A});
        const auto start = boot.clock;
        const ScanResult r = scanForShift(boot.options(milliseconds(1000)));
        CHECK(!r.shift);
        CHECK(boot.clock - start == milliseconds(1000));
        CHECK(r.rounds == 21);
    }
    { // Keyboard appears late (udev) and Shift is held then.
        FakeBoot boot;
        boot.onRound = [&](int round) {
            if (round == 5)
                boot.devices["/dev/input/event7"] = keyboard({KEY_LEFTSHIFT});
        };
        const ScanResult r = scanForShift(boot.options(milliseconds(1500)));
        CHECK(r.shift && r.rounds == 6);
    }
    { // Shift state on a device without Shift capability is ignored.
        FakeBoot boot;
        boot.devices["/dev/input/event1"] = {true, bits({BTN_LEFT}), bits({KEY_LEFTSHIFT})};
        CHECK(!scanForShift(boot.options(milliseconds(100))).shift);
    }
    { // Unreadable devices (evdev failure): no recovery, cmdline is the fallback.
        FakeBoot boot;
        boot.devices["/dev/input/event0"] = {};
        const ScanResult r = scanForShift(boot.options(milliseconds(0)));
        CHECK(!r.shift && r.devicesOpened == 0 && r.rounds == 1);
    }
}

void flag()
{
    const fs::path run = fs::temp_directory_path() / ("360io-recovery-test-" + std::to_string(::getpid()));
    fs::remove_all(run);
    fs::create_directories(run);
    CHECK(!writeFlag(run.string(), Reason::Shift));
    std::ifstream in(run / "360io/recovery-requested");
    std::string body((std::istreambuf_iterator<char>(in)), {});
    CHECK(body == "reason=shift\n");
    CHECK(!fs::exists(run / "360io/recovery-requested.tmp"));
    CHECK(!writeFlag(run.string(), Reason::Cmdline)); // idempotent overwrite
    CHECK(writeFlag((run / "missing").string(), Reason::Shift).has_value());

    // A symlinked 360io directory is refused instead of followed.
    const fs::path evil = run / "evil";
    fs::create_directories(evil / "target");
    fs::create_directory_symlink(evil / "target", evil / "360io");
    CHECK(writeFlag(evil.string(), Reason::Shift).has_value());
    CHECK(!fs::exists(evil / "target/recovery-requested"));
    fs::remove_all(run);
}

void devices()
{
    const fs::path dir = fs::temp_directory_path() / ("360io-input-test-" + std::to_string(::getpid()));
    fs::remove_all(dir);
    fs::create_directories(dir);
    for (const char *name : {"event2", "event10", "mouse0", "eventX", "event"})
        std::ofstream(dir / name) << "";
    const auto list = listEventDevices(dir.string());
    CHECK(list.size() == 2);
    // Regular files are not character devices: probed as unopened.
    CHECK(!probeEventDevice((dir / "event2").string()).opened);
    CHECK(listEventDevices((dir / "none").string()).empty());
    fs::remove_all(dir);
}

} // namespace

int main()
{
    cmdline();
    keyBits();
    scan();
    flag();
    devices();
    if (failures) {
        std::fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    std::puts("recovery detect: all checks passed");
    return 0;
}
