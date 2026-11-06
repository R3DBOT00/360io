// 360io-recovery-detect: decide at boot whether to enter recovery mode.
//
// Requests recovery when the kernel command line has 360io.recovery=1 or a
// left/right Shift key is held on any evdev keyboard within the timeout.
// The only side effect is the ephemeral flag /run/360io/recovery-requested.
//
// Exit: 0 recovery requested (flag written), 1 not requested, 2 error.

#include "recovery_detect.hpp"

#include <algorithm>
#include <charconv>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>
#include <thread>

using namespace threesixty::recovery;
using namespace std::chrono;

namespace {

struct Args {
    std::string cmdlinePath = "/proc/cmdline";
    std::string inputDir = "/dev/input";
    std::string runDir = "/run";
    milliseconds timeout{1500};
    bool dryRun = false;
};

constexpr milliseconds kMaxTimeout{10000};

int usage()
{
    std::fputs("usage: 360io-recovery-detect [--timeout-ms N] [--cmdline FILE] "
               "[--input-dir DIR] [--run-dir DIR] [--dry-run]\n", stderr);
    return 2;
}

bool parseArgs(int argc, char **argv, Args &args)
{
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg = argv[i];
        if (arg == "--dry-run") {
            args.dryRun = true;
            continue;
        }
        if (i + 1 >= argc)
            return false;
        const std::string value = argv[++i];
        if (arg == "--cmdline") {
            args.cmdlinePath = value;
        } else if (arg == "--input-dir") {
            args.inputDir = value;
        } else if (arg == "--run-dir") {
            args.runDir = value;
        } else if (arg == "--timeout-ms") {
            long ms = -1;
            const auto [end, ec] = std::from_chars(value.data(), value.data() + value.size(), ms);
            if (ec != std::errc{} || end != value.data() + value.size() || ms < 0)
                return false;
            args.timeout = std::min(milliseconds(ms), kMaxTimeout);
        } else {
            return false;
        }
    }
    return true;
}

int request(const Args &args, Reason reason)
{
    if (args.dryRun) {
        std::printf("recovery requested (%s), dry run\n", reasonName(reason).data());
        return 0;
    }
    if (const auto error = writeFlag(args.runDir, reason)) {
        std::fprintf(stderr, "360io-recovery-detect: cannot write flag: %s\n", error->c_str());
        return 2;
    }
    std::printf("recovery requested (%s)\n", reasonName(reason).data());
    return 0;
}

} // namespace

int main(int argc, char **argv)
{
    Args args;
    if (!parseArgs(argc, argv, args))
        return usage();

    // Kernel cmdline first: it is the fallback that works without evdev.
    std::ifstream cmdlineFile(args.cmdlinePath);
    const std::string cmdline((std::istreambuf_iterator<char>(cmdlineFile)), {});
    if (cmdlineRequestsRecovery(cmdline))
        return request(args, Reason::Cmdline);

    ScanOptions options;
    options.timeout = args.timeout;
    options.listDevices = [&] { return listEventDevices(args.inputDir); };
    options.probe = probeEventDevice;
    options.sleep = [](milliseconds ms) { std::this_thread::sleep_for(ms); };
    options.now = [] { return steady_clock::now(); };
    const ScanResult scan = scanForShift(options);
    if (scan.shift)
        return request(args, Reason::Shift);

    if (scan.devicesOpened == 0)
        std::printf("no recovery: no readable evdev device in %s (use %s)\n",
                    args.inputDir.c_str(), std::string(kCmdlineToken).c_str());
    else
        std::printf("no recovery: shift not held (%d keyboard(s))\n", scan.keyboards);
    return 1;
}
