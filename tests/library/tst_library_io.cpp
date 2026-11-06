// I/O engine backends and fallback, confined path resolution, mount
// validation, directory listing, inotify table and install scanning.
// Everything runs in mkdtemp() directories; nothing touches /games.
#include "test_support.hpp"

#include "inotify_watcher.hpp"
#include "install_scanner.hpp"
#include "io_engine.hpp"
#include "safe_fs.hpp"

#include <cerrno>

#include <fcntl.h>
#include <sys/stat.h>

using namespace threesixty::daemon::library;
using namespace libtest;

namespace {

LibraryConfig tmpConfig(const TempDir &dir)
{
    LibraryConfig config;
    config.rootPath = dir.path();
    config.databasePath = dir / "unused.db";
    config.mountPolicy = MountPolicy::AnyFilesystem;
    return config;
}

UniqueFd openRoot(const std::string &path)
{
    return UniqueFd(::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
}

// Open + read everything + close through the engine; returns bytes or -errno.
int readAll(IoEngine &engine, int rootFd, const std::string &rel, std::vector<std::uint8_t> &out)
{
    IoRequest open;
    open.op = IoOp::Open;
    open.dirFd = rootFd;
    open.path = rel;
    IoResult opened = engine.run(std::move(open));
    if (opened.res < 0) {
        return opened.res;
    }
    struct stat st {};
    ::fstat(opened.res, &st);
    IoRequest read;
    read.op = IoOp::Read;
    read.fd = opened.res;
    read.length = static_cast<std::uint32_t>(st.st_size);
    IoResult data = engine.run(std::move(read));
    out = std::move(data.data);
    IoRequest close;
    close.op = IoOp::Close;
    close.fd = opened.res;
    engine.run(std::move(close));
    return data.res;
}

void testBackendSelection()
{
    section("io backend selection and fallback");
    TempDir dir;
    SafeOpener opener;

    {
        LibraryConfig config = tmpConfig(dir);
        config.ioBackend = IoBackendPreference::ThreadPool;
        IoEngine engine(config, opener);
        CHECK(engine.kind() == IoBackendKind::ThreadPool);
        CHECK_EQ(engine.reason(), std::string("CONFIG"));
    }

#ifdef THREESIXTY_TEST_EXPECT_LIBURING
    CHECK(liburingCompiledIn());
#endif
    if (!liburingCompiledIn()) {
        LibraryConfig config = tmpConfig(dir);
        IoEngine engine(config, opener);
        CHECK(engine.kind() == IoBackendKind::ThreadPool);
        CHECK_EQ(engine.reason(), std::string("NO_LIBURING"));
        return;
    }

    // kernel.io_uring_disabled = 2 (read from a fake sysctl file).
    {
        writeFile(dir / "io_uring_disabled", "2\n");
        LibraryConfig config = tmpConfig(dir);
        config.ioUringDisabledSysctl = dir / "io_uring_disabled";
        IoEngine engine(config, opener);
        CHECK(engine.kind() == IoBackendKind::ThreadPool);
        CHECK_EQ(engine.reason(), std::string("SYSCTL_DISABLED"));
    }
    // io_uring_setup denied (sysctl = 1 without group, seccomp, LSM).
    for (int err : {-EPERM, -EACCES}) {
        LibraryConfig config = tmpConfig(dir);
        config.simulateIoUringInitError = err;
        IoEngine engine(config, opener);
        CHECK(engine.kind() == IoBackendKind::ThreadPool);
        CHECK_EQ(engine.reason(), std::string("EPERM"));
    }
    for (int err : {-ENOSYS, -EINVAL, -ENOMEM}) {
        LibraryConfig config = tmpConfig(dir);
        config.simulateIoUringInitError = err;
        IoEngine engine(config, opener);
        CHECK(engine.kind() == IoBackendKind::ThreadPool);
        CHECK_EQ(engine.reason(), std::string("UNSUPPORTED"));
    }
    // Missing sysctl file counts as 0: io_uring is attempted.
    {
        LibraryConfig config = tmpConfig(dir);
        config.ioUringDisabledSysctl = dir / "does-not-exist";
        IoEngine engine(config, opener);
        std::fprintf(stderr, "   real backend: %s (%s)\n", ioBackendKindName(engine.kind()),
                     engine.reason().c_str());
        CHECK(engine.kind() == IoBackendKind::IoUring || engine.reason() == "EPERM" ||
              engine.reason() == "UNSUPPORTED" || engine.reason() == "MISSING_OPS");
    }
}

void testBackendParity()
{
    section("io backend parity and runtime switch");
    TempDir dir;
    std::string payload;
    for (int i = 0; i < 70000; ++i) {
        payload.push_back(static_cast<char>('a' + i % 26));
    }
    writeFile(dir / "data/blob.bin", payload);
    writeFile(dir / "data/small.txt", "hello");
    UniqueFd root = openRoot(dir.path());
    SafeOpener opener;

    std::vector<IoBackendPreference> prefs = {IoBackendPreference::ThreadPool, IoBackendPreference::Auto};
    for (IoBackendPreference pref : prefs) {
        LibraryConfig config = tmpConfig(dir);
        config.ioBackend = pref;
        IoEngine engine(config, opener);
        std::vector<std::uint8_t> bytes;
        CHECK_EQ(readAll(engine, root.get(), "data/blob.bin", bytes), int(payload.size()));
        CHECK(std::string(bytes.begin(), bytes.end()) == payload);

        IoRequest stx;
        stx.op = IoOp::Statx;
        stx.dirFd = root.get();
        stx.path = "data/small.txt";
        IoResult st = engine.run(std::move(stx));
        CHECK_EQ(st.res, 0);
        CHECK_EQ(st.stx.stx_size, std::uint64_t(5));

        // Batch keeps order; a missing file fails alone.
        std::vector<IoRequest> batch(3);
        for (auto &r : batch) {
            r.op = IoOp::Statx;
            r.dirFd = root.get();
        }
        batch[0].path = "data/small.txt";
        batch[1].path = "data/missing";
        batch[2].path = "data/blob.bin";
        auto results = engine.runBatch(std::move(batch));
        CHECK_EQ(results.size(), std::size_t(3));
        CHECK_EQ(results[0].stx.stx_size, std::uint64_t(5));
        CHECK_EQ(results[1].res, -ENOENT);
        CHECK_EQ(results[2].stx.stx_size, std::uint64_t(payload.size()));

        // Symlink escape through the engine (openat2 RESOLVE_BENEATH or io_uring OPENAT2).
        std::error_code ec;
        fs::create_symlink("/etc/hostname", dir / "data/escape", ec);
        IoRequest open;
        open.op = IoOp::Open;
        open.dirFd = root.get();
        open.path = "data/escape";
        CHECK(engine.run(std::move(open)).res < 0);
        CHECK_EQ(engine.fdBudget().inUse(), std::uint64_t(0));
        CHECK_EQ(engine.bufferBudget().inUse(), std::uint64_t(0));

        // Cancelled token: the request is not served.
        CancelToken token = makeCancelToken();
        token->cancelled = true;
        IoRequest cancelled;
        cancelled.op = IoOp::Statx;
        cancelled.dirFd = root.get();
        cancelled.path = "data/small.txt";
        cancelled.token = token;
        IoResult cr = engine.run(std::move(cancelled));
        CHECK(cr.cancelled || cr.res == -ECANCELED);
    }

    if (liburingCompiledIn()) {
        LibraryConfig config = tmpConfig(dir);
        config.simulateIoUringRuntimeFailureAfter = 2;
        IoEngine engine(config, opener);
        if (engine.kind() == IoBackendKind::IoUring) {
            for (int i = 0; i < 6; ++i) {
                std::vector<std::uint8_t> bytes;
                CHECK_EQ(readAll(engine, root.get(), "data/small.txt", bytes), 5);
                CHECK(std::string(bytes.begin(), bytes.end()) == "hello");
            }
            CHECK(engine.kind() == IoBackendKind::ThreadPool);
            CHECK_EQ(engine.reason(), std::string("RUNTIME_FAILURE"));
            CHECK(engine.backendChanges() >= 1);
            CHECK_EQ(engine.fdBudget().inUse(), std::uint64_t(0));
        } else {
            std::fprintf(stderr, "   io_uring unavailable at runtime (%s): runtime switch skipped\n",
                         engine.reason().c_str());
        }
    }
}

void testSafeOpener()
{
    section("path confinement and symlinks");
    TempDir outside("360io-outside");
    writeFile(outside / "secret.txt", "secret");
    TempDir dir;
    writeFile(dir / "game/inner/real.exe", "MZ");
    std::error_code ec;
    fs::create_symlink(outside / "secret.txt", dir / "game/abs-escape", ec);
    fs::create_symlink("../../" + fs::path(outside.path()).filename().string() + "/secret.txt",
                       dir / "game/rel-escape", ec);
    fs::create_symlink("inner/real.exe", dir / "game/inner-link.exe", ec);
    fs::create_symlink(outside.path(), dir / "game/dir-escape", ec);
    fs::create_symlink("/proc/self/root/etc/hostname", dir / "game/magic", ec);
    fs::create_symlink(dir / "game", dir / "linked-root", ec);
    UniqueFd root = openRoot(dir.path());

    for (bool fallback : {false, true}) {
        SafeOpener opener(fallback);
        CHECK(fallback ? !opener.usesOpenat2() : opener.usesOpenat2() == kernelSupportsOpenat2());
        auto open = [&](const char *rel, bool directory) {
            const int fd = opener.openBeneath(root.get(), rel, directory);
            if (fd >= 0) {
                ::close(fd);
            }
            return fd;
        };
        CHECK(open("game/inner/real.exe", false) >= 0);
        CHECK(open("game/inner", true) >= 0);
        CHECK(open("game/abs-escape", false) < 0);
        CHECK(open("game/rel-escape", false) < 0);
        CHECK(open("game/dir-escape/secret.txt", false) < 0);
        CHECK(open("game/dir-escape", true) < 0);
        CHECK(open("game/magic", false) < 0);
        CHECK(open("../", true) < 0);
        CHECK(open("game/../../etc/hostname", false) < 0);
        CHECK(open("/etc/hostname", false) < 0);
        // Install root must never be a symlink (directories use O_DIRECTORY
        // + beneath; the fallback rejects every symlink).
        if (fallback) {
            CHECK(open("linked-root", true) < 0);
            CHECK(open("game/inner-link.exe", false) < 0);
        }
        // Final component is O_NOFOLLOW for files in both modes.
        CHECK(open("game/inner-link.exe", false) < 0);
    }
}

void testListingAndIdentity()
{
    section("getdents64 listing, truncation, identity");
    TempDir dir;
    for (int i = 0; i < 50; ++i) {
        writeFile(dir / ("many/f" + std::to_string(i)), "x");
    }
    ::mkfifo((dir / "many/fifo").c_str(), 0600);
    UniqueFd root = openRoot(dir.path());
    SafeOpener opener;
    UniqueFd many(opener.openBeneath(root.get(), "many", true));
    CHECK(many.valid());
    std::vector<DirEntryRaw> entries;
    bool truncated = false;
    CHECK_EQ(listDirectory(many.get(), 1000, entries, truncated), 0);
    CHECK_EQ(entries.size(), std::size_t(51));
    CHECK(!truncated);
    entries.clear();
    UniqueFd many2(opener.openBeneath(root.get(), "many", true));
    CHECK_EQ(listDirectory(many2.get(), 10, entries, truncated), 0);
    CHECK_EQ(entries.size(), std::size_t(10));
    CHECK(truncated);

    const DirIdentity a = identityOf(many.get());
    CHECK(a.ino != 0);
    fs::rename(dir / "many", dir / "renamed");
    UniqueFd renamed(opener.openBeneath(root.get(), "renamed", true));
    const DirIdentity b = identityOf(renamed.get());
    CHECK_EQ(a.ino, b.ino);
    CHECK(a.handle == b.handle);
    CHECK_EQ(joinRel("", "x"), std::string("x"));
    CHECK_EQ(joinRel("a", "b"), std::string("a/b"));
}

void testMount()
{
    section("mount validation");
    TempDir dir;
    LibraryConfig config = tmpConfig(dir);
    config.mountPolicy = MountPolicy::Strict;
    // A plain tmp directory is never an accepted /games in release policy.
    const MountCheck strict = validateLibraryMount(config);
    CHECK(strict.state != MountState::Ok);
    // Developer Preview policy: a plain directory is fine, the filesystem
    // rules still apply (tmpfs -> UNSUPPORTED_FS, btrfs without zstd ->
    // MOUNT_POLICY_VIOLATION, ext4/btrfs+zstd -> OK).
    config.mountPolicy = MountPolicy::Directory;
    const MountCheck directory = validateLibraryMount(config);
    CHECK(directory.state != MountState::NotAMountpoint && directory.state != MountState::Absent);
    if (directory.fsType == "ext4" || directory.fsType == "btrfs") {
        CHECK(directory.state == MountState::Ok || directory.state == MountState::PolicyViolation);
    } else {
        CHECK(directory.state == MountState::UnsupportedFs);
    }
    std::fprintf(stderr, "   directory policy on %s: %s\n", directory.fsType.c_str(),
                 mountStateName(directory.state));
    config.mountPolicy = MountPolicy::AnyFilesystem;
    CHECK(validateLibraryMount(config).state == MountState::Ok);
    config.rootPath = dir / "absent";
    CHECK(validateLibraryMount(config).state == MountState::Absent);
    // Root symlink is rejected (O_NOFOLLOW).
    std::error_code ec;
    fs::create_symlink(dir.path(), dir / "rootlink", ec);
    config.rootPath = dir / "rootlink";
    CHECK(validateLibraryMount(config).state != MountState::Ok);

    const auto entries = parseMountInfo(
        "36 35 98:0 /mnt1 /games rw,noatime master:1 - btrfs /dev/sda1 rw,compress=zstd:3\n"
        "garbage line\n"
        "37 35 8:2 / /data\\040dir ro - ext4 /dev/sda2 rw\n");
    CHECK_EQ(entries.size(), std::size_t(2));
    if (entries.size() == 2) {
        CHECK_EQ(entries[0].mountId, std::uint64_t(36));
        CHECK_EQ(entries[0].major, 98u);
        CHECK_EQ(entries[0].mountPoint, std::string("/games"));
        CHECK_EQ(entries[0].fsType, std::string("btrfs"));
        CHECK(entries[0].superOptions.find("compress=zstd") != std::string::npos);
        CHECK_EQ(entries[1].mountPoint, std::string("/data dir"));
    }
}

void testInotifyTable()
{
    section("inotify watch table and budget");
    TempDir dir;
    for (const char *d : {"a", "a/b", "c", "d"}) {
        fs::create_directories(dir / d);
    }
    UniqueFd root = openRoot(dir.path());
    SafeOpener opener;
    InotifyWatcher watcher;
    CHECK(watcher.init(3));
    CHECK(watcher.budget() <= 3);
    CHECK(watcher.addWatch(root.get(), opener, "") == InotifyWatcher::AddResult::Added);
    CHECK(watcher.addWatch(root.get(), opener, "a") == InotifyWatcher::AddResult::Added);
    CHECK(watcher.addWatch(root.get(), opener, "a") == InotifyWatcher::AddResult::Existing);
    CHECK(watcher.addWatch(root.get(), opener, "a/b") == InotifyWatcher::AddResult::Added);
    CHECK(watcher.addWatch(root.get(), opener, "c") == InotifyWatcher::AddResult::BudgetExhausted);
    CHECK(watcher.exhausted());
    CHECK_EQ(watcher.used(), std::size_t(3));
    // Watches outside the root cannot be placed through a symlink.
    std::error_code ec;
    fs::create_symlink("/tmp", dir / "tmplink", ec);
    watcher.removeTree("a");
    CHECK_EQ(watcher.used(), std::size_t(1));
    CHECK(watcher.addWatch(root.get(), opener, "tmplink") == InotifyWatcher::AddResult::Failed);

    CHECK(watcher.addWatch(root.get(), opener, "d") == InotifyWatcher::AddResult::Added);
    fs::rename(dir / "d", dir / "e");
    watcher.renamePrefix("d", "e");
    writeFile(dir / "e/new.txt", "x");
    std::vector<RawInotifyEvent> events;
    waitFor([&] {
        watcher.readEvents(events);
        for (const auto &ev : events) {
            if (ev.name == "new.txt" && watcher.relFor(ev.wd) == std::optional<std::string>("e")) {
                return true;
            }
        }
        return false;
    }, std::chrono::milliseconds(2000));
    bool sawRenamed = false;
    for (const auto &ev : events) {
        sawRenamed = sawRenamed || (ev.name == "new.txt" && watcher.relFor(ev.wd) == std::optional<std::string>("e"));
    }
    CHECK(sawRenamed);
}

void writeGame(const TempDir &dir, const std::string &rel, const std::string &exe, PeSpec spec = {})
{
    writeBytes(dir / (rel + "/" + exe), buildPe(spec));
}

InstallScanResult scanDir(const TempDir &dir, LibraryConfig config, const std::string &rel,
                          bool fallbackOpener = false)
{
    SafeOpener opener(fallbackOpener);
    IoEngine engine(config, opener);
    InstallScanner scanner(config, engine, opener);
    UniqueFd root = openRoot(dir.path());
    DiscoveredInstall install;
    install.key.kind = InstallKind::Directory;
    install.key.relPath = rel;
    UniqueFd installFd(opener.openBeneath(root.get(), rel, true));
    if (installFd.valid()) {
        install.identity = identityOf(installFd.get());
    }
    return scanner.scan(root.get(), install, 1, {}, makeCancelToken());
}

void testScanner()
{
    section("install scanner: discovery, malformed, symlinks, limits");
    TempDir outside("360io-outside");
    writeBytes(outside / "Evil.exe", buildPe({}));
    TempDir dir;
    LibraryConfig config = tmpConfig(dir);

    // Clear winner.
    PeSpec quest;
    writeGame(dir, "Fixture Quest", "FixtureQuest.exe", quest);
    writeGame(dir, "Fixture Quest", "UnityCrashHandler64.exe");
    writeGame(dir, "Fixture Quest", "unins000.exe");
    writeGame(dir, "Fixture Quest", "_CommonRedist/DXSETUP.exe");
    writeGame(dir, "Fixture Quest", "_CommonRedist/vcredist_x64.exe");
    PeSpec dll;
    dll.dll = true;
    writeGame(dir, "Fixture Quest", "Plugin.exe", dll);
    // Malformed / truncated / not-PE .exe files never crash and never win.
    auto pe = buildPe(quest);
    writeBytes(dir / "Fixture Quest/Truncated.exe", std::vector<std::uint8_t>(pe.begin(), pe.begin() + 90));
    writeFile(dir / "Fixture Quest/text.exe", "this is not a PE file at all");
    writeFile(dir / "Fixture Quest/empty.exe", "");
    auto badLfanew = pe;
    put32(badLfanew, 0x3C, 0x7FFFFFF0);
    writeBytes(dir / "Fixture Quest/BadHeader.exe", badLfanew);
    // Symlink escapes and special files are ignored without reading.
    std::error_code ec;
    fs::create_symlink(outside / "Evil.exe", dir / "Fixture Quest/Evil.exe", ec);
    fs::create_symlink(outside.path(), dir / "Fixture Quest/outside-dir", ec);
    ::mkfifo((dir / "Fixture Quest/pipe.exe").c_str(), 0600);

    for (bool fallback : {false, true}) {
        const InstallScanResult r = scanDir(dir, config, "Fixture Quest", fallback);
        CHECK(!r.notAGame);
        CHECK(r.state == GameState::Ready);
        CHECK(r.mainCandidate.has_value());
        if (r.mainCandidate) {
            CHECK_EQ(r.candidates[*r.mainCandidate].relPath, std::string("FixtureQuest.exe"));
        }
        CHECK_EQ(r.displayName, std::string("Fixture Quest"));
        bool sawEvil = false;
        int excluded = 0;
        for (const auto &c : r.candidates) {
            sawEvil = sawEvil || c.relPath.find("Evil") != std::string::npos ||
                c.relPath.find("outside-dir") != std::string::npos || c.relPath == "pipe.exe";
            excluded += c.excludedBy.empty() ? 0 : 1;
            if (c.relPath == "Truncated.exe" || c.relPath == "text.exe" || c.relPath == "BadHeader.exe") {
                CHECK(!c.pe.validPe);
                CHECK(!c.pe.parseError.empty());
            }
        }
        CHECK(!sawEvil);
        CHECK(excluded >= 5); // four hard rules + DLL
    }

    // Ambiguous: two equally plausible executables.
    PeSpec plain;
    plain.tables = {{"040904b0", {{"ProductName", u"Twin"}}}};
    writeGame(dir, "Twins", "Alpha.exe", plain);
    writeGame(dir, "Twins", "Bravo.exe", plain);
    const auto twins = scanDir(dir, config, "Twins");
    CHECK(twins.state == GameState::Ambiguous);
    CHECK(twins.candidates.size() >= 2);
    CHECK(!twins.mainCandidate.has_value());

    // Only hard-excluded executables -> ERROR(NO_EXECUTABLE) or not a game.
    writeGame(dir, "Redist", "vcredist_x86.exe");
    const auto redist = scanDir(dir, config, "Redist");
    CHECK(redist.notAGame || (redist.state == GameState::Error && redist.reason == "NO_EXECUTABLE"));

    // Directory without executables is not a game.
    writeFile(dir / "Docs/readme.txt", "x");
    CHECK(scanDir(dir, config, "Docs").notAGame);

    // Candidate cap.
    LibraryConfig capped = config;
    capped.maxCandidatesPerInstall = 3;
    for (int i = 0; i < 6; ++i) {
        writeGame(dir, "Many", "tool" + std::to_string(i) + ".exe");
    }
    const auto many = scanDir(dir, capped, "Many");
    CHECK(many.candidates.size() <= 3);
    CHECK(many.candidatesTruncated >= 3);

    // PE read budget: a huge file is read only up to maxPeReadBytes.
    PeSpec big;
    big.padTo = 8 * 1024 * 1024;
    writeGame(dir, "Big", "Big.exe", big);
    const auto bigScan = scanDir(dir, config, "Big");
    CHECK(bigScan.peBytesRead <= config.maxPeReadBytes);

    // Incomplete copy: temp markers are reported by scan and snapshot.
    writeGame(dir, "Copying", "Copying.exe");
    writeFile(dir / "Copying/data.pak.part", "partial");
    const auto copying = scanDir(dir, config, "Copying");
    CHECK(copying.tempMarkers);
    {
        SafeOpener opener;
        IoEngine engine(config, opener);
        InstallScanner scanner(config, engine, opener);
        UniqueFd root = openRoot(dir.path());
        InstallKey key;
        key.relPath = "Copying";
        const InstallSnapshot s1 = scanner.snapshot(root.get(), key);
        CHECK(s1.exists);
        CHECK(s1.tempMarkers);
        fs::rename(dir / "Copying/data.pak.part", dir / "Copying/data.pak");
        const InstallSnapshot s2 = scanner.snapshot(root.get(), key);
        CHECK(!s2.tempMarkers);
        CHECK(s2 == scanner.snapshot(root.get(), key));
        writeFile(dir / "Copying/more.bin", "grow");
        CHECK(!(s2 == scanner.snapshot(root.get(), key)));
        key.relPath = "Gone";
        CHECK(!scanner.snapshot(root.get(), key).exists);
    }
    CHECK(isTempMarkerName("a.crdownload"));
    CHECK(isTempMarkerName("b.!qB"));
    CHECK(isTempMarkerName("c~"));
    CHECK(!isTempMarkerName("game.exe"));

    // Vanished install root.
    const auto vanished = scanDir(dir, config, "NeverExisted");
    CHECK(vanished.vanished || vanished.notAGame || vanished.state == GameState::Error);
}

void testSteamDiscovery()
{
    section("steam discovery: valid, malformed, escape, updating");
    TempDir outside("360io-outside");
    TempDir dir;
    LibraryConfig config = tmpConfig(dir);
    writeFile(dir / "SteamLibrary/steamapps/appmanifest_440.acf", acf(440, "Team Fortress 2", "Team Fortress 2"));
    writeGame(dir, "SteamLibrary/steamapps/common/Team Fortress 2", "hl2.exe");
    writeFile(dir / "SteamLibrary/steamapps/appmanifest_10.acf", acf(10, "Escape", ".."));
    writeFile(dir / "SteamLibrary/steamapps/appmanifest_20.acf", "\"AppState\" { \"appid\" \"20\"");
    writeFile(dir / "SteamLibrary/steamapps/appmanifest_30.acf", acf(30, "Updating", "Upd", 1026));
    writeGame(dir, "SteamLibrary/steamapps/common/Upd", "upd.exe");
    writeFile(dir / "SteamLibrary/steamapps/appmanifest_40.acf", acf(40, "Linked", "Linked"));
    std::error_code ec;
    fs::create_symlink(outside.path(), dir / "SteamLibrary/steamapps/common/Linked", ec);
    writeFile(dir / "SteamLibrary/steamapps/appmanifest_50.acf", std::string(300 * 1024, ' '));
    writeFile(dir / "SteamLibrary/steamapps/appmanifest_x.acf", acf(1, "Bad", "Bad"));
    writeGame(dir, "Loose Game", "Loose.exe");

    SafeOpener opener;
    IoEngine engine(config, opener);
    InstallScanner scanner(config, engine, opener);
    UniqueFd root = openRoot(dir.path());
    const DiscoveryResult d = scanner.discover(root.get(), makeCancelToken());
    CHECK_EQ(d.error, 0);
    std::map<std::uint32_t, const DiscoveredInstall *> steam;
    bool sawLoose = false;
    bool sawSteamLibraryAsGame = false;
    for (const auto &install : d.installs) {
        if (install.key.kind == InstallKind::Steam) {
            steam[install.key.steamAppId] = &install;
        } else {
            sawLoose = sawLoose || install.key.relPath == "Loose Game";
            sawSteamLibraryAsGame = sawSteamLibraryAsGame || install.key.relPath == "SteamLibrary";
        }
    }
    CHECK(sawLoose);
    CHECK(!sawSteamLibraryAsGame);
    CHECK(steam.count(440) && steam[440]->manifestError.empty() && steam[440]->steam &&
          steam[440]->steam->name == "Team Fortress 2");
    CHECK(steam.count(10) && !steam[10]->manifestError.empty());
    CHECK(steam.count(20) && !steam[20]->manifestError.empty());
    CHECK(steam.count(30) && steam[30]->steam && (steam[30]->steam->stateFlags & 4) == 0);
    // Symlinked installdir never resolves outside the library.
    CHECK(steam.count(40) && (!steam[40]->manifestError.empty() || steam[40]->installDirMissing));
    CHECK(steam.count(50) == 0 || !steam[50]->manifestError.empty());
    CHECK(!scanner.acfFailures().empty());

    if (steam.count(440)) {
        const auto r = scanner.scan(root.get(), *steam[440], 1, {}, makeCancelToken());
        CHECK(r.state == GameState::Ready);
        CHECK_EQ(r.displayName, std::string("Team Fortress 2"));
        CHECK_EQ(r.displayNameSource, std::string("steam_acf"));
    }
}

} // namespace

int main()
{
    testBackendSelection();
    testBackendParity();
    testSafeOpener();
    testListingAndIdentity();
    testMount();
    testInotifyTable();
    testScanner();
    testSteamDiscovery();
    return finish("tst_library_io");
}
