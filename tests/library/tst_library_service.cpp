// End-to-end scanner service over a tmp root (AnyFilesystem policy, short
// timings): initial scan, incomplete copy, rename, simulated IN_Q_OVERFLOW,
// symlink escape, storage loss, restart and io_uring unavailability.
#include "test_support.hpp"

#include "library_service.hpp"

#include <QJsonArray>

#include <cerrno>

#include <sys/inotify.h>

using namespace threesixty::daemon::library;
using namespace libtest;
using namespace std::chrono_literals;

namespace {

LibraryConfig serviceConfig(const TempDir &root, const TempDir &state)
{
    LibraryConfig config;
    config.rootPath = root.path();
    config.databasePath = state / "library.db";
    config.mountPolicy = MountPolicy::AnyFilesystem;
    config.debounce = 100ms;
    config.quietWindow = 300ms;
    config.tick = 50ms;
    config.renamePairWindow = 200ms;
    config.mountRetryInterval = 200ms;
    config.installConcurrency = 2;
    return config;
}

struct GameView {
    std::string id;
    std::string name;
    std::string state;
    std::string reason;
    std::string relPath;
};

std::map<std::string, GameView> gamesByRel(const LibraryService &service)
{
    std::map<std::string, GameView> out;
    ListGamesQuery query;
    query.limit = 200;
    // Default listing hides tombstones; ask for every state explicitly.
    query.states = {GameState::Discovered, GameState::Stabilizing, GameState::Scanning, GameState::Ready,
                    GameState::Ambiguous, GameState::Error, GameState::Removed};
    const QJsonArray games = service.listGames(query).value(QStringLiteral("games")).toArray();
    for (const QJsonValue &value : games) {
        const std::string id = value.toObject().value(QStringLiteral("game_id")).toString().toStdString();
        const auto game = service.getGame(id);
        if (!game) {
            continue;
        }
        GameView view;
        view.id = id;
        view.name = game->value(QStringLiteral("display_name")).toString().toStdString();
        view.state = game->value(QStringLiteral("state")).toString().toStdString();
        view.reason = game->value(QStringLiteral("state_reason")).toString().toStdString();
        const QJsonArray installs = game->value(QStringLiteral("installs")).toArray();
        for (const QJsonValue &install : installs) {
            if (!install.toObject().value(QStringLiteral("removed")).toBool()) {
                view.relPath = install.toObject().value(QStringLiteral("rel_path")).toString().toStdString();
            }
        }
        if (view.relPath.empty() && !installs.isEmpty()) {
            view.relPath = installs.first().toObject().value(QStringLiteral("rel_path")).toString().toStdString();
        }
        out[view.relPath] = view;
    }
    return out;
}

void addGame(const TempDir &root, const std::string &rel, const std::string &exe, const std::u16string &product)
{
    PeSpec spec;
    spec.tables = {{"040904b0", {{"ProductName", product}, {"FileDescription", product}}}};
    writeBytes(root / (rel + "/" + exe), buildPe(spec));
    writeBytes(root / (rel + "/UnityCrashHandler64.exe"), buildPe({}));
}

bool settle(LibraryService &service)
{
    return service.waitIdle(20s);
}

void testLifecycle(IoBackendPreference backend, int simulatedInitError)
{
    TempDir outside("360io-outside");
    addGame(outside, "Evil", "Evil.exe", u"Evil");
    TempDir root;
    TempDir state("360io-state");
    addGame(root, "Alpha Game", "Alpha.exe", u"Alpha Game");
    addGame(root, "Bravo", "Bravo.exe", u"Bravo");
    writeFile(root / "SteamLibrary/steamapps/appmanifest_440.acf", acf(440, "Team Fortress 2", "Team Fortress 2"));
    addGame(root, "SteamLibrary/steamapps/common/Team Fortress 2", "hl2.exe", u"Half-Life 2");
    writeFile(root / "SteamLibrary/steamapps/appmanifest_77.acf", "\"AppState\" { \"appid\" \"77\" ");
    writeFile(root / "Notes/readme.txt", "not a game");
    std::error_code ec;
    fs::create_symlink(outside / "Evil", root / "EvilLink", ec);

    LibraryConfig config = serviceConfig(root, state);
    config.ioBackend = backend;
    config.simulateIoUringInitError = simulatedInitError;

    std::string alphaId;
    std::string twinsId;
    std::int64_t pick = 0;
    {
        LibraryService service(config);
        CHECK(service.start());
        section("  initial scan");
        CHECK(settle(service));
        CHECK(service.storageAvailable());
        auto games = gamesByRel(service);
        CHECK_EQ(games.count("Alpha Game"), std::size_t(1));
        CHECK_EQ(games["Alpha Game"].state, std::string("READY"));
        CHECK_EQ(games["Alpha Game"].name, std::string("Alpha Game"));
        CHECK_EQ(games["Bravo"].state, std::string("READY"));
        CHECK_EQ(games.count("Notes"), std::size_t(0));
        CHECK_EQ(games.count("EvilLink"), std::size_t(0)); // symlinked install root never scanned
        bool sawTf2 = false;
        bool sawBrokenManifest = false;
        for (const auto &[rel, g] : games) {
            sawTf2 = sawTf2 || (g.name == "Team Fortress 2" && g.state == "READY");
            sawBrokenManifest = sawBrokenManifest || (g.state == "ERROR" && g.reason.find("MANIFEST") != std::string::npos);
        }
        CHECK(sawTf2);
        CHECK(sawBrokenManifest);
        alphaId = games["Alpha Game"].id;

        const QJsonObject health = service.health();
        const QJsonObject io = health.value(QStringLiteral("io_backend")).toObject();
        std::fprintf(stderr, "   io backend %s reason %s\n", qPrintable(io.value(QStringLiteral("kind")).toString()),
                     qPrintable(io.value(QStringLiteral("reason")).toString()));
        if (backend == IoBackendPreference::ThreadPool) {
            CHECK_EQ(io.value(QStringLiteral("kind")).toString(), QStringLiteral("threadpool"));
            CHECK_EQ(io.value(QStringLiteral("reason")).toString(), QStringLiteral("CONFIG"));
        }
        if (simulatedInitError != 0 && liburingCompiledIn()) {
            CHECK_EQ(io.value(QStringLiteral("kind")).toString(), QStringLiteral("threadpool"));
            CHECK_EQ(io.value(QStringLiteral("reason")).toString(), QStringLiteral("EPERM"));
        }
        CHECK_EQ(health.value(QStringLiteral("storage")).toObject().value(QStringLiteral("state")).toString(),
                 QStringLiteral("AVAILABLE"));
        CHECK(!health.value(QStringLiteral("db")).toObject().value(QStringLiteral("dirty")).toBool());
        CHECK(health.value(QStringLiteral("watches")).toObject().value(QStringLiteral("used")).toInteger() > 0);
        const QByteArray healthText = QJsonDocument(health).toJson();
        CHECK(!healthText.contains(QByteArray::fromStdString(state.path())));
        CHECK(!healthText.contains(QByteArray::fromStdString(outside.path())));

        section("  incomplete copy stays out of READY until stable");
        addGame(root, "Copying", "Copying.exe", u"Copying Game");
        writeFile(root / "Copying/data.pak.part", "partial");
        std::this_thread::sleep_for(900ms);
        games = gamesByRel(service);
        CHECK(games.count("Copying") == 0 || games["Copying"].state != "READY");
        fs::rename(root / "Copying/data.pak.part", root / "Copying/data.pak");
        CHECK(waitFor([&] {
            auto now = gamesByRel(service);
            return now.count("Copying") && now["Copying"].state == "READY";
        }, 10s));
        CHECK(settle(service));

        section("  rename keeps game_id");
        fs::rename(root / "Alpha Game", root / "Alpha Renamed");
        CHECK(waitFor([&] { return gamesByRel(service).count("Alpha Renamed") == 1; }, 10s));
        CHECK(settle(service));
        games = gamesByRel(service);
        CHECK_EQ(games["Alpha Renamed"].id, alphaId);
        CHECK_EQ(games["Alpha Renamed"].state, std::string("READY"));
        CHECK_EQ(games.count("Alpha Game"), std::size_t(0));

        section("  ambiguous + user choice");
        PeSpec plain;
        plain.tables = {{"040904b0", {{"ProductName", u"Twin"}}}};
        writeBytes(root / "Twins/Left.exe", buildPe(plain));
        writeBytes(root / "Twins/Right.exe", buildPe(plain));
        CHECK(waitFor([&] { return gamesByRel(service).count("Twins") == 1; }, 10s));
        CHECK(settle(service));
        games = gamesByRel(service);
        CHECK_EQ(games["Twins"].state, std::string("AMBIGUOUS"));
        twinsId = games["Twins"].id;
        const auto twins = service.getGame(twinsId);
        const QJsonArray candidates = twins->value(QStringLiteral("installs")).toArray().first().toObject()
                                          .value(QStringLiteral("candidates")).toArray();
        CHECK(candidates.size() >= 2);
        if (!candidates.isEmpty()) {
            pick = candidates.first().toObject().value(QStringLiteral("candidate_id")).toInteger();
            CHECK(service.setMainExecutable(twinsId, pick).empty());
            CHECK(settle(service));
            CHECK_EQ(gamesByRel(service)["Twins"].state, std::string("READY"));
        }

        section("  simulated IN_Q_OVERFLOW -> full reconciliation");
        const std::uint64_t reconciles = service.completedReconciles();
        service.setInotifyPaused(true); // events below are "lost"
        addGame(root, "Lost Event Game", "Lost.exe", u"Lost Event Game");
        fs::remove_all(root / "Bravo");
        std::this_thread::sleep_for(300ms);
        service.setInotifyPaused(false);
        RawInotifyEvent overflow;
        overflow.wd = -1;
        overflow.mask = IN_Q_OVERFLOW;
        service.injectInotifyEvent(overflow);
        CHECK(waitFor([&] { return service.completedReconciles() > reconciles; }, 15s));
        CHECK(settle(service));
        CHECK_EQ(service.inotifyOverflows(), std::uint64_t(1));
        games = gamesByRel(service);
        CHECK(games.count("Lost Event Game") && games["Lost Event Game"].state == "READY");
        CHECK(games.count("Bravo") && games["Bravo"].state == "REMOVED");
        const QJsonObject after = service.health();
        CHECK(!after.value(QStringLiteral("db")).toObject().value(QStringLiteral("dirty")).toBool());
        CHECK(!after.value(QStringLiteral("reconcile_pending_after_overflow")).toBool());
        CHECK(after.value(QStringLiteral("metrics")).toObject().value(QStringLiteral("inotify_overflows_total")).toInteger() == 1);

        section("  user rescan");
        const auto reply = service.rescan("", true);
        CHECK(reply.ok);
        CHECK(!service.rescan("not-a-game", false).ok);
        CHECK(settle(service));

        section("  events log");
        bool resync = true;
        const auto events = service.eventsSince(0, resync);
        CHECK(!resync);
        std::set<std::string> types;
        for (const auto &e : events) {
            types.insert(e.type);
            CHECK(e.payloadJson.find(root.path()) == std::string::npos);
        }
        CHECK(types.count("game.added"));
        CHECK(types.count("game.removed"));
        CHECK(types.count("scan.finished") || types.count("library.reconciled"));
        service.stop();
    }

    section("  restart preserves identity and overrides");
    {
        LibraryService service(config);
        CHECK(service.start());
        CHECK(settle(service));
        auto games = gamesByRel(service);
        CHECK_EQ(games["Alpha Renamed"].id, alphaId);
        CHECK_EQ(games["Twins"].id, twinsId);
        CHECK_EQ(games["Twins"].state, std::string("READY"));
        const auto twins = service.getGame(twinsId);
        CHECK(twins && twins->value(QStringLiteral("user_main_candidate")).toInteger() == pick);
        const QJsonObject db = service.health().value(QStringLiteral("db")).toObject();
        CHECK_EQ(db.value(QStringLiteral("state")).toString(), QStringLiteral("OK"));

        section("  storage unavailable never removes games");
        fs::rename(root.path(), root.path() + ".away");
        CHECK(waitFor([&] { return !service.storageAvailable(); }, 10s));
        std::this_thread::sleep_for(500ms);
        games = gamesByRel(service);
        CHECK_EQ(games["Alpha Renamed"].state, std::string("READY"));
        CHECK(service.health().value(QStringLiteral("db")).toObject().value(QStringLiteral("dirty")).toBool());
        fs::rename(root.path() + ".away", root.path());
        CHECK(waitFor([&] { return service.storageAvailable(); }, 10s));
        CHECK(settle(service));
        games = gamesByRel(service);
        CHECK_EQ(games["Alpha Renamed"].id, alphaId);
        CHECK_EQ(games["Alpha Renamed"].state, std::string("READY"));
        service.stop();
    }
}

void testUnavailableRoot()
{
    section("absent root: daemon keeps running, nothing created");
    TempDir state("360io-state");
    TempDir holder;
    LibraryConfig config;
    config.rootPath = holder / "absent";
    config.databasePath = state / "library.db";
    config.mountPolicy = MountPolicy::AnyFilesystem;
    config.tick = 50ms;
    LibraryService service(config);
    CHECK(service.start());
    std::this_thread::sleep_for(300ms);
    CHECK(!service.storageAvailable());
    CHECK(!fs::exists(holder / "absent"));
    CHECK_EQ(service.health().value(QStringLiteral("storage")).toObject().value(QStringLiteral("state")).toString(),
             QStringLiteral("MOUNT_ABSENT"));
    service.stop();

    section("strict policy rejects a tmp directory");
    TempDir root;
    addGame(root, "Game", "Game.exe", u"Game");
    config.rootPath = root.path();
    config.mountPolicy = MountPolicy::Strict;
    config.databasePath = state / "strict.db";
    LibraryService strict(config);
    CHECK(strict.start());
    std::this_thread::sleep_for(300ms);
    CHECK(!strict.storageAvailable());
    CHECK(gamesByRel(strict).empty());
    strict.stop();
}

} // namespace

int main()
{
    section("service lifecycle: threadpool backend");
    testLifecycle(IoBackendPreference::ThreadPool, 0);
    section("service lifecycle: auto backend (io_uring when available)");
    testLifecycle(IoBackendPreference::Auto, 0);
    section("service lifecycle: io_uring unavailable (EPERM) -> fallback");
    testLifecycle(IoBackendPreference::Auto, -EPERM);
    testUnavailableRoot();
    return finish("tst_library_service");
}
