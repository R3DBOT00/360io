// SQLite persistence: WAL, schema creation and forward migration, future
// version, corruption recovery, crash recovery, identity, user overrides,
// tombstones and the event log. Databases live in mkdtemp() directories.
#include "test_support.hpp"

#include "library_store.hpp"

#include <QJsonArray>

#include <sqlite3.h>

using namespace threesixty::daemon::library;
using namespace libtest;

namespace {

std::string pragmaText(const std::string &path, const char *sql)
{
    sqlite3 *db = nullptr;
    std::string out;
    if (sqlite3_open_v2(path.c_str(), &db, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK) {
        sqlite3_stmt *stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
            const auto *text = sqlite3_column_text(stmt, 0);
            out = text != nullptr ? reinterpret_cast<const char *>(text) : "";
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    return out;
}

void execRaw(const std::string &path, const char *sql)
{
    sqlite3 *db = nullptr;
    sqlite3_open(path.c_str(), &db);
    char *err = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        std::fprintf(stderr, "execRaw failed: %s\n", err != nullptr ? err : "?");
        sqlite3_free(err);
    }
    sqlite3_close(db);
}

InstallScanResult directoryResult(const std::string &rel, const std::string &handle, std::uint64_t ino,
                                  std::vector<std::string> exes, std::optional<std::size_t> main,
                                  GameState state)
{
    InstallScanResult r;
    r.key.kind = InstallKind::Directory;
    r.key.relPath = rel;
    r.generation = 1;
    r.identity.handle = handle;
    r.identity.ino = ino;
    r.state = state;
    r.reason = state == GameState::Ambiguous ? "AMBIGUOUS" : "";
    r.displayName = rel;
    r.displayNameSource = "directory";
    int score = 60;
    for (const auto &exe : exes) {
        ExeCandidate c;
        c.relPath = exe;
        c.size = 1000;
        c.pe.validPe = true;
        c.pe.machine = 0x8664;
        c.score = score;
        score -= 5;
        r.candidates.push_back(c);
    }
    r.mainCandidate = main;
    return r;
}

std::string onlyGameId(const LibraryStore &store)
{
    const QJsonArray games = store.listGames({}).value(QStringLiteral("games")).toArray();
    return games.isEmpty() ? std::string() : games.first().toObject().value(QStringLiteral("game_id")).toString().toStdString();
}

void testCreateAndWal()
{
    section("create, WAL, schema version");
    TempDir dir;
    const std::string path = dir / "library.db";
    {
        LibraryStore store;
        const auto report = store.open(path);
        CHECK(report.state == LibraryStore::OpenState::Created);
        CHECK(report.needsFullReconcile);
        CHECK(store.dirty());
        CHECK_EQ(store.librarySeq(), std::int64_t(0));
        store.setDirty(false);
        store.close(true);
    }
    CHECK_EQ(pragmaText(path, "PRAGMA journal_mode"), std::string("wal"));
    CHECK_EQ(pragmaText(path, "PRAGMA user_version"), std::to_string(kSchemaVersion));
    CHECK_EQ(pragmaText(path, "PRAGMA application_id"), std::to_string(kApplicationId));
    CHECK_EQ(pragmaText(path, "SELECT count(*) FROM sqlite_master WHERE name='install_relpath'"), std::string("1"));
    {
        LibraryStore store;
        const auto report = store.open(path);
        CHECK(report.state == LibraryStore::OpenState::Ok);
        CHECK(!report.needsFullReconcile); // clean shutdown, not dirty
        CHECK_EQ(report.migratedFrom, 0);
    }
}

void testMigration()
{
    section("forward migration v1 -> current with VACUUM INTO backup");
    TempDir dir;
    const std::string path = dir / "library.db";
    std::string gameId;
    {
        LibraryStore store;
        store.open(path);
        store.applyScanResult(directoryResult("Game", "h1", 11, {"Game.exe"}, 0, GameState::Ready), "fs");
        gameId = onlyGameId(store);
        store.close(true);
    }
    // Downgrade to the v1 layout.
    execRaw(path, "DROP INDEX install_relpath; DROP INDEX library_event_game; PRAGMA user_version=1;");
    CHECK_EQ(pragmaText(path, "PRAGMA user_version"), std::string("1"));
    {
        LibraryStore store;
        const auto report = store.open(path);
        CHECK(report.state == LibraryStore::OpenState::Ok);
        CHECK_EQ(report.migratedFrom, 1);
        CHECK_EQ(report.migrationBackupName, std::string("library.db.pre-v2"));
        CHECK(store.getGame(gameId).has_value()); // data preserved
        store.close(true);
    }
    CHECK(fs::exists(dir / "library.db.pre-v2"));
    CHECK_EQ(pragmaText(dir / "library.db.pre-v2", "PRAGMA user_version"), std::string("1"));
    CHECK_EQ(pragmaText(path, "PRAGMA user_version"), std::to_string(kSchemaVersion));
    CHECK_EQ(pragmaText(path, "SELECT count(*) FROM sqlite_master WHERE name='install_relpath'"), std::string("1"));
}

void testFutureAndCorrupt()
{
    section("future version -> read-only; corruption -> recreate");
    TempDir dir;
    const std::string path = dir / "library.db";
    {
        LibraryStore store;
        store.open(path);
        store.applyScanResult(directoryResult("Game", "h1", 11, {"Game.exe"}, 0, GameState::Ready), "fs");
        store.close(true);
    }
    execRaw(path, "PRAGMA user_version=99;");
    {
        LibraryStore store;
        const auto report = store.open(path);
        CHECK(report.state == LibraryStore::OpenState::FutureVersion);
        CHECK(store.readOnly());
        CHECK(!onlyGameId(store).empty()); // still readable through the API side
        const auto events = store.applyScanResult(
            directoryResult("Other", "h2", 12, {"O.exe"}, 0, GameState::Ready), "fs");
        CHECK(events.empty()); // no writes
    }
    CHECK_EQ(pragmaText(path, "PRAGMA user_version"), std::string("99"));

    const std::string corrupt = dir / "corrupt.db";
    writeFile(corrupt, std::string(8192, '\x5A'));
    {
        LibraryStore store;
        const auto report = store.open(corrupt);
        CHECK(report.state == LibraryStore::OpenState::Recreated);
        CHECK(report.needsFullReconcile);
        CHECK(report.corruptBackupName.rfind("corrupt.db.corrupt-", 0) == 0);
        CHECK(report.corruptBackupName.find('/') == std::string::npos);
        CHECK(fs::exists(dir / report.corruptBackupName));
    }
    // Foreign SQLite database (other application_id) is not adopted.
    const std::string foreign = dir / "foreign.db";
    execRaw(foreign, "PRAGMA application_id=1234; CREATE TABLE x(y);");
    {
        LibraryStore store;
        CHECK(store.open(foreign).state == LibraryStore::OpenState::Recreated);
    }
}

void testCrashRecovery()
{
    section("crash recovery: SCANNING reset, CRASHED runs, uncommitted txn");
    TempDir dir;
    const std::string path = dir / "library.db";
    std::string gameId;
    {
        LibraryStore store;
        store.open(path);
        store.setDirty(false);
        store.applyScanResult(directoryResult("Game", "h1", 11, {"Game.exe"}, 0, GameState::Ready), "fs");
        gameId = onlyGameId(store);
        store.beginRun("FULL"); // never finished
        store.close(false);
    }
    execRaw(path, "UPDATE game SET state='SCANNING'; UPDATE install SET state='SCANNING';");
    {
        LibraryStore store;
        const auto report = store.open(path);
        CHECK(report.state == LibraryStore::OpenState::Ok);
        CHECK_EQ(report.crashedRuns, 1);
        CHECK(report.resetScanning >= 1);
        CHECK(report.needsFullReconcile);
        const auto game = store.getGame(gameId);
        CHECK(game && game->value(QStringLiteral("state")).toString() == QStringLiteral("DISCOVERED"));
        // Simulated crash in the middle of a write transaction.
        const std::int64_t seq = store.librarySeq();
        store.debugBeginTransaction();
        store.close(false);
        LibraryStore again;
        CHECK(again.open(path).state == LibraryStore::OpenState::Ok);
        CHECK_EQ(again.librarySeq(), seq);
    }
    CHECK_EQ(pragmaText(path, "SELECT count(*) FROM game WHERE state='SCANNING'"), std::string("0"));
}

void testCatalog()
{
    section("catalog: states, overrides, identity, tombstones, events");
    TempDir dir;
    LibraryStore store;
    store.open(dir / "library.db");
    store.setDirty(false);

    // AMBIGUOUS exposes candidates; READY exposes a main executable.
    auto events = store.applyScanResult(
        directoryResult("Twins", "hT", 21, {"A.exe", "B.exe"}, std::nullopt, GameState::Ambiguous), "fs");
    CHECK(!events.empty());
    CHECK_EQ(events.front().type, std::string("game.added"));
    const std::string twins = onlyGameId(store);
    auto game = store.getGame(twins);
    CHECK(game.has_value());
    if (!game) {
        return;
    }
    CHECK_EQ(game->value(QStringLiteral("state")).toString(), QStringLiteral("AMBIGUOUS"));
    const QJsonObject install = game->value(QStringLiteral("installs")).toArray().first().toObject();
    const QJsonArray candidates = install.value(QStringLiteral("candidates")).toArray();
    CHECK(candidates.size() >= 2);
    const std::int64_t pick = candidates.at(1).toObject().value(QStringLiteral("candidate_id")).toInteger();

    // User choice resolves ambiguity and survives rescans (§10 invariant 9).
    std::string error;
    events = store.setUserMainExecutable(twins, pick, error);
    CHECK(error.empty());
    game = store.getGame(twins);
    CHECK_EQ(game->value(QStringLiteral("state")).toString(), QStringLiteral("READY"));
    store.applyScanResult(
        directoryResult("Twins", "hT", 21, {"A.exe", "B.exe"}, std::nullopt, GameState::Ambiguous), "fs");
    game = store.getGame(twins);
    CHECK_EQ(game->value(QStringLiteral("state")).toString(), QStringLiteral("READY"));
    CHECK_EQ(game->value(QStringLiteral("user_main_candidate")).toInteger(), pick);
    store.setUserMainExecutable(twins, 999999, error);
    CHECK(!error.empty());
    error.clear();
    store.setUserMainExecutable("no-such-game", std::nullopt, error);
    CHECK(!error.empty());

    // Rename: same handle, new rel_path -> same game_id.
    store.applyScanResult(
        directoryResult("Twins Renamed", "hT", 21, {"A.exe", "B.exe"}, std::nullopt, GameState::Ambiguous), "fs");
    CHECK_EQ(onlyGameId(store), twins);
    const QJsonObject renamed = store.getGame(twins)->value(QStringLiteral("installs")).toArray().first().toObject();
    CHECK_EQ(renamed.value(QStringLiteral("rel_path")).toString(), QStringLiteral("Twins Renamed"));
    CHECK_EQ(store.getGame(twins)->value(QStringLiteral("user_main_candidate")).toInteger(), pick);

    // Removal only via applyRemovals, then restore with the same identity.
    events = store.applyRemovals({});
    bool removedEvent = false;
    for (const auto &e : events) {
        removedEvent = removedEvent || e.type == "game.removed";
    }
    CHECK(removedEvent);
    CHECK_EQ(store.getGame(twins)->value(QStringLiteral("state")).toString(), QStringLiteral("REMOVED"));
    events = store.applyScanResult(
        directoryResult("Twins Renamed", "hT", 21, {"A.exe", "B.exe"}, std::nullopt, GameState::Ambiguous), "fs");
    bool restored = false;
    for (const auto &e : events) {
        restored = restored || e.type == "game.restored";
    }
    CHECK(restored);
    CHECK_EQ(store.getGame(twins)->value(QStringLiteral("state")).toString(), QStringLiteral("READY"));

    // Transition to STABILIZING (event during copy) and back.
    const auto rows = store.activeInstalls();
    CHECK_EQ(rows.size(), std::size_t(1));
    events = store.transitionInstall(rows.front().installId, {GameState::Ready}, GameState::Stabilizing,
                                     "COPY_IN_PROGRESS");
    CHECK_EQ(store.getGame(twins)->value(QStringLiteral("state")).toString(), QStringLiteral("STABILIZING"));
    CHECK_EQ(store.getGame(twins)->value(QStringLiteral("state_reason")).toString(), QStringLiteral("COPY_IN_PROGRESS"));
    // Transition from a state not in `from` is a no-op.
    events = store.transitionInstall(rows.front().installId, {GameState::Error}, GameState::Ready, "");
    CHECK(events.empty());

    // Steam: same appid in two libraries -> one game, two installs.
    for (const char *lib : {"LibA", "LibB"}) {
        InstallScanResult s;
        s.key.kind = InstallKind::Steam;
        s.key.libraryRelPath = lib;
        s.key.steamAppId = 440;
        s.key.relPath = std::string(lib) + "/steamapps/common/TF2";
        s.steam = SteamInfo{};
        s.steam->appId = 440;
        s.steam->name = "Team Fortress 2";
        s.steam->stateFlags = 4;
        s.state = GameState::Ready;
        s.displayName = "Team Fortress 2";
        s.displayNameSource = "steam_acf";
        ExeCandidate c;
        c.relPath = "hl2.exe";
        c.score = 50;
        s.candidates.push_back(c);
        s.mainCandidate = 0;
        store.applyScanResult(s, "fs");
    }
    ListGamesQuery steamOnly;
    steamOnly.kind = InstallKind::Steam;
    const QJsonArray steamGames = store.listGames(steamOnly).value(QStringLiteral("games")).toArray();
    CHECK_EQ(steamGames.size(), qsizetype(1));
    if (!steamGames.isEmpty()) {
        const auto tf2 = store.getGame(steamGames.first().toObject().value(QStringLiteral("game_id")).toString().toStdString());
        CHECK(tf2 && tf2->value(QStringLiteral("installs")).toArray().size() == 2);
        CHECK(tf2 && tf2->value(QStringLiteral("steam_appid")).toInteger() == 440);
    }

    // State filter + paging.
    ListGamesQuery ready;
    ready.states = {GameState::Ready};
    CHECK_EQ(store.listGames(ready).value(QStringLiteral("games")).toArray().size(), qsizetype(1));
    ListGamesQuery page;
    page.limit = 1;
    const QJsonObject first = store.listGames(page);
    CHECK_EQ(first.value(QStringLiteral("games")).toArray().size(), qsizetype(1));
    CHECK(!first.value(QStringLiteral("next_cursor")).isNull());

    // Event log: seq strictly increasing, since_seq, resync outside retention.
    bool resync = true;
    const auto all = store.eventsSince(0, resync);
    CHECK(!resync);
    CHECK(!all.empty());
    for (std::size_t i = 1; i < all.size(); ++i) {
        CHECK(all[i].seq > all[i - 1].seq);
    }
    CHECK_EQ(all.back().seq, store.librarySeq());
    for (const auto &e : all) {
        CHECK(e.payloadJson.find(dir.path()) == std::string::npos); // no absolute paths
    }
    store.purge(std::chrono::seconds(30 * 24 * 3600), 2);
    store.eventsSince(0, resync);
    CHECK(resync);
    const auto tail = store.eventsSince(store.librarySeq() - 1, resync);
    CHECK(!resync);
    CHECK_EQ(tail.size(), std::size_t(1));

    // Tombstone purge after retention.
    store.applyRemovals({});
    store.purge(std::chrono::seconds(-1), 10000);
    CHECK(store.listGames({}).value(QStringLiteral("games")).toArray().isEmpty() ||
          store.countsByState()["REMOVED"] == 0);
}

} // namespace

int main()
{
    testCreateAndWal();
    testMigration();
    testFutureAndCorrupt();
    testCrashRecovery();
    testCatalog();
    return finish("tst_library_store");
}
