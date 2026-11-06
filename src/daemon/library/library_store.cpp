#include "library_store.hpp"

#include "pe_parser.hpp"
#include "sanitize.hpp"

#include <QDebug>
#include <QJsonArray>
#include <QJsonDocument>
#include <QString>

#include <sqlite3.h>

#include <cstdio>
#include <stdexcept>

#include <sys/random.h>
#include <unistd.h>

namespace threesixty::daemon::library {

namespace {

struct DbError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

class Stmt
{
public:
    Stmt(sqlite3 *db, const char *sql)
        : m_db(db)
    {
        if (sqlite3_prepare_v2(db, sql, -1, &m_stmt, nullptr) != SQLITE_OK) {
            throw DbError(sqlite3_errmsg(db));
        }
    }
    ~Stmt() { sqlite3_finalize(m_stmt); }
    Stmt(const Stmt &) = delete;
    Stmt &operator=(const Stmt &) = delete;

    Stmt &bind(int index, std::int64_t value)
    {
        sqlite3_bind_int64(m_stmt, index, value);
        return *this;
    }
    Stmt &bindText(int index, const std::string &value)
    {
        sqlite3_bind_text(m_stmt, index, value.data(), static_cast<int>(value.size()),
                          SQLITE_TRANSIENT);
        return *this;
    }
    Stmt &bindBlob(int index, const std::string &value)
    {
        sqlite3_bind_blob(m_stmt, index, value.data(), static_cast<int>(value.size()),
                          SQLITE_TRANSIENT);
        return *this;
    }
    Stmt &bindTextOrNull(int index, const std::string &value)
    {
        if (value.empty()) {
            sqlite3_bind_null(m_stmt, index);
            return *this;
        }
        return bindText(index, value);
    }
    Stmt &bindBlobOrNull(int index, const std::string &value)
    {
        if (value.empty()) {
            sqlite3_bind_null(m_stmt, index);
            return *this;
        }
        return bindBlob(index, value);
    }
    Stmt &bindNull(int index)
    {
        sqlite3_bind_null(m_stmt, index);
        return *this;
    }

    bool step()
    {
        const int rc = sqlite3_step(m_stmt);
        if (rc == SQLITE_ROW) {
            return true;
        }
        if (rc == SQLITE_DONE) {
            return false;
        }
        throw DbError(sqlite3_errmsg(m_db));
    }
    void run()
    {
        step();
    }
    void reset()
    {
        sqlite3_reset(m_stmt);
        sqlite3_clear_bindings(m_stmt);
    }

    std::int64_t i64(int col) const { return sqlite3_column_int64(m_stmt, col); }
    bool isNull(int col) const { return sqlite3_column_type(m_stmt, col) == SQLITE_NULL; }
    std::string text(int col) const
    {
        const auto *p = sqlite3_column_blob(m_stmt, col);
        const int n = sqlite3_column_bytes(m_stmt, col);
        return p != nullptr ? std::string(static_cast<const char *>(p), static_cast<std::size_t>(n))
                            : std::string();
    }

private:
    sqlite3 *m_db;
    sqlite3_stmt *m_stmt = nullptr;
};

int libnameCollation(void *, int la, const void *a, int lb, const void *b)
{
    const QString qa = QString::fromUtf8(static_cast<const char *>(a), la)
                           .normalized(QString::NormalizationForm_C)
                           .toCaseFolded();
    const QString qb = QString::fromUtf8(static_cast<const char *>(b), lb)
                           .normalized(QString::NormalizationForm_C)
                           .toCaseFolded();
    return qa.compare(qb);
}

std::string toJson(const QJsonObject &object)
{
    return QJsonDocument(object).toJson(QJsonDocument::Compact).toStdString();
}

QString qs(const std::string &s) { return QString::fromStdString(s); }

const char *kSchemaSql = R"SQL(
CREATE TABLE meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE game (
  game_id              TEXT PRIMARY KEY,
  state                TEXT NOT NULL CHECK (state IN
    ('DISCOVERED','STABILIZING','SCANNING','READY','AMBIGUOUS','ERROR','REMOVED')),
  state_reason         TEXT,
  display_name         TEXT NOT NULL,
  display_name_source  TEXT NOT NULL,
  steam_appid          INTEGER,
  user_display_name    TEXT,
  user_main_candidate  INTEGER REFERENCES exe_candidate(candidate_id) ON DELETE SET NULL,
  possible_duplicate_of TEXT REFERENCES game(game_id),
  created_at           INTEGER NOT NULL,
  updated_at           INTEGER NOT NULL,
  removed_at           INTEGER,
  seq                  INTEGER NOT NULL
);
CREATE TABLE install (
  install_id        INTEGER PRIMARY KEY,
  game_id           TEXT NOT NULL REFERENCES game(game_id),
  kind              TEXT NOT NULL CHECK (kind IN ('steam','directory')),
  fs_uuid           TEXT NOT NULL,
  dir_handle        BLOB,
  ino               INTEGER NOT NULL,
  btime_ns          INTEGER,
  rel_path          BLOB NOT NULL,
  library_rel_path  BLOB,
  steam_appid       INTEGER,
  steam_state_flags INTEGER,
  steam_last_updated INTEGER,
  steam_name        TEXT,
  watch_coverage    TEXT NOT NULL DEFAULT 'FULL' CHECK (watch_coverage IN ('FULL','PARTIAL','NONE')),
  scan_generation   INTEGER NOT NULL DEFAULT 0,
  last_scanned_at   INTEGER,
  error_count       INTEGER NOT NULL DEFAULT 0,
  next_retry_at     INTEGER,
  removed_at        INTEGER,
  state             TEXT NOT NULL DEFAULT 'DISCOVERED',
  state_reason      TEXT,
  display_name      TEXT NOT NULL DEFAULT '',
  display_name_source TEXT NOT NULL DEFAULT 'directory',
  main_candidate_id INTEGER REFERENCES exe_candidate(candidate_id) ON DELETE SET NULL,
  root_mtime_ns     INTEGER NOT NULL DEFAULT 0,
  ruleset_version   INTEGER,
  scorer_version    INTEGER,
  candidates_truncated INTEGER NOT NULL DEFAULT 0,
  entries_truncated INTEGER NOT NULL DEFAULT 0,
  UNIQUE (fs_uuid, dir_handle),
  UNIQUE (fs_uuid, library_rel_path, steam_appid)
);
CREATE TABLE exe_candidate (
  candidate_id    INTEGER PRIMARY KEY,
  install_id      INTEGER NOT NULL REFERENCES install(install_id) ON DELETE CASCADE,
  rel_path        BLOB NOT NULL,
  size            INTEGER NOT NULL,
  mtime_ns        INTEGER NOT NULL,
  ino             INTEGER NOT NULL,
  machine         TEXT,
  subsystem       INTEGER,
  pe_timestamp    INTEGER,
  characteristics INTEGER,
  product_name    TEXT,
  file_description TEXT,
  company_name    TEXT,
  product_version TEXT,
  file_version    TEXT,
  original_filename TEXT,
  internal_name   TEXT,
  excluded_by     TEXT,
  score           INTEGER,
  features_json   TEXT,
  parse_error     TEXT,
  UNIQUE (install_id, rel_path)
);
CREATE TABLE cover (
  game_id      TEXT NOT NULL REFERENCES game(game_id),
  variant      TEXT NOT NULL,
  source       TEXT NOT NULL,
  source_mtime_ns INTEGER NOT NULL,
  width INTEGER NOT NULL, height INTEGER NOT NULL,
  PRIMARY KEY (game_id, variant)
);
CREATE TABLE scan_run (
  run_id      INTEGER PRIMARY KEY,
  kind        TEXT NOT NULL,
  started_at  INTEGER NOT NULL,
  finished_at INTEGER,
  outcome     TEXT
);
CREATE TABLE library_event (
  seq       INTEGER PRIMARY KEY,
  at        INTEGER NOT NULL,
  type      TEXT NOT NULL,
  game_id   TEXT,
  payload   TEXT NOT NULL
);
CREATE INDEX game_state   ON game(state);
CREATE INDEX game_appid   ON game(steam_appid);
CREATE INDEX install_game ON install(game_id);
INSERT INTO meta(key, value) VALUES
  ('dirty', '1'), ('library_seq', '0'), ('ruleset_version', '1'), ('scorer_version', '1'),
  ('fs_uuid', '');
)SQL";

InstallRow readInstallRow(const Stmt &s)
{
    // Column order used by kInstallColumns.
    InstallRow row;
    row.installId = s.i64(0);
    row.gameId = s.text(1);
    row.kind = s.text(2) == "steam" ? InstallKind::Steam : InstallKind::Directory;
    row.relPath = s.text(3);
    row.state = gameStateFromName(s.text(4)).value_or(GameState::Discovered);
    row.removed = !s.isNull(5);
    const std::string coverage = s.text(6);
    row.coverage = coverage == "PARTIAL" ? WatchCoverage::Partial
        : coverage == "NONE"            ? WatchCoverage::None
                                        : WatchCoverage::Full;
    row.rootMtimeNs = s.i64(7);
    row.steamAppId = static_cast<std::uint32_t>(s.i64(8));
    row.libraryRelPath = s.text(9);
    row.handle = s.text(10);
    return row;
}

constexpr const char *kInstallColumns =
    "install_id, game_id, kind, rel_path, state, removed_at, watch_coverage, root_mtime_ns, "
    "COALESCE(steam_appid, 0), COALESCE(library_rel_path, x''), COALESCE(dir_handle, x'')";

} // namespace

struct LibraryStore::Txn {
    explicit Txn(sqlite3 *db)
        : db(db)
    {
        if (sqlite3_exec(db, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) != SQLITE_OK) {
            throw DbError(sqlite3_errmsg(db));
        }
    }
    ~Txn()
    {
        if (!committed) {
            sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
        }
    }
    void commit()
    {
        if (sqlite3_exec(db, "COMMIT", nullptr, nullptr, nullptr) != SQLITE_OK) {
            throw DbError(sqlite3_errmsg(db));
        }
        committed = true;
    }
    sqlite3 *db;
    bool committed = false;
};

std::string makeUuidV4()
{
    unsigned char b[16] = {};
    std::size_t got = 0;
    while (got < sizeof b) {
        const ssize_t n = ::getrandom(b + got, sizeof b - got, 0);
        if (n > 0) {
            got += static_cast<std::size_t>(n);
        }
    }
    b[6] = static_cast<unsigned char>((b[6] & 0x0F) | 0x40);
    b[8] = static_cast<unsigned char>((b[8] & 0x3F) | 0x80);
    char out[37];
    std::snprintf(out, sizeof out,
                  "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", b[0], b[1],
                  b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14],
                  b[15]);
    return out;
}

LibraryStore::~LibraryStore()
{
    close(false);
}

const char *LibraryStore::openStateName(OpenState state)
{
    switch (state) {
    case OpenState::Ok:
        return "OK";
    case OpenState::Created:
        return "CREATED";
    case OpenState::Recreated:
        return "RECREATED_AFTER_CORRUPTION";
    case OpenState::FutureVersion:
        return "DB_FROM_FUTURE";
    case OpenState::Failed:
        return "FAILED";
    }
    return "UNKNOWN";
}

bool LibraryStore::exec(const char *sql) const
{
    char *error = nullptr;
    if (sqlite3_exec(m_db, sql, nullptr, nullptr, &error) != SQLITE_OK) {
        qWarning().noquote() << "library: sqlite:" << (error != nullptr ? error : "?");
        sqlite3_free(error);
        return false;
    }
    return true;
}

bool LibraryStore::openHandles(const std::string &path, bool readOnly, std::string &error)
{
    const int flags = (readOnly ? SQLITE_OPEN_READONLY : SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE) |
        SQLITE_OPEN_NOMUTEX;
    if (sqlite3_open_v2(path.c_str(), &m_db, flags, nullptr) != SQLITE_OK) {
        error = m_db != nullptr ? sqlite3_errmsg(m_db) : "open failed";
        closeHandles();
        return false;
    }
    sqlite3_busy_timeout(m_db, 5000);
    sqlite3_create_collation(m_db, "LIBNAME", SQLITE_UTF8, nullptr, libnameCollation);
    m_readOnly = readOnly;
    return true;
}

void LibraryStore::closeHandles()
{
    if (m_reader != nullptr) {
        sqlite3_close_v2(m_reader);
        m_reader = nullptr;
    }
    if (m_db != nullptr) {
        sqlite3_close_v2(m_db);
        m_db = nullptr;
    }
}

bool LibraryStore::createSchema()
{
    try {
        Txn txn(m_db);
        if (sqlite3_exec(m_db, kSchemaSql, nullptr, nullptr, nullptr) != SQLITE_OK) {
            throw DbError(sqlite3_errmsg(m_db));
        }
        const std::string pragmas = "PRAGMA application_id=" + std::to_string(kApplicationId) +
            "; PRAGMA user_version=1;";
        if (sqlite3_exec(m_db, pragmas.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK) {
            throw DbError(sqlite3_errmsg(m_db));
        }
        txn.commit();
        return true;
    } catch (const DbError &error) {
        qWarning().noquote() << "library: schema creation failed:" << error.what();
        return false;
    }
}

// Forward-only migrations: kMigrations[i] upgrades user_version i+1 -> i+2.
const char *const kMigrations[] = {
    // v2: rel_path lookups of active installs (event -> install key) and
    // per-game event scans no longer walk the whole table.
    "CREATE INDEX install_relpath ON install(rel_path) WHERE removed_at IS NULL;"
    "CREATE INDEX library_event_game ON library_event(game_id);",
};
static_assert(std::size(kMigrations) == kSchemaVersion - 1, "one migration per schema bump");

bool LibraryStore::migrate(int from, bool backup, std::string &backupName, std::string &error)
{
    for (int version = from; version < kSchemaVersion; ++version) {
        const int target = version + 1;
        if (backup) {
            const std::string copy = m_path + ".pre-v" + std::to_string(target);
            std::remove(copy.c_str());
            try {
                Stmt vacuum(m_db, "VACUUM INTO ?");
                vacuum.bindText(1, copy).run();
            } catch (const DbError &e) {
                error = "backup before migration to v" + std::to_string(target) + " failed: " + e.what();
                return false;
            }
            const std::size_t slash = copy.rfind('/');
            backupName = slash == std::string::npos ? copy : copy.substr(slash + 1);
        }
        try {
            Txn txn(m_db);
            if (sqlite3_exec(m_db, kMigrations[version - 1], nullptr, nullptr, nullptr) != SQLITE_OK) {
                throw DbError(sqlite3_errmsg(m_db));
            }
            const std::string pragma = "PRAGMA user_version=" + std::to_string(target);
            if (sqlite3_exec(m_db, pragma.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK) {
                throw DbError(sqlite3_errmsg(m_db));
            }
            txn.commit();
        } catch (const DbError &e) {
            error = "migration to v" + std::to_string(target) + " failed: " + e.what();
            return false;
        }
    }
    return true;
}

LibraryStore::OpenReport LibraryStore::open(const std::string &path)
{
    OpenReport report;
    m_path = path;
    std::string error;
    if (!openHandles(path, false, error)) {
        report.detail = error;
        return report;
    }

    // Integrity + ownership check; anything unreadable is treated as corrupt.
    bool healthy = true;
    int appId = 0;
    int version = 0;
    try {
        Stmt check(m_db, "PRAGMA quick_check");
        healthy = check.step() && check.text(0) == "ok";
        Stmt app(m_db, "PRAGMA application_id");
        appId = app.step() ? static_cast<int>(app.i64(0)) : 0;
        Stmt ver(m_db, "PRAGMA user_version");
        version = ver.step() ? static_cast<int>(ver.i64(0)) : 0;
        if (appId != 0 && appId != kApplicationId) {
            healthy = false;
        }
    } catch (const DbError &) {
        healthy = false;
    }

    bool recreated = false;
    if (!healthy) {
        closeHandles();
        const std::string suffix = ".corrupt-" + std::to_string(unixMillisNow());
        for (const char *ext : {"", "-wal", "-shm"}) {
            const std::string from = path + ext;
            const std::string to = path + suffix + ext;
            std::rename(from.c_str(), to.c_str());
        }
        const std::size_t slash = path.rfind('/');
        report.corruptBackupName =
            (slash == std::string::npos ? path : path.substr(slash + 1)) + suffix;
        qWarning().noquote() << "library: database failed integrity check; recreated, previous "
                                "file kept as"
                             << report.corruptBackupName.c_str();
        if (!openHandles(path, false, error)) {
            report.detail = error;
            return report;
        }
        recreated = true;
        version = 0;
    }

    if (version > kSchemaVersion) {
        closeHandles();
        if (!openHandles(path, true, error)) {
            report.detail = error;
            return report;
        }
        if (sqlite3_open_v2(path.c_str(), &m_reader, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX,
                            nullptr) == SQLITE_OK) {
            sqlite3_create_collation(m_reader, "LIBNAME", SQLITE_UTF8, nullptr, libnameCollation);
        }
        report.state = OpenState::FutureVersion;
        report.detail = "schema version " + std::to_string(version) + " is newer than supported " +
            std::to_string(kSchemaVersion);
        return report;
    }

    if (!exec("PRAGMA journal_mode=WAL") || !exec("PRAGMA synchronous=FULL") ||
        !exec("PRAGMA foreign_keys=ON")) {
        report.detail = "pragma failed";
        closeHandles();
        return report;
    }

    if (version == 0) {
        if (!createSchema()) {
            report.detail = "schema creation failed";
            closeHandles();
            return report;
        }
        if (!migrate(1, false, report.migrationBackupName, report.detail)) {
            closeHandles();
            return report;
        }
        report.state = recreated ? OpenState::Recreated : OpenState::Created;
        if (recreated) {
            report.detail = "previous database was corrupt; user overrides from it are lost";
        }
    } else {
        if (version < kSchemaVersion) {
            report.migratedFrom = version;
            if (!migrate(version, true, report.migrationBackupName, report.detail)) {
                closeHandles();
                return report;
            }
        }
        report.state = OpenState::Ok;
    }

    // Crash recovery (§13).
    try {
        Txn txn(m_db);
        Stmt resetInstalls(m_db, "UPDATE install SET state='DISCOVERED' WHERE state='SCANNING'");
        resetInstalls.run();
        report.resetScanning = sqlite3_changes(m_db);
        Stmt resetGames(m_db, "UPDATE game SET state='DISCOVERED' WHERE state='SCANNING'");
        resetGames.run();
        Stmt crashed(m_db,
                     "UPDATE scan_run SET outcome='CRASHED', finished_at=? WHERE finished_at IS NULL");
        crashed.bind(1, unixMillisNow()).run();
        report.crashedRuns = sqlite3_changes(m_db);
        txn.commit();
    } catch (const DbError &e) {
        report.state = OpenState::Failed;
        report.detail = e.what();
        closeHandles();
        return report;
    }
    report.needsFullReconcile = dirty() || report.crashedRuns > 0 ||
        report.state == OpenState::Created || report.state == OpenState::Recreated;

    if (sqlite3_open_v2(path.c_str(), &m_reader, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX,
                        nullptr) != SQLITE_OK) {
        report.state = OpenState::Failed;
        report.detail = "reader open failed";
        closeHandles();
        return report;
    }
    sqlite3_busy_timeout(m_reader, 5000);
    sqlite3_create_collation(m_reader, "LIBNAME", SQLITE_UTF8, nullptr, libnameCollation);
    return report;
}

void LibraryStore::close(bool cleanShutdown)
{
    if (m_db != nullptr && cleanShutdown && !m_readOnly) {
        checkpoint(true);
    }
    closeHandles();
}

void LibraryStore::checkpoint(bool truncate)
{
    std::lock_guard dbLock(m_dbMutex);
    if (m_db == nullptr || m_readOnly) {
        return;
    }
    sqlite3_wal_checkpoint_v2(m_db, nullptr,
                              truncate ? SQLITE_CHECKPOINT_TRUNCATE : SQLITE_CHECKPOINT_PASSIVE,
                              nullptr, nullptr);
}

std::string LibraryStore::meta(const std::string &key) const
{
    std::lock_guard dbLock(m_dbMutex);
    try {
        Stmt s(m_db, "SELECT value FROM meta WHERE key=?");
        s.bindText(1, key);
        return s.step() ? s.text(0) : std::string();
    } catch (const DbError &) {
        return {};
    }
}

void LibraryStore::setMeta(const std::string &key, const std::string &value)
{
    std::lock_guard dbLock(m_dbMutex);
    if (m_readOnly) {
        return;
    }
    try {
        Stmt s(m_db, "INSERT INTO meta(key, value) VALUES(?, ?) "
                     "ON CONFLICT(key) DO UPDATE SET value=excluded.value");
        s.bindText(1, key).bindText(2, value).run();
    } catch (const DbError &e) {
        qWarning().noquote() << "library: meta write failed:" << e.what();
    }
}

bool LibraryStore::dirty() const
{
    return meta("dirty") == "1";
}

void LibraryStore::setDirty(bool dirty)
{
    setMeta("dirty", dirty ? "1" : "0");
}

std::int64_t LibraryStore::librarySeq() const
{
    const std::string value = meta("library_seq");
    return value.empty() ? 0 : std::stoll(value);
}

std::int64_t LibraryStore::beginRun(const std::string &kind)
{
    std::lock_guard dbLock(m_dbMutex);
    if (m_readOnly) {
        return 0;
    }
    try {
        Stmt s(m_db, "INSERT INTO scan_run(kind, started_at) VALUES(?, ?)");
        s.bindText(1, kind).bind(2, unixMillisNow()).run();
        return sqlite3_last_insert_rowid(m_db);
    } catch (const DbError &e) {
        qWarning().noquote() << "library: beginRun failed:" << e.what();
        return 0;
    }
}

void LibraryStore::finishRun(std::int64_t runId, const std::string &outcome)
{
    std::lock_guard dbLock(m_dbMutex);
    if (m_readOnly || runId == 0) {
        return;
    }
    try {
        Stmt s(m_db, "UPDATE scan_run SET finished_at=?, outcome=? WHERE run_id=?");
        s.bind(1, unixMillisNow()).bindText(2, outcome).bind(3, runId).run();
    } catch (const DbError &e) {
        qWarning().noquote() << "library: finishRun failed:" << e.what();
    }
}

std::int64_t LibraryStore::nextSeq()
{
    Stmt up(m_db, "UPDATE meta SET value = CAST(value AS INTEGER) + 1 WHERE key='library_seq'");
    up.run();
    Stmt get(m_db, "SELECT CAST(value AS INTEGER) FROM meta WHERE key='library_seq'");
    get.step();
    return get.i64(0);
}

LibraryEvent LibraryStore::addEvent(const std::string &type, const std::string &gameId,
                                    const std::string &payloadJson)
{
    LibraryEvent event;
    event.seq = nextSeq();
    event.at = unixMillisNow();
    event.type = type;
    event.gameId = gameId;
    event.payloadJson = payloadJson;
    Stmt s(m_db, "INSERT INTO library_event(seq, at, type, game_id, payload) VALUES(?,?,?,?,?)");
    s.bind(1, event.seq).bind(2, event.at).bindText(3, type).bindTextOrNull(4, gameId)
        .bindText(5, payloadJson)
        .run();
    return event;
}

std::optional<InstallRow> LibraryStore::findInstall(const InstallKey &key,
                                                    const DirIdentity &identity,
                                                    const std::string &fsUuid) const
{
    std::lock_guard dbLock(m_dbMutex);
    try {
        const std::string base = std::string("SELECT ") + kInstallColumns + " FROM install WHERE ";
        const std::string order = " ORDER BY removed_at IS NOT NULL, install_id LIMIT 1";
        if (key.kind == InstallKind::Steam) {
            Stmt s(m_db, (base + "kind='steam' AND fs_uuid=? AND library_rel_path=? AND "
                                 "steam_appid=?" + order).c_str());
            s.bindText(1, fsUuid).bindBlob(2, key.libraryRelPath).bind(3, key.steamAppId);
            if (s.step()) {
                return readInstallRow(s);
            }
            return std::nullopt;
        }
        if (!identity.handle.empty()) {
            Stmt s(m_db, (base + "kind='directory' AND fs_uuid=? AND dir_handle=?" + order).c_str());
            s.bindText(1, fsUuid).bindBlob(2, identity.handle);
            if (s.step()) {
                return readInstallRow(s);
            }
            return std::nullopt;
        }
        if (identity.btimeNs != 0) {
            Stmt s(m_db, (base + "kind='directory' AND fs_uuid=? AND ino=? AND btime_ns=?" + order).c_str());
            s.bindText(1, fsUuid).bind(2, std::int64_t(identity.ino)).bind(3, identity.btimeNs);
            if (s.step()) {
                return readInstallRow(s);
            }
            return std::nullopt;
        }
        Stmt s(m_db, (base + "kind='directory' AND fs_uuid=? AND ino=? AND rel_path=?" + order).c_str());
        s.bindText(1, fsUuid).bind(2, std::int64_t(identity.ino)).bindBlob(3, key.relPath);
        if (s.step()) {
            return readInstallRow(s);
        }
    } catch (const DbError &e) {
        qWarning().noquote() << "library: findInstall failed:" << e.what();
    }
    return std::nullopt;
}

std::optional<InstallRow> LibraryStore::findActiveInstallByRelPath(const std::string &relPath) const
{
    std::lock_guard dbLock(m_dbMutex);
    try {
        Stmt s(m_db, (std::string("SELECT ") + kInstallColumns +
                      " FROM install WHERE removed_at IS NULL AND rel_path=? LIMIT 1").c_str());
        s.bindBlob(1, relPath);
        if (s.step()) {
            return readInstallRow(s);
        }
    } catch (const DbError &) {
    }
    return std::nullopt;
}

std::vector<InstallRow> LibraryStore::activeInstalls() const
{
    std::lock_guard dbLock(m_dbMutex);
    std::vector<InstallRow> rows;
    try {
        Stmt s(m_db, (std::string("SELECT ") + kInstallColumns +
                      " FROM install WHERE removed_at IS NULL ORDER BY install_id").c_str());
        while (s.step()) {
            rows.push_back(readInstallRow(s));
        }
    } catch (const DbError &) {
    }
    return rows;
}

std::map<std::string, PreviousCandidate> LibraryStore::previousCandidates(std::int64_t installId) const
{
    std::lock_guard dbLock(m_dbMutex);
    std::map<std::string, PreviousCandidate> out;
    try {
        Stmt s(m_db, "SELECT rel_path, size, mtime_ns, ino, machine, subsystem, pe_timestamp, "
                     "characteristics, product_name, file_description, company_name, "
                     "product_version, file_version, original_filename, internal_name, parse_error "
                     "FROM exe_candidate WHERE install_id=?");
        s.bind(1, installId);
        while (s.step()) {
            PreviousCandidate c;
            c.size = static_cast<std::uint64_t>(s.i64(1));
            c.mtimeNs = s.i64(2);
            c.ino = static_cast<std::uint64_t>(s.i64(3));
            const std::string machine = s.text(4);
            c.pe.machine = machine == "amd64" ? 0x8664 : machine == "i386" ? 0x14C
                : machine == "arm64"                                        ? 0xAA64
                                                                             : 0;
            c.pe.validPe = true;
            c.pe.subsystem = static_cast<std::uint16_t>(s.i64(5));
            c.pe.timestamp = static_cast<std::uint32_t>(s.i64(6));
            c.pe.characteristics = static_cast<std::uint16_t>(s.i64(7));
            c.pe.isDll = (c.pe.characteristics & 0x2000) != 0;
            c.pe.productName = s.text(8);
            c.pe.fileDescription = s.text(9);
            c.pe.companyName = s.text(10);
            c.pe.productVersion = s.text(11);
            c.pe.fileVersion = s.text(12);
            c.pe.originalFilename = s.text(13);
            c.pe.internalName = s.text(14);
            c.pe.parseError = s.text(15);
            c.pe.hasVersionInfo = !c.pe.productName.empty() || !c.pe.fileDescription.empty();
            out.emplace(s.text(0), std::move(c));
        }
    } catch (const DbError &) {
    }
    return out;
}

std::string LibraryStore::createGame(GameState state, const std::string &name,
                                     const std::string &source, std::uint32_t steamAppId)
{
    const std::string gameId = makeUuidV4();
    const std::int64_t now = unixMillisNow();
    Stmt s(m_db, "INSERT INTO game(game_id, state, display_name, display_name_source, steam_appid, "
                 "created_at, updated_at, seq) VALUES(?,?,?,?,?,?,?,0)");
    s.bindText(1, gameId).bindText(2, gameStateName(state)).bindText(3, name).bindText(4, source);
    if (steamAppId != 0) {
        s.bind(5, steamAppId);
    } else {
        s.bindNull(5);
    }
    s.bind(6, now).bind(7, now).run();
    return gameId;
}

void LibraryStore::refreshGame(const std::string &gameId, std::vector<LibraryEvent> &events,
                               const char *forcedEvent)
{
    Stmt game(m_db, "SELECT state, COALESCE(state_reason,''), display_name, "
                    "COALESCE(user_display_name,''), removed_at FROM game WHERE game_id=?");
    game.bindText(1, gameId);
    if (!game.step()) {
        return;
    }
    const std::string oldState = game.text(0);
    const std::string oldReason = game.text(1);
    const std::string oldName = game.text(2);
    const std::string userName = game.text(3);

    Stmt pref(m_db, "SELECT state, COALESCE(state_reason,''), display_name, display_name_source, "
                    "kind, COALESCE(steam_name,''), COALESCE(steam_appid,0) FROM install "
                    "WHERE game_id=? AND removed_at IS NULL "
                    "ORDER BY COALESCE(steam_last_updated,0) DESC, rel_path ASC LIMIT 1");
    pref.bindText(1, gameId);
    if (!pref.step()) {
        return;
    }
    const std::string state = pref.text(0);
    const std::string reason = pref.text(1);
    std::string name = pref.text(2);
    std::string source = pref.text(3);
    const std::string steamName = pref.text(5);
    if (pref.text(4) == "steam" && !steamName.empty()) {
        name = steamName;
        source = "steam_acf";
    } else if (!userName.empty()) {
        name = userName;
        source = "user";
    }

    std::string type;
    QJsonObject payload;
    if (forcedEvent != nullptr) {
        type = forcedEvent;
        payload.insert(QStringLiteral("state"), qs(state));
        payload.insert(QStringLiteral("display_name"), qs(name));
    } else if (state != oldState) {
        type = "game.state_changed";
        payload.insert(QStringLiteral("from"), qs(oldState));
        payload.insert(QStringLiteral("to"), qs(state));
    } else if (name != oldName || reason != oldReason) {
        type = "game.updated";
        payload.insert(QStringLiteral("display_name"), qs(name));
    }
    if (!reason.empty()) {
        payload.insert(QStringLiteral("reason"), qs(reason));
    }

    std::int64_t seq = -1;
    if (!type.empty()) {
        LibraryEvent event = addEvent(type, gameId, toJson(payload));
        seq = event.seq;
        events.push_back(std::move(event));
    }
    Stmt update(m_db, "UPDATE game SET state=?, state_reason=?, display_name=?, "
                      "display_name_source=?, updated_at=?, removed_at=NULL, "
                      "seq=CASE WHEN ?>=0 THEN ? ELSE seq END WHERE game_id=?");
    update.bindText(1, state).bindTextOrNull(2, reason).bindText(3, name).bindText(4, source)
        .bind(5, unixMillisNow()).bind(6, seq).bind(7, seq).bindText(8, gameId)
        .run();
}

std::vector<LibraryEvent> LibraryStore::applyScanResult(const InstallScanResult &result,
                                                        const std::string &fsUuid)
{
    std::lock_guard dbLock(m_dbMutex);
    std::vector<LibraryEvent> events;
    if (m_readOnly || result.vanished) {
        return events;
    }
    try {
        Txn txn(m_db);
        std::optional<InstallRow> row = findInstall(result.key, result.identity, fsUuid);

        if (!row && result.key.kind == InstallKind::Directory && result.mainCandidate) {
            // §6 rule 4: reappearance with same rel_path and same main executable.
            Stmt s(m_db, (std::string("SELECT ") + kInstallColumns +
                          " FROM install i WHERE kind='directory' AND removed_at IS NOT NULL AND "
                          "rel_path=? AND EXISTS (SELECT 1 FROM exe_candidate c WHERE "
                          "c.candidate_id=i.main_candidate_id AND c.rel_path=?) LIMIT 1").c_str());
            s.bindBlob(1, result.key.relPath)
                .bindBlob(2, result.candidates[*result.mainCandidate].relPath);
            if (s.step()) {
                row = readInstallRow(s);
            }
        }
        if (!row && result.key.kind == InstallKind::Steam) {
            Stmt s(m_db, (std::string("SELECT ") + kInstallColumns +
                          " FROM install WHERE kind='steam' AND removed_at IS NOT NULL AND "
                          "steam_appid=? LIMIT 1").c_str());
            s.bind(1, result.key.steamAppId);
            if (s.step()) {
                row = readInstallRow(s);
            }
        }
        if (!row && result.notAGame) {
            return events; // not a game and never was: no record
        }

        const char *forced = nullptr;
        std::int64_t installId = 0;
        std::string gameId;
        const std::string kind = installKindName(result.key.kind);
        if (!row) {
            if (result.key.kind == InstallKind::Steam) {
                Stmt g(m_db, "SELECT game_id FROM game WHERE steam_appid=? AND removed_at IS NULL LIMIT 1");
                g.bind(1, result.key.steamAppId);
                if (g.step()) {
                    gameId = g.text(0);
                }
            }
            if (gameId.empty()) {
                gameId = createGame(result.state, result.displayName, result.displayNameSource,
                                    result.key.steamAppId);
                forced = "game.added";
            }
            Stmt ins(m_db, "INSERT INTO install(game_id, kind, fs_uuid, ino, rel_path) VALUES(?,?,?,?,?)");
            ins.bindText(1, gameId).bindText(2, kind).bindText(3, fsUuid)
                .bind(4, std::int64_t(result.identity.ino)).bindBlob(5, result.key.relPath)
                .run();
            installId = sqlite3_last_insert_rowid(m_db);
        } else {
            installId = row->installId;
            gameId = row->gameId;
            if (row->removed) {
                forced = "game.restored";
            }
        }

        Stmt up(m_db, "UPDATE install SET rel_path=?, dir_handle=?, ino=?, btime_ns=?, "
                      "library_rel_path=?, steam_appid=?, steam_state_flags=?, steam_last_updated=?, "
                      "steam_name=?, watch_coverage=?, scan_generation=?, last_scanned_at=?, "
                      "error_count=CASE WHEN ?='ERROR' THEN error_count+1 ELSE 0 END, "
                      "removed_at=NULL, state=?, state_reason=?, display_name=?, "
                      "display_name_source=?, root_mtime_ns=?, ruleset_version=?, scorer_version=?, "
                      "candidates_truncated=?, entries_truncated=? WHERE install_id=?");
        const bool steam = result.key.kind == InstallKind::Steam;
        up.bindBlob(1, result.key.relPath);
        if (steam || result.identity.handle.empty()) {
            up.bindNull(2);
        } else {
            up.bindBlob(2, result.identity.handle);
        }
        up.bind(3, std::int64_t(result.identity.ino));
        if (result.identity.btimeNs != 0) {
            up.bind(4, result.identity.btimeNs);
        } else {
            up.bindNull(4);
        }
        if (steam) {
            // An empty blob (x'') marks "the root itself is the library".
            up.bindBlob(5, result.key.libraryRelPath).bind(6, result.key.steamAppId);
        } else {
            up.bindNull(5).bindNull(6);
        }
        if (result.steam) {
            up.bind(7, result.steam->stateFlags).bind(8, result.steam->lastUpdated)
                .bindText(9, result.steam->name);
        } else {
            up.bindNull(7).bindNull(8).bindNull(9);
        }
        const std::string state = gameStateName(result.state);
        up.bindText(10, watchCoverageName(result.coverage))
            .bind(11, std::int64_t(result.generation))
            .bind(12, unixMillisNow())
            .bindText(13, state)
            .bindText(14, state)
            .bindTextOrNull(15, result.reason)
            .bindText(16, result.displayName)
            .bindText(17, result.displayNameSource)
            .bind(18, result.identity.mtimeNs)
            .bind(19, kRulesetVersion)
            .bind(20, kScorerVersion)
            .bind(21, std::int64_t(result.candidatesTruncated))
            .bind(22, result.entriesTruncated ? 1 : 0)
            .bind(23, installId);
        up.run();

        // Candidates: upsert by (install_id, rel_path) so candidate_id (and
        // with it the user's choice) survives rescans and moves.
        std::set<std::int64_t> kept;
        std::vector<std::int64_t> ids;
        Stmt cand(m_db,
                  "INSERT INTO exe_candidate(install_id, rel_path, size, mtime_ns, ino, machine, "
                  "subsystem, pe_timestamp, characteristics, product_name, file_description, "
                  "company_name, product_version, file_version, original_filename, internal_name, "
                  "excluded_by, score, features_json, parse_error) "
                  "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                  "ON CONFLICT(install_id, rel_path) DO UPDATE SET size=excluded.size, "
                  "mtime_ns=excluded.mtime_ns, ino=excluded.ino, machine=excluded.machine, "
                  "subsystem=excluded.subsystem, pe_timestamp=excluded.pe_timestamp, "
                  "characteristics=excluded.characteristics, product_name=excluded.product_name, "
                  "file_description=excluded.file_description, company_name=excluded.company_name, "
                  "product_version=excluded.product_version, file_version=excluded.file_version, "
                  "original_filename=excluded.original_filename, internal_name=excluded.internal_name, "
                  "excluded_by=excluded.excluded_by, score=excluded.score, "
                  "features_json=excluded.features_json, parse_error=excluded.parse_error");
        Stmt candId(m_db, "SELECT candidate_id FROM exe_candidate WHERE install_id=? AND rel_path=?");
        for (const ExeCandidate &c : result.candidates) {
            cand.reset();
            cand.bind(1, installId).bindBlob(2, c.relPath).bind(3, std::int64_t(c.size))
                .bind(4, c.mtimeNs).bind(5, std::int64_t(c.ino))
                .bindText(6, machineName(c.pe.machine)).bind(7, c.pe.subsystem)
                .bind(8, c.pe.timestamp).bind(9, c.pe.characteristics)
                .bindTextOrNull(10, c.pe.productName).bindTextOrNull(11, c.pe.fileDescription)
                .bindTextOrNull(12, c.pe.companyName).bindTextOrNull(13, c.pe.productVersion)
                .bindTextOrNull(14, c.pe.fileVersion).bindTextOrNull(15, c.pe.originalFilename)
                .bindTextOrNull(16, c.pe.internalName).bindTextOrNull(17, c.excludedBy)
                .bind(18, c.score).bindTextOrNull(19, c.featuresJson)
                .bindTextOrNull(20, c.pe.parseError);
            cand.run();
            candId.reset();
            candId.bind(1, installId).bindBlob(2, c.relPath);
            candId.step();
            ids.push_back(candId.i64(0));
            kept.insert(ids.back());
        }
        {
            std::vector<std::int64_t> stale;
            Stmt all(m_db, "SELECT candidate_id FROM exe_candidate WHERE install_id=?");
            all.bind(1, installId);
            while (all.step()) {
                if (!kept.contains(all.i64(0))) {
                    stale.push_back(all.i64(0));
                }
            }
            Stmt del(m_db, "DELETE FROM exe_candidate WHERE candidate_id=?");
            for (std::int64_t id : stale) {
                del.reset();
                del.bind(1, id).run();
            }
        }

        std::optional<std::int64_t> main;
        if (result.mainCandidate && *result.mainCandidate < ids.size()) {
            main = ids[*result.mainCandidate];
        }
        // §10 invariant 9: a persisted user choice always wins while its file exists.
        Stmt user(m_db, "SELECT user_main_candidate FROM game WHERE game_id=?");
        user.bindText(1, gameId);
        if (user.step() && !user.isNull(0) && kept.contains(user.i64(0))) {
            main = user.i64(0);
            Stmt fix(m_db, "UPDATE install SET state='READY', state_reason='USER_CHOICE' WHERE install_id=?");
            fix.bind(1, installId).run();
        }
        Stmt setMain(m_db, "UPDATE install SET main_candidate_id=? WHERE install_id=?");
        if (main) {
            setMain.bind(1, *main);
        } else {
            setMain.bindNull(1);
        }
        setMain.bind(2, installId).run();

        refreshGame(gameId, events, forced);
        txn.commit();
    } catch (const DbError &e) {
        qWarning().noquote() << "library: applyScanResult failed:" << e.what();
        events.clear();
    }
    return events;
}

std::vector<LibraryEvent> LibraryStore::recordDiscovered(const InstallKey &key,
                                                         const DirIdentity &identity,
                                                         const SteamInfo &steam,
                                                         const std::string &fsUuid,
                                                         std::int64_t *installIdOut)
{
    std::lock_guard dbLock(m_dbMutex);
    std::vector<LibraryEvent> events;
    if (m_readOnly) {
        return events;
    }
    try {
        Txn txn(m_db);
        std::optional<InstallRow> row = findInstall(key, identity, fsUuid);
        if (row && !row->removed) {
            if (installIdOut != nullptr) {
                *installIdOut = row->installId;
            }
            return events;
        }
        const char *forced = "game.added";
        std::int64_t installId = 0;
        std::string gameId;
        if (row) {
            installId = row->installId;
            gameId = row->gameId;
            forced = "game.restored";
        } else {
            Stmt g(m_db, "SELECT game_id FROM game WHERE steam_appid=? AND removed_at IS NULL LIMIT 1");
            g.bind(1, key.steamAppId);
            if (g.step()) {
                gameId = g.text(0);
                forced = nullptr;
            } else {
                gameId = createGame(GameState::Discovered, steam.name, "steam_acf", key.steamAppId);
            }
            Stmt ins(m_db, "INSERT INTO install(game_id, kind, fs_uuid, ino, rel_path, library_rel_path, "
                           "steam_appid) VALUES(?,?,?,?,?,?,?)");
            ins.bindText(1, gameId).bindText(2, "steam").bindText(3, fsUuid)
                .bind(4, std::int64_t(identity.ino)).bindBlob(5, key.relPath)
                .bindBlob(6, key.libraryRelPath).bind(7, key.steamAppId)
                .run();
            installId = sqlite3_last_insert_rowid(m_db);
        }
        Stmt up(m_db, "UPDATE install SET removed_at=NULL, state='DISCOVERED', state_reason=NULL, "
                      "rel_path=?, steam_name=?, steam_state_flags=?, steam_last_updated=?, "
                      "display_name=?, display_name_source='steam_acf' WHERE install_id=?");
        up.bindBlob(1, key.relPath).bindText(2, steam.name).bind(3, steam.stateFlags)
            .bind(4, steam.lastUpdated).bindText(5, steam.name).bind(6, installId)
            .run();
        refreshGame(gameId, events, forced);
        txn.commit();
        if (installIdOut != nullptr) {
            *installIdOut = installId;
        }
    } catch (const DbError &e) {
        qWarning().noquote() << "library: recordDiscovered failed:" << e.what();
        events.clear();
    }
    return events;
}

std::vector<LibraryEvent> LibraryStore::recordManifestError(const InstallKey &key,
                                                            const std::string &reason,
                                                            const std::string &fsUuid,
                                                            std::int64_t *installIdOut)
{
    std::lock_guard dbLock(m_dbMutex);
    std::vector<LibraryEvent> events;
    if (m_readOnly) {
        return events;
    }
    try {
        Txn txn(m_db);
        std::optional<InstallRow> row = findInstall(key, DirIdentity{}, fsUuid);
        const char *forced = nullptr;
        std::int64_t installId = 0;
        std::string gameId;
        const std::string name = "Steam app " + std::to_string(key.steamAppId);
        if (row) {
            installId = row->installId;
            gameId = row->gameId;
            if (row->removed) {
                forced = "game.restored";
            }
        } else {
            gameId = createGame(GameState::Error, name, "steam_appid", key.steamAppId);
            forced = "game.added";
            Stmt ins(m_db, "INSERT INTO install(game_id, kind, fs_uuid, ino, rel_path, library_rel_path, "
                           "steam_appid) VALUES(?,?,?,0,?,?,?)");
            ins.bindText(1, gameId).bindText(2, "steam").bindText(3, fsUuid).bindBlob(4, key.relPath)
                .bindBlob(5, key.libraryRelPath).bind(6, key.steamAppId)
                .run();
            installId = sqlite3_last_insert_rowid(m_db);
        }
        Stmt up(m_db, "UPDATE install SET removed_at=NULL, state='ERROR', state_reason=?, "
                      "display_name=CASE WHEN display_name='' THEN ? ELSE display_name END, "
                      "error_count=error_count+1 WHERE install_id=?");
        up.bindText(1, reason).bindText(2, name).bind(3, installId).run();
        refreshGame(gameId, events, forced);
        txn.commit();
        if (installIdOut != nullptr) {
            *installIdOut = installId;
        }
    } catch (const DbError &e) {
        qWarning().noquote() << "library: recordManifestError failed:" << e.what();
        events.clear();
    }
    return events;
}

std::vector<LibraryEvent> LibraryStore::transitionInstall(std::int64_t installId,
                                                          const std::set<GameState> &from,
                                                          GameState to, const std::string &reason)
{
    std::lock_guard dbLock(m_dbMutex);
    std::vector<LibraryEvent> events;
    if (m_readOnly) {
        return events;
    }
    try {
        Txn txn(m_db);
        Stmt s(m_db, "SELECT game_id, state FROM install WHERE install_id=? AND removed_at IS NULL");
        s.bind(1, installId);
        if (!s.step()) {
            return events;
        }
        const std::string gameId = s.text(0);
        const auto current = gameStateFromName(s.text(1));
        if (!current || !from.contains(*current)) {
            return events;
        }
        Stmt up(m_db, "UPDATE install SET state=?, state_reason=? WHERE install_id=?");
        up.bindText(1, gameStateName(to)).bindTextOrNull(2, reason).bind(3, installId).run();
        refreshGame(gameId, events);
        txn.commit();
    } catch (const DbError &e) {
        qWarning().noquote() << "library: transitionInstall failed:" << e.what();
        events.clear();
    }
    return events;
}

std::vector<LibraryEvent> LibraryStore::setCoverage(std::int64_t installId, WatchCoverage coverage)
{
    std::lock_guard dbLock(m_dbMutex);
    if (m_readOnly) {
        return {};
    }
    try {
        Stmt up(m_db, "UPDATE install SET watch_coverage=? WHERE install_id=?");
        up.bindText(1, watchCoverageName(coverage)).bind(2, installId).run();
    } catch (const DbError &) {
    }
    return {};
}

std::vector<LibraryEvent> LibraryStore::applyRemovals(const std::set<std::int64_t> &seenInstallIds)
{
    std::lock_guard dbLock(m_dbMutex);
    std::vector<LibraryEvent> events;
    if (m_readOnly) {
        return events;
    }
    try {
        Txn txn(m_db);
        std::set<std::string> affected;
        std::vector<std::pair<std::int64_t, std::string>> gone;
        {
            Stmt s(m_db, "SELECT install_id, game_id FROM install WHERE removed_at IS NULL");
            while (s.step()) {
                if (!seenInstallIds.contains(s.i64(0))) {
                    gone.emplace_back(s.i64(0), s.text(1));
                }
            }
        }
        const std::int64_t now = unixMillisNow();
        Stmt mark(m_db, "UPDATE install SET removed_at=?, state='REMOVED' WHERE install_id=?");
        for (const auto &[id, gameId] : gone) {
            mark.reset();
            mark.bind(1, now).bind(2, id).run();
            affected.insert(gameId);
        }
        for (const std::string &gameId : affected) {
            Stmt remaining(m_db, "SELECT COUNT(*) FROM install WHERE game_id=? AND removed_at IS NULL");
            remaining.bindText(1, gameId);
            remaining.step();
            if (remaining.i64(0) > 0) {
                refreshGame(gameId, events);
                continue;
            }
            Stmt old(m_db, "SELECT state FROM game WHERE game_id=?");
            old.bindText(1, gameId);
            old.step();
            QJsonObject payload{{QStringLiteral("from"), qs(old.text(0))}};
            LibraryEvent event = addEvent("game.removed", gameId, toJson(payload));
            Stmt up(m_db, "UPDATE game SET state='REMOVED', removed_at=?, updated_at=?, seq=? WHERE game_id=?");
            up.bind(1, now).bind(2, now).bind(3, event.seq).bindText(4, gameId).run();
            events.push_back(std::move(event));
        }
        txn.commit();
    } catch (const DbError &e) {
        qWarning().noquote() << "library: applyRemovals failed:" << e.what();
        events.clear();
    }
    return events;
}

std::vector<LibraryEvent> LibraryStore::setUserMainExecutable(const std::string &gameId,
                                                              std::optional<std::int64_t> candidateId,
                                                              std::string &error)
{
    std::lock_guard dbLock(m_dbMutex);
    std::vector<LibraryEvent> events;
    if (m_readOnly) {
        error = "READ_ONLY";
        return events;
    }
    try {
        Txn txn(m_db);
        Stmt g(m_db, "SELECT 1 FROM game WHERE game_id=? AND removed_at IS NULL");
        g.bindText(1, gameId);
        if (!g.step()) {
            error = "NOT_FOUND";
            return events;
        }
        if (candidateId) {
            Stmt c(m_db, "SELECT i.install_id FROM exe_candidate c JOIN install i ON "
                         "i.install_id=c.install_id WHERE c.candidate_id=? AND i.game_id=? AND "
                         "i.removed_at IS NULL AND c.excluded_by IS NULL");
            c.bind(1, *candidateId).bindText(2, gameId);
            if (!c.step()) {
                error = "INVALID_CANDIDATE";
                return events;
            }
            const std::int64_t installId = c.i64(0);
            Stmt set(m_db, "UPDATE game SET user_main_candidate=? WHERE game_id=?");
            set.bind(1, *candidateId).bindText(2, gameId).run();
            Stmt inst(m_db, "UPDATE install SET state='READY', state_reason='USER_CHOICE', "
                            "main_candidate_id=? WHERE install_id=?");
            inst.bind(1, *candidateId).bind(2, installId).run();
        } else {
            Stmt set(m_db, "UPDATE game SET user_main_candidate=NULL WHERE game_id=?");
            set.bindText(1, gameId).run();
            // Back to automatic: the service rescans these installs.
            Stmt inst(m_db, "UPDATE install SET state='DISCOVERED', state_reason='USER_CHOICE_CLEARED' "
                            "WHERE game_id=? AND removed_at IS NULL");
            inst.bindText(1, gameId).run();
        }
        refreshGame(gameId, events);
        txn.commit();
    } catch (const DbError &e) {
        error = "DB_ERROR";
        events.clear();
    }
    return events;
}

std::vector<LibraryEvent> LibraryStore::appendLibraryEvent(const std::string &type,
                                                           const std::string &payloadJson)
{
    std::lock_guard dbLock(m_dbMutex);
    std::vector<LibraryEvent> events;
    if (m_readOnly) {
        return events;
    }
    try {
        Txn txn(m_db);
        events.push_back(addEvent(type, {}, payloadJson));
        txn.commit();
    } catch (const DbError &e) {
        qWarning().noquote() << "library: appendLibraryEvent failed:" << e.what();
        events.clear();
    }
    return events;
}

void LibraryStore::purge(std::chrono::seconds tombstoneRetention, std::size_t eventRetention)
{
    std::lock_guard dbLock(m_dbMutex);
    if (m_readOnly) {
        return;
    }
    try {
        Txn txn(m_db);
        const std::int64_t cutoff =
            unixMillisNow() - std::chrono::duration_cast<std::chrono::milliseconds>(tombstoneRetention).count();
        Stmt c(m_db, "DELETE FROM exe_candidate WHERE install_id IN (SELECT install_id FROM install "
                     "WHERE game_id IN (SELECT game_id FROM game WHERE removed_at IS NOT NULL AND removed_at < ?))");
        c.bind(1, cutoff).run();
        Stmt clearUser(m_db, "UPDATE game SET user_main_candidate=NULL WHERE removed_at IS NOT NULL AND removed_at < ?");
        clearUser.bind(1, cutoff).run();
        Stmt i(m_db, "DELETE FROM install WHERE game_id IN (SELECT game_id FROM game WHERE "
                     "removed_at IS NOT NULL AND removed_at < ?)");
        i.bind(1, cutoff).run();
        Stmt cov(m_db, "DELETE FROM cover WHERE game_id IN (SELECT game_id FROM game WHERE "
                       "removed_at IS NOT NULL AND removed_at < ?)");
        cov.bind(1, cutoff).run();
        Stmt dup(m_db, "UPDATE game SET possible_duplicate_of=NULL WHERE possible_duplicate_of IN "
                       "(SELECT game_id FROM game WHERE removed_at IS NOT NULL AND removed_at < ?)");
        dup.bind(1, cutoff).run();
        Stmt g(m_db, "DELETE FROM game WHERE removed_at IS NOT NULL AND removed_at < ?");
        g.bind(1, cutoff).run();
        Stmt e(m_db, "DELETE FROM library_event WHERE seq <= (SELECT MAX(seq) FROM library_event) - ?");
        e.bind(1, std::int64_t(eventRetention)).run();
        txn.commit();
    } catch (const DbError &e) {
        qWarning().noquote() << "library: purge failed:" << e.what();
    }
}

void LibraryStore::debugBeginTransaction()
{
    std::lock_guard dbLock(m_dbMutex);
    exec("BEGIN IMMEDIATE");
}

QJsonObject LibraryStore::listGames(const ListGamesQuery &query) const
{
    std::lock_guard lock(m_readerMutex);
    QJsonObject out;
    QJsonArray games;
    if (m_reader == nullptr) {
        return out;
    }
    try {
        std::string sql =
            "SELECT g.game_id, g.display_name, g.display_name_source, g.state, "
            "COALESCE(g.state_reason,''), COALESCE(g.steam_appid,0), g.seq, "
            "(SELECT kind FROM install i WHERE i.game_id=g.game_id ORDER BY i.removed_at IS NOT NULL "
            "LIMIT 1) FROM game g WHERE 1=1";
        bool includeRemoved = false;
        if (!query.states.empty()) {
            sql += " AND g.state IN (";
            for (std::size_t i = 0; i < query.states.size(); ++i) {
                sql += i == 0 ? "?" : ",?";
                includeRemoved = includeRemoved || query.states[i] == GameState::Removed;
            }
            sql += ")";
        }
        if (!includeRemoved) {
            sql += " AND g.removed_at IS NULL";
        }
        if (query.kind) {
            sql += " AND EXISTS (SELECT 1 FROM install i WHERE i.game_id=g.game_id AND i.kind=?)";
        }
        sql += " ORDER BY g.display_name COLLATE LIBNAME, g.game_id LIMIT ? OFFSET ?";
        // Snapshot seq and page from the same read transaction.
        sqlite3_exec(m_reader, "BEGIN", nullptr, nullptr, nullptr);
        Stmt seq(m_reader, "SELECT CAST(value AS INTEGER) FROM meta WHERE key='library_seq'");
        const std::int64_t librarySeq = seq.step() ? seq.i64(0) : 0;
        Stmt s(m_reader, sql.c_str());
        int index = 1;
        for (GameState state : query.states) {
            s.bindText(index++, gameStateName(state));
        }
        if (query.kind) {
            s.bindText(index++, installKindName(*query.kind));
        }
        const int limit = std::clamp(query.limit, 1, 200);
        s.bind(index, limit + 1);
        s.bind(index + 1, query.offset);
        int rows = 0;
        bool more = false;
        while (s.step()) {
            if (++rows > limit) {
                more = true;
                break;
            }
            QJsonObject game{
                {QStringLiteral("game_id"), qs(s.text(0))},
                {QStringLiteral("display_name"), qs(s.text(1))},
                {QStringLiteral("display_name_source"), qs(s.text(2))},
                {QStringLiteral("state"), qs(s.text(3))},
                {QStringLiteral("kind"), qs(s.text(7))},
                {QStringLiteral("seq"), static_cast<qint64>(s.i64(6))},
            };
            if (!s.text(4).empty()) {
                game.insert(QStringLiteral("state_reason"), qs(s.text(4)));
            }
            if (s.i64(5) != 0) {
                game.insert(QStringLiteral("steam_appid"), static_cast<qint64>(s.i64(5)));
            }
            games.append(game);
        }
        sqlite3_exec(m_reader, "COMMIT", nullptr, nullptr, nullptr);
        out.insert(QStringLiteral("library_seq"), static_cast<qint64>(librarySeq));
        out.insert(QStringLiteral("games"), games);
        out.insert(QStringLiteral("next_cursor"),
                   more ? QJsonValue(QString::number(query.offset + limit)) : QJsonValue());
    } catch (const DbError &e) {
        sqlite3_exec(m_reader, "ROLLBACK", nullptr, nullptr, nullptr);
        qWarning().noquote() << "library: listGames failed:" << e.what();
    }
    return out;
}

std::optional<QJsonObject> LibraryStore::getGame(const std::string &gameId) const
{
    std::lock_guard lock(m_readerMutex);
    if (m_reader == nullptr) {
        return std::nullopt;
    }
    try {
        Stmt g(m_reader, "SELECT game_id, state, COALESCE(state_reason,''), display_name, "
                         "display_name_source, COALESCE(steam_appid,0), COALESCE(user_display_name,''), "
                         "user_main_candidate, removed_at, seq FROM game WHERE game_id=?");
        g.bindText(1, gameId);
        if (!g.step()) {
            return std::nullopt;
        }
        const std::string state = g.text(1);
        QJsonObject game{
            {QStringLiteral("game_id"), qs(g.text(0))},
            {QStringLiteral("state"), qs(state)},
            {QStringLiteral("display_name"), qs(g.text(3))},
            {QStringLiteral("display_name_source"), qs(g.text(4))},
            {QStringLiteral("seq"), static_cast<qint64>(g.i64(9))},
            {QStringLiteral("cover_available"), false},
        };
        if (!g.text(2).empty()) {
            game.insert(QStringLiteral("state_reason"), qs(g.text(2)));
        }
        if (g.i64(5) != 0) {
            game.insert(QStringLiteral("steam_appid"), static_cast<qint64>(g.i64(5)));
        }
        if (!g.text(6).empty()) {
            game.insert(QStringLiteral("user_display_name"), qs(g.text(6)));
        }
        if (!g.isNull(7)) {
            game.insert(QStringLiteral("user_main_candidate"), static_cast<qint64>(g.i64(7)));
        }

        auto candidateJson = [](const Stmt &c) {
            QJsonObject obj{
                {QStringLiteral("candidate_id"), static_cast<qint64>(c.i64(0))},
                {QStringLiteral("rel_path"), qs(sanitizeRelPath(c.text(1)))},
                {QStringLiteral("score"), static_cast<qint64>(c.i64(2))},
                {QStringLiteral("size"), static_cast<qint64>(c.i64(3))},
                {QStringLiteral("machine"), qs(c.text(4))},
                {QStringLiteral("subsystem"), static_cast<qint64>(c.i64(5))},
            };
            const std::pair<const char *, int> fields[] = {
                {"product_name", 6}, {"file_description", 7}, {"company_name", 8},
                {"product_version", 9}, {"file_version", 10}, {"excluded_by", 11},
                {"parse_error", 12},
            };
            for (const auto &[name, col] : fields) {
                if (!c.isNull(col) && !c.text(col).empty()) {
                    obj.insert(QString::fromLatin1(name), qs(c.text(col)));
                }
            }
            if (!c.isNull(13)) {
                obj.insert(QStringLiteral("features"),
                           QJsonDocument::fromJson(QByteArray::fromStdString(c.text(13))).object());
            }
            return obj;
        };
        constexpr const char *kCandidateSelect =
            "SELECT candidate_id, rel_path, COALESCE(score,0), size, COALESCE(machine,''), "
            "COALESCE(subsystem,0), product_name, file_description, company_name, product_version, "
            "file_version, excluded_by, parse_error, features_json FROM exe_candidate ";

        QJsonArray installs;
        Stmt i(m_reader, "SELECT install_id, kind, rel_path, COALESCE(library_rel_path, x''), "
                         "COALESCE(steam_appid,0), state, COALESCE(state_reason,''), watch_coverage, "
                         "main_candidate_id, removed_at, candidates_truncated, entries_truncated, "
                         "COALESCE(steam_state_flags,0), COALESCE(ruleset_version,0), "
                         "COALESCE(scorer_version,0) FROM install WHERE game_id=? ORDER BY install_id");
        i.bindText(1, gameId);
        while (i.step()) {
            const std::int64_t installId = i.i64(0);
            const std::string installState = i.text(5);
            QJsonObject install{
                {QStringLiteral("install_id"), static_cast<qint64>(installId)},
                {QStringLiteral("kind"), qs(i.text(1))},
                {QStringLiteral("rel_path"), qs(sanitizeRelPath(i.text(2)))},
                {QStringLiteral("state"), qs(installState)},
                {QStringLiteral("watch_coverage"), qs(i.text(7))},
                {QStringLiteral("removed"), !i.isNull(9)},
                {QStringLiteral("candidates_truncated"), static_cast<qint64>(i.i64(10))},
                {QStringLiteral("entries_truncated"), i.i64(11) != 0},
                {QStringLiteral("ruleset_version"), static_cast<qint64>(i.i64(13))},
                {QStringLiteral("scorer_version"), static_cast<qint64>(i.i64(14))},
            };
            if (!i.text(6).empty()) {
                install.insert(QStringLiteral("state_reason"), qs(i.text(6)));
            }
            if (i.text(1) == "steam") {
                install.insert(QStringLiteral("library_rel_path"), qs(sanitizeRelPath(i.text(3))));
                install.insert(QStringLiteral("steam_appid"), static_cast<qint64>(i.i64(4)));
                install.insert(QStringLiteral("steam_state_flags"), static_cast<qint64>(i.i64(12)));
            }
            if (!i.isNull(8)) {
                Stmt m(m_reader, (std::string(kCandidateSelect) + "WHERE candidate_id=?").c_str());
                m.bind(1, i.i64(8));
                if (m.step()) {
                    install.insert(QStringLiteral("main_executable"), candidateJson(m));
                }
            }
            Stmt count(m_reader, "SELECT COUNT(*) FROM exe_candidate WHERE install_id=? AND excluded_by IS NULL");
            count.bind(1, installId);
            count.step();
            install.insert(QStringLiteral("candidate_count"), static_cast<qint64>(count.i64(0)));
            if (installState == "AMBIGUOUS") {
                QJsonArray candidates;
                Stmt c(m_reader, (std::string(kCandidateSelect) +
                                  "WHERE install_id=? AND excluded_by IS NULL "
                                  "ORDER BY score DESC, rel_path LIMIT 8").c_str());
                c.bind(1, installId);
                while (c.step()) {
                    candidates.append(candidateJson(c));
                }
                install.insert(QStringLiteral("candidates"), candidates);
            }
            installs.append(install);
        }
        game.insert(QStringLiteral("installs"), installs);
        return game;
    } catch (const DbError &e) {
        qWarning().noquote() << "library: getGame failed:" << e.what();
        return std::nullopt;
    }
}

std::vector<LibraryEvent> LibraryStore::eventsSince(std::int64_t since, bool &resync,
                                                    std::size_t limit) const
{
    std::lock_guard lock(m_readerMutex);
    std::vector<LibraryEvent> events;
    resync = false;
    if (m_reader == nullptr) {
        resync = true;
        return events;
    }
    try {
        Stmt range(m_reader, "SELECT COALESCE(MIN(seq),0), (SELECT CAST(value AS INTEGER) FROM meta "
                             "WHERE key='library_seq') FROM library_event");
        range.step();
        const std::int64_t minSeq = range.i64(0);
        const std::int64_t maxSeq = range.i64(1);
        if (since > maxSeq || (since < maxSeq && (minSeq == 0 || since < minSeq - 1))) {
            resync = true;
            return events;
        }
        Stmt s(m_reader, "SELECT seq, at, type, COALESCE(game_id,''), payload FROM library_event "
                         "WHERE seq > ? ORDER BY seq LIMIT ?");
        s.bind(1, since).bind(2, std::int64_t(limit));
        while (s.step()) {
            events.push_back({s.i64(0), s.i64(1), s.text(2), s.text(3), s.text(4)});
        }
    } catch (const DbError &) {
        resync = true;
    }
    return events;
}

std::map<std::string, int> LibraryStore::countsByState() const
{
    std::lock_guard lock(m_readerMutex);
    std::map<std::string, int> counts;
    if (m_reader == nullptr) {
        return counts;
    }
    try {
        Stmt s(m_reader, "SELECT state, COUNT(*) FROM game GROUP BY state");
        while (s.step()) {
            counts[s.text(0)] = static_cast<int>(s.i64(1));
        }
    } catch (const DbError &) {
    }
    return counts;
}

int LibraryStore::partialInstalls() const
{
    std::lock_guard lock(m_readerMutex);
    if (m_reader == nullptr) {
        return 0;
    }
    try {
        Stmt s(m_reader, "SELECT COUNT(*) FROM install WHERE removed_at IS NULL AND watch_coverage!='FULL'");
        s.step();
        return static_cast<int>(s.i64(0));
    } catch (const DbError &) {
        return 0;
    }
}

QJsonObject LibraryStore::lastRuns() const
{
    std::lock_guard lock(m_readerMutex);
    QJsonObject out;
    if (m_reader == nullptr) {
        return out;
    }
    try {
        Stmt s(m_reader, "SELECT run_id, kind, started_at, COALESCE(finished_at,0), COALESCE(outcome,'') "
                         "FROM scan_run WHERE kind IN ('FULL','RECONCILE') AND outcome='OK' "
                         "ORDER BY run_id DESC LIMIT 1");
        if (s.step()) {
            out.insert(QStringLiteral("last_full_scan"),
                       QJsonObject{{QStringLiteral("run_id"), static_cast<qint64>(s.i64(0))},
                                   {QStringLiteral("kind"), qs(s.text(1))},
                                   {QStringLiteral("finished_at"), static_cast<qint64>(s.i64(3))}});
        }
        Stmt c(m_reader, "SELECT COUNT(*) FROM scan_run WHERE outcome='CRASHED'");
        c.step();
        out.insert(QStringLiteral("crashed_runs"), static_cast<qint64>(c.i64(0)));
    } catch (const DbError &) {
    }
    return out;
}

} // namespace threesixty::daemon::library
