// 360io-library: command-line client of the /games library scanner
// (docs/game-storage-scanner.md §11). By default it talks to the library API
// socket of 360iod; --offline runs the scanner in-process against a root and
// database of your choice (diagnostics, fake trees, daemon stopped).

#include "library_service.hpp"

#include <QCommandLineParser>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocalSocket>
#include <QLoggingCategory>

#include <chrono>
#include <cstdio>
#include <memory>
#include <optional>

namespace {

using namespace threesixty::daemon::library;

enum Exit { kOk = 0, kError = 1, kUsage = 2, kUnreachable = 3 };

void out(const QString &text)
{
    std::fputs(text.toUtf8().constData(), stdout);
    std::fputc('\n', stdout);
}

void err(const QString &text)
{
    std::fputs(("360io-library: " + text).toUtf8().constData(), stderr);
    std::fputc('\n', stderr);
}

QString compact(const QJsonValue &value)
{
    if (value.isObject()) {
        return QString::fromUtf8(QJsonDocument(value.toObject()).toJson(QJsonDocument::Compact));
    }
    if (value.isArray()) {
        return QString::fromUtf8(QJsonDocument(value.toArray()).toJson(QJsonDocument::Compact));
    }
    return value.toVariant().toString();
}

void printJson(const QJsonObject &object)
{
    out(QString::fromUtf8(QJsonDocument(object).toJson(QJsonDocument::Indented)).trimmed());
}

// ---------------------------------------------------------------- source ---

// Where answers come from: the daemon socket or an in-process service.
class Source
{
public:
    virtual ~Source() = default;
    virtual std::optional<QJsonObject> call(const QString &type, QJsonObject params, QString &error) = 0;
};

class SocketSource final : public Source
{
public:
    bool connect(const QString &path, QString &error)
    {
        m_socket.connectToServer(path);
        if (!m_socket.waitForConnected(3000)) {
            error = QStringLiteral("cannot connect to %1: %2").arg(path, m_socket.errorString());
            return false;
        }
        return true;
    }

    std::optional<QJsonObject> call(const QString &type, QJsonObject params, QString &error) override
    {
        const qint64 id = ++m_nextId;
        params.insert(QStringLiteral("protocol"), 1);
        params.insert(QStringLiteral("id"), id);
        params.insert(QStringLiteral("type"), type);
        m_socket.write(QJsonDocument(params).toJson(QJsonDocument::Compact) + '\n');
        m_socket.flush();
        QElapsedTimer timer;
        timer.start();
        while (timer.elapsed() < 15000) {
            while (m_socket.canReadLine()) {
                const QJsonObject reply = QJsonDocument::fromJson(m_socket.readLine()).object();
                const QJsonValue replyId = reply.value(QStringLiteral("id"));
                if (reply.value(QStringLiteral("type")) == QStringLiteral("event")) {
                    continue;
                }
                if (reply.value(QStringLiteral("status")) == QStringLiteral("error")) {
                    if (!replyId.isUndefined() && replyId.toInteger() != id) {
                        continue;
                    }
                    const QJsonObject e = reply.value(QStringLiteral("error")).toObject();
                    error = e.value(QStringLiteral("code")).toString();
                    if (e.contains(QStringLiteral("message"))) {
                        error += QStringLiteral(" (%1)").arg(e.value(QStringLiteral("message")).toString());
                    }
                    if (e.contains(QStringLiteral("retry_after_ms"))) {
                        error += QStringLiteral(", retry after %1 s")
                                     .arg(e.value(QStringLiteral("retry_after_ms")).toInteger() / 1000 + 1);
                    }
                    return std::nullopt;
                }
                if (replyId.toInteger() == id) {
                    return reply.value(QStringLiteral("result")).toObject();
                }
            }
            if (m_socket.state() != QLocalSocket::ConnectedState) {
                error = QStringLiteral("connection closed by 360iod");
                return std::nullopt;
            }
            m_socket.waitForReadyRead(250);
        }
        error = QStringLiteral("timeout waiting for 360iod");
        return std::nullopt;
    }

private:
    QLocalSocket m_socket;
    qint64 m_nextId = 0;
};

class OfflineSource final : public Source
{
public:
    explicit OfflineSource(LibraryConfig config) : m_service(std::move(config)) {}
    ~OfflineSource() override { m_service.stop(); }

    bool start(std::chrono::milliseconds timeout, QString &error)
    {
        m_timeout = timeout;
        if (!m_service.start()) {
            error = QStringLiteral("database unavailable");
            return false;
        }
        return waitIdle(error);
    }

    bool waitIdle(QString &error)
    {
        if (!m_service.waitIdle(m_timeout)) {
            error = QStringLiteral("scan did not finish within the timeout");
            return false;
        }
        return true;
    }

    std::optional<QJsonObject> call(const QString &type, QJsonObject params, QString &error) override
    {
        if (type == QStringLiteral("hello")) {
            return QJsonObject{{QStringLiteral("role"), QStringLiteral("offline")}};
        }
        if (type == QStringLiteral("ListGames")) {
            ListGamesQuery query;
            query.offset = params.value(QStringLiteral("cursor")).toString().toLongLong();
            query.limit = 200;
            return m_service.listGames(query);
        }
        if (type == QStringLiteral("GetGame")) {
            auto game = m_service.getGame(params.value(QStringLiteral("game_id")).toString().toStdString());
            if (!game) {
                error = QStringLiteral("NOT_FOUND");
            }
            return game;
        }
        if (type == QStringLiteral("GetHealth")) {
            return m_service.health();
        }
        if (type == QStringLiteral("GetProgress")) {
            return m_service.progress();
        }
        if (type == QStringLiteral("Rescan")) {
            const QString scope = params.value(QStringLiteral("scope")).toString();
            const auto reply = m_service.rescan(scope == QStringLiteral("all") ? std::string() : scope.toStdString(),
                                                params.value(QStringLiteral("mode")) == QStringLiteral("full"));
            if (!reply.ok) {
                error = QString::fromStdString(reply.error);
                return std::nullopt;
            }
            if (!waitIdle(error)) {
                return std::nullopt;
            }
            return QJsonObject{{QStringLiteral("request_id"), static_cast<qint64>(reply.requestId)},
                               {QStringLiteral("queued"), reply.queued}};
        }
        error = QStringLiteral("UNSUPPORTED");
        return std::nullopt;
    }

private:
    LibraryService m_service;
    std::chrono::milliseconds m_timeout{600000};
};

// -------------------------------------------------------------- commands ---

std::optional<QJsonArray> allGames(Source &source, QString &error)
{
    QJsonArray games;
    QJsonValue cursor;
    do {
        QJsonObject params{{QStringLiteral("limit"), 200}};
        if (cursor.isString()) {
            params.insert(QStringLiteral("cursor"), cursor);
        }
        const auto page = source.call(QStringLiteral("ListGames"), params, error);
        if (!page) {
            return std::nullopt;
        }
        for (const QJsonValue &game : page->value(QStringLiteral("games")).toArray()) {
            games.append(game);
        }
        cursor = page->value(QStringLiteral("next_cursor"));
    } while (cursor.isString());
    return games;
}

int cmdList(Source &source, bool json)
{
    QString error;
    const auto games = allGames(source, error);
    if (!games) {
        err(QStringLiteral("list failed: %1").arg(error));
        return kError;
    }
    if (json) {
        printJson(QJsonObject{{QStringLiteral("games"), *games}});
        return kOk;
    }
    if (games->isEmpty()) {
        out(QStringLiteral("no games found"));
        return kOk;
    }
    out(QStringLiteral("%1 %2 %3 %4").arg(QStringLiteral("STATE"), -10).arg(QStringLiteral("KIND"), -9)
            .arg(QStringLiteral("NAME"), -40).arg(QStringLiteral("GAME_ID")));
    for (const QJsonValue &value : *games) {
        const QJsonObject game = value.toObject();
        QString state = game.value(QStringLiteral("state")).toString();
        QString name = game.value(QStringLiteral("display_name")).toString();
        if (game.contains(QStringLiteral("state_reason"))) {
            name += QStringLiteral(" [%1]").arg(game.value(QStringLiteral("state_reason")).toString());
        }
        out(QStringLiteral("%1 %2 %3 %4").arg(state, -10)
                .arg(game.value(QStringLiteral("kind")).toString(), -9)
                .arg(name, -40)
                .arg(game.value(QStringLiteral("game_id")).toString()));
    }
    out(QStringLiteral("%1 game(s)").arg(games->size()));
    return kOk;
}

void printCandidate(const QString &label, const QJsonObject &c)
{
    out(QStringLiteral("    %1 %2 (score %3, %4 KiB, %5)")
            .arg(label, c.value(QStringLiteral("rel_path")).toString())
            .arg(c.value(QStringLiteral("score")).toInteger())
            .arg(c.value(QStringLiteral("size")).toInteger() / 1024)
            .arg(c.value(QStringLiteral("machine")).toString()));
    for (const char *key : {"product_name", "file_description", "company_name", "product_version",
                            "file_version", "parse_error", "excluded_by"}) {
        const QString value = c.value(QLatin1String(key)).toString();
        if (!value.isEmpty()) {
            out(QStringLiteral("        %1: %2").arg(QLatin1String(key), value));
        }
    }
}

int cmdShow(Source &source, const QString &gameId, bool json)
{
    QString error;
    const auto game = source.call(QStringLiteral("GetGame"), {{QStringLiteral("game_id"), gameId}}, error);
    if (!game) {
        err(QStringLiteral("show failed: %1").arg(error));
        return kError;
    }
    if (json) {
        printJson(*game);
        return kOk;
    }
    out(QStringLiteral("%1  (name from %2)")
            .arg(game->value(QStringLiteral("display_name")).toString(),
                 game->value(QStringLiteral("display_name_source")).toString()));
    out(QStringLiteral("  id:    %1").arg(game->value(QStringLiteral("game_id")).toString()));
    QString state = game->value(QStringLiteral("state")).toString();
    if (game->contains(QStringLiteral("state_reason"))) {
        state += QStringLiteral(" (%1)").arg(game->value(QStringLiteral("state_reason")).toString());
    }
    out(QStringLiteral("  state: %1").arg(state));
    if (game->contains(QStringLiteral("steam_appid"))) {
        out(QStringLiteral("  steam: appid %1").arg(game->value(QStringLiteral("steam_appid")).toInteger()));
    }
    for (const QJsonValue &value : game->value(QStringLiteral("installs")).toArray()) {
        const QJsonObject install = value.toObject();
        out(QStringLiteral("  install /%1 [%2, %3, %4 candidate(s)]")
                .arg(install.value(QStringLiteral("rel_path")).toString(),
                     install.value(QStringLiteral("kind")).toString(),
                     install.value(QStringLiteral("state")).toString())
                .arg(install.value(QStringLiteral("candidate_count")).toInteger()));
        if (install.contains(QStringLiteral("main_executable"))) {
            printCandidate(QStringLiteral("main:"), install.value(QStringLiteral("main_executable")).toObject());
        }
        for (const QJsonValue &candidate : install.value(QStringLiteral("candidates")).toArray()) {
            printCandidate(QStringLiteral("candidate #%1:")
                               .arg(candidate.toObject().value(QStringLiteral("candidate_id")).toInteger()),
                           candidate.toObject());
        }
    }
    return kOk;
}

int cmdStatus(Source &source, bool json)
{
    QString error;
    const auto health = source.call(QStringLiteral("GetHealth"), {}, error);
    if (!health) {
        err(QStringLiteral("status failed: %1").arg(error));
        return kError;
    }
    const auto progress = source.call(QStringLiteral("GetProgress"), {}, error);
    if (json) {
        // storage/db also at the top level: the 360io CLI envelope keeps the
        // scanner's keys as they are, and scripts check them without "health".
        QJsonObject combined{{QStringLiteral("health"), *health},
                             {QStringLiteral("storage"), health->value(QStringLiteral("storage"))},
                             {QStringLiteral("db"), health->value(QStringLiteral("db"))}};
        if (progress) {
            combined.insert(QStringLiteral("progress"), *progress);
        }
        printJson(combined);
        return kOk;
    }
    const QJsonObject storage = health->value(QStringLiteral("storage")).toObject();
    out(QStringLiteral("storage:  %1 (root %2, policy %3, fs %4)")
            .arg(storage.value(QStringLiteral("state")).toString(), storage.value(QStringLiteral("root")).toString(),
                 storage.value(QStringLiteral("policy")).toString(),
                 storage.value(QStringLiteral("fs_type")).toString(QStringLiteral("-"))));
    const QJsonObject db = health->value(QStringLiteral("db")).toObject();
    out(QStringLiteral("database: %1, schema v%2%3")
            .arg(db.value(QStringLiteral("state")).toString())
            .arg(db.value(QStringLiteral("schema_version")).toInteger())
            .arg(db.value(QStringLiteral("read_only")).toBool() ? QStringLiteral(", read-only") : QString()));
    const QJsonObject io = health->value(QStringLiteral("io_backend")).toObject();
    out(QStringLiteral("io:       %1 (%2)")
            .arg(io.value(QStringLiteral("kind")).toString(), io.value(QStringLiteral("reason")).toString()));
    const QJsonObject watches = health->value(QStringLiteral("watches")).toObject();
    out(QStringLiteral("inotify:  %1, %2/%3 watches")
            .arg(watches.value(QStringLiteral("available")).toBool() ? QStringLiteral("on")
                                                                       : QStringLiteral("off (periodic rescans)"))
            .arg(watches.value(QStringLiteral("used")).toInteger())
            .arg(watches.value(QStringLiteral("budget")).toInteger()));
    out(QStringLiteral("games:    %1").arg(compact(health->value(QStringLiteral("games_by_state")))));
    if (progress) {
        out(QStringLiteral("progress: %1").arg(compact(*progress)));
    }
    return kOk;
}

// Every game with its full GetGame detail in one document; the 360io CLI
// builds the official game contract (docs/game-library-contract.md) from it.
int cmdExport(Source &source)
{
    QString error;
    const auto games = allGames(source, error);
    if (!games) {
        err(QStringLiteral("export failed: %1").arg(error));
        return kError;
    }
    QJsonArray detailed;
    for (const QJsonValue &value : *games) {
        const QString gameId = value.toObject().value(QStringLiteral("game_id")).toString();
        const auto game = source.call(QStringLiteral("GetGame"), {{QStringLiteral("game_id"), gameId}}, error);
        if (!game) {
            err(QStringLiteral("export failed on %1: %2").arg(gameId, error));
            return kError;
        }
        detailed.append(*game);
    }
    QJsonObject result{{QStringLiteral("games"), detailed}};
    if (const auto health = source.call(QStringLiteral("GetHealth"), {}, error)) {
        result.insert(QStringLiteral("storage"), health->value(QStringLiteral("storage")));
    }
    printJson(result);
    return kOk;
}

int cmdScan(Source &source, const QString &gameId, bool full, bool json)
{
    QString error;
    const QJsonObject params{{QStringLiteral("scope"), gameId.isEmpty() ? QStringLiteral("all") : gameId},
                             {QStringLiteral("mode"), full ? QStringLiteral("full") : QStringLiteral("cheap")}};
    const auto reply = source.call(QStringLiteral("Rescan"), params, error);
    if (!reply) {
        err(QStringLiteral("scan failed: %1").arg(error));
        return kError;
    }
    if (json) {
        printJson(*reply);
    } else {
        out(QStringLiteral("rescan queued: request %1, %2 install(s)")
                .arg(reply->value(QStringLiteral("request_id")).toInteger())
                .arg(reply->value(QStringLiteral("queued")).toInt()));
    }
    return kOk;
}

} // namespace

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("360io-library"));

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral(
        "360io /games library client.\n\n"
        "Commands:\n"
        "  status             storage, database, I/O backend and scan progress\n"
        "  list               games known to the library\n"
        "  show <game_id>     installs, main executable, PE metadata, candidates\n"
        "  scan [<game_id>]   request a rescan (control role; --full rescans everything)\n"
        "  export             every game with full detail, as JSON (used by 360io)"));
    parser.addHelpOption();
    parser.addPositionalArgument(QStringLiteral("command"), QStringLiteral("status | list | show | scan | export"));
    const QCommandLineOption socketOption(
        QStringLiteral("socket"), QStringLiteral("Library API socket."), QStringLiteral("path"),
        qEnvironmentVariable("THREESIXTY_LIBRARY_SOCKET", QStringLiteral("/run/360io/library.sock")));
    const QCommandLineOption jsonOption(QStringLiteral("json"), QStringLiteral("Print raw JSON."));
    const QCommandLineOption fullOption(QStringLiteral("full"), QStringLiteral("scan: full rescan instead of cheap."));
    const QCommandLineOption offlineOption(
        QStringLiteral("offline"),
        QStringLiteral("Scan in-process instead of asking 360iod. Never point it at the database 360iod uses."));
    const QCommandLineOption rootOption(QStringLiteral("root"), QStringLiteral("Offline: library root."),
                                        QStringLiteral("dir"), QStringLiteral("/games"));
    const QCommandLineOption dbOption(QStringLiteral("db"), QStringLiteral("Offline: SQLite database."),
                                      QStringLiteral("path"));
    const QCommandLineOption policyOption(
        QStringLiteral("policy"),
        QStringLiteral("Offline mount policy: strict, directory (default)"
#ifdef THREESIXTY_LIBRARY_ALLOW_ANY_FS
                       " or any"
#endif
                       "."),
        QStringLiteral("policy"), QStringLiteral("directory"));
    const QCommandLineOption timeoutOption(QStringLiteral("timeout"),
                                           QStringLiteral("Offline: max seconds to wait for the scan."),
                                           QStringLiteral("sec"), QStringLiteral("600"));
    const QCommandLineOption verboseOption(QStringLiteral("verbose"), QStringLiteral("Offline: scanner logs."));
    parser.addOptions({socketOption, jsonOption, fullOption, offlineOption, rootOption, dbOption, policyOption,
                       timeoutOption, verboseOption});
    parser.process(app);

    const QStringList args = parser.positionalArguments();
    const QString command = args.value(0);
    const bool json = parser.isSet(jsonOption);
    if (command.isEmpty() || !QStringList{"status", "list", "show", "scan", "export"}.contains(command) ||
        (command == QStringLiteral("show") && args.size() != 2) || args.size() > 2 ||
        (args.size() == 2 && command != QStringLiteral("show") && command != QStringLiteral("scan"))) {
        parser.showHelp(kUsage);
    }

    std::unique_ptr<Source> source;
    QString error;
    if (parser.isSet(offlineOption)) {
        if (!parser.isSet(verboseOption)) {
            QLoggingCategory::setFilterRules(QStringLiteral("threesixty.library.info=false"));
        }
        LibraryConfig config;
        config.rootPath = parser.value(rootOption).toStdString();
        if (!parser.isSet(dbOption)) {
            err(QStringLiteral("--offline needs --db (keep it apart from the 360iod database)"));
            return kUsage;
        }
        config.databasePath = parser.value(dbOption).toStdString();
        const QString policy = parser.value(policyOption);
        if (policy == QStringLiteral("strict")) {
            config.mountPolicy = MountPolicy::Strict;
        } else if (policy == QStringLiteral("directory")) {
            config.mountPolicy = MountPolicy::Directory;
#ifdef THREESIXTY_LIBRARY_ALLOW_ANY_FS
        } else if (policy == QStringLiteral("any")) {
            config.mountPolicy = MountPolicy::AnyFilesystem;
#endif
        } else {
            err(QStringLiteral("unknown --policy %1").arg(policy));
            return kUsage;
        }
        // One-shot run: no copy can be in progress that we would wait for.
        config.debounce = std::chrono::milliseconds(100);
        config.quietWindow = std::chrono::milliseconds(300);
        config.tick = std::chrono::milliseconds(50);
        auto offline = std::make_unique<OfflineSource>(config);
        if (!offline->start(std::chrono::seconds(parser.value(timeoutOption).toInt()), error)) {
            err(error);
            return kError;
        }
        source = std::move(offline);
    } else {
        auto socket = std::make_unique<SocketSource>();
        if (!socket->connect(parser.value(socketOption), error)) {
            err(error + QStringLiteral(" (is 360iod running with 360io-library installed? "
                                       "try --offline --db <path>)"));
            return kUnreachable;
        }
        source = std::move(socket);
    }

    if (command == QStringLiteral("list")) {
        return cmdList(*source, json);
    }
    if (command == QStringLiteral("show")) {
        return cmdShow(*source, args.at(1), json);
    }
    if (command == QStringLiteral("status")) {
        return cmdStatus(*source, json);
    }
    if (command == QStringLiteral("export")) {
        return cmdExport(*source);
    }
    // Offline "scan" already scanned on start; --full forces a second, full pass.
    if (parser.isSet(offlineOption) && !parser.isSet(fullOption) && args.size() == 1) {
        return json ? cmdStatus(*source, true) : cmdList(*source, false);
    }
    return cmdScan(*source, args.value(1), parser.isSet(fullOption), json);
}
