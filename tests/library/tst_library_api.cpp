// Local NDJSON API over a Unix socket placed in a tmp directory: framing,
// list/get/rescan/health/progress, events with since_seq and resync, errors,
// message limit, rate limiting and subscriber overflow.
#include "test_support.hpp"

#include "library_api.hpp"
#include "library_service.hpp"

#include <QCoreApplication>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLocalSocket>

using namespace threesixty::daemon::library;
using namespace libtest;
using namespace std::chrono_literals;

namespace {

class Client
{
public:
    explicit Client(const QString &name)
    {
        m_socket.connectToServer(name);
        m_connected = m_socket.waitForConnected(2000);
    }
    bool connected() const { return m_connected; }

    void sendRaw(const QByteArray &bytes)
    {
        m_socket.write(bytes);
        m_socket.flush();
    }
    QJsonObject call(QJsonObject request)
    {
        request.insert(QStringLiteral("protocol"), 1);
        request.insert(QStringLiteral("id"), ++m_id);
        sendRaw(QJsonDocument(request).toJson(QJsonDocument::Compact) + '\n');
        return next([&](const QJsonObject &o) { return o.value(QStringLiteral("id")).toInt() == m_id; });
    }
    QJsonObject next(const std::function<bool(const QJsonObject &)> &match, std::chrono::milliseconds timeout = 5s)
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            for (auto it = m_inbox.begin(); it != m_inbox.end(); ++it) {
                if (match(*it)) {
                    QJsonObject out = *it;
                    m_inbox.erase(it);
                    return out;
                }
            }
            QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
            m_socket.waitForReadyRead(5);
            while (m_socket.canReadLine()) {
                m_inbox.push_back(QJsonDocument::fromJson(m_socket.readLine()).object());
            }
            if (m_socket.state() != QLocalSocket::ConnectedState && !m_socket.canReadLine() && m_inbox.empty()) {
                break;
            }
        }
        return {};
    }
    std::vector<QJsonObject> events(std::chrono::milliseconds window)
    {
        std::vector<QJsonObject> out;
        const auto deadline = std::chrono::steady_clock::now() + window;
        while (std::chrono::steady_clock::now() < deadline) {
            QJsonObject e = next([](const QJsonObject &o) {
                return o.value(QStringLiteral("type")).toString() == QStringLiteral("event");
            }, 50ms);
            if (!e.isEmpty()) {
                out.push_back(e);
            }
        }
        return out;
    }
    QLocalSocket &socket() { return m_socket; }

private:
    QLocalSocket m_socket;
    bool m_connected = false;
    int m_id = 0;
    std::vector<QJsonObject> m_inbox;
};

QString errorCode(const QJsonObject &reply)
{
    return reply.value(QStringLiteral("error")).toObject().value(QStringLiteral("code")).toString();
}

bool ok(const QJsonObject &reply)
{
    return reply.value(QStringLiteral("status")).toString() == QStringLiteral("ok");
}

void pumpUntil(const std::function<bool()> &predicate, std::chrono::milliseconds timeout)
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!predicate() && std::chrono::steady_clock::now() < deadline) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        std::this_thread::sleep_for(5ms);
    }
}

void testApi()
{
    TempDir root;
    TempDir state("360io-state");
    PeSpec spec;
    spec.tables = {{"040904b0", {{"ProductName", u"Api Quest"}}}};
    writeBytes(root / "Api Quest/ApiQuest.exe", buildPe(spec));

    LibraryConfig config;
    config.rootPath = root.path();
    config.databasePath = state / "library.db";
    config.mountPolicy = MountPolicy::AnyFilesystem;
    config.debounce = 100ms;
    config.quietWindow = 300ms;
    config.tick = 50ms;
    LibraryService service(config);
    CHECK(service.start());
    CHECK(service.waitIdle(20s));

    LibraryApiServer server(service);
    const QString socketPath = QString::fromStdString(state / "library.sock");
    CHECK(server.listen(socketPath));

    Client client(socketPath);
    CHECK(client.connected());

    section("hello / framing");
    QJsonObject reply = client.call({{QStringLiteral("type"), QStringLiteral("hello")}});
    CHECK(ok(reply));
    CHECK_EQ(reply.value(QStringLiteral("protocol")).toInt(), 1);
    CHECK_EQ(reply.value(QStringLiteral("result")).toObject().value(QStringLiteral("role")).toString(),
             QStringLiteral("control")); // same uid as the daemon

    section("ListGames / GetGame");
    reply = client.call({{QStringLiteral("type"), QStringLiteral("ListGames")}});
    CHECK(ok(reply));
    const QJsonArray games = reply.value(QStringLiteral("result")).toObject().value(QStringLiteral("games")).toArray();
    CHECK_EQ(games.size(), qsizetype(1));
    const QString gameId = games.isEmpty() ? QString() : games.first().toObject().value(QStringLiteral("game_id")).toString();
    CHECK(reply.value(QStringLiteral("result")).toObject().contains(QStringLiteral("library_seq")));
    reply = client.call({{QStringLiteral("type"), QStringLiteral("ListGames")},
                         {QStringLiteral("filter"), QJsonObject{{QStringLiteral("state"), QJsonArray{QStringLiteral("AMBIGUOUS")}}}}});
    CHECK(ok(reply) && reply.value(QStringLiteral("result")).toObject().value(QStringLiteral("games")).toArray().isEmpty());
    reply = client.call({{QStringLiteral("type"), QStringLiteral("ListGames")},
                         {QStringLiteral("filter"), QJsonObject{{QStringLiteral("state"), QJsonArray{QStringLiteral("BOGUS")}}}}});
    CHECK_EQ(errorCode(reply), QStringLiteral("INVALID_ARGUMENT"));
    reply = client.call({{QStringLiteral("type"), QStringLiteral("GetGame")}, {QStringLiteral("game_id"), gameId}});
    CHECK(ok(reply));
    const QJsonObject game = reply.value(QStringLiteral("result")).toObject();
    CHECK_EQ(game.value(QStringLiteral("display_name")).toString(), QStringLiteral("Api Quest"));
    CHECK_EQ(game.value(QStringLiteral("state")).toString(), QStringLiteral("READY"));
    const QByteArray gameText = QJsonDocument(game).toJson();
    CHECK(!gameText.contains(QByteArray::fromStdString(root.path()))); // relative paths only
    reply = client.call({{QStringLiteral("type"), QStringLiteral("GetGame")}, {QStringLiteral("game_id"), QStringLiteral("nope")}});
    CHECK_EQ(errorCode(reply), QStringLiteral("NOT_FOUND"));

    section("GetHealth / GetProgress");
    reply = client.call({{QStringLiteral("type"), QStringLiteral("GetHealth")}});
    CHECK(ok(reply));
    const QJsonObject health = reply.value(QStringLiteral("result")).toObject();
    CHECK(health.contains(QStringLiteral("io_backend")));
    CHECK(health.contains(QStringLiteral("api")));
    CHECK_EQ(health.value(QStringLiteral("db")).toObject().value(QStringLiteral("schema_version")).toInt(), 2);
    reply = client.call({{QStringLiteral("type"), QStringLiteral("GetProgress")}});
    CHECK(ok(reply) && reply.value(QStringLiteral("result")).toObject().contains(QStringLiteral("phase")));

    section("errors: unknown method, bad JSON, bad protocol, oversize");
    CHECK_EQ(errorCode(client.call({{QStringLiteral("type"), QStringLiteral("DropTables")}})), QStringLiteral("UNKNOWN_METHOD"));
    client.sendRaw("{not json\n");
    reply = client.next([](const QJsonObject &o) { return o.value(QStringLiteral("status")).toString() == QStringLiteral("error"); });
    CHECK_EQ(errorCode(reply), QStringLiteral("INVALID_JSON"));
    reply = client.call({{QStringLiteral("type"), QStringLiteral("hello")}, {QStringLiteral("protocol"), 7}});
    // call() overrides protocol to 1; send a raw one instead.
    client.sendRaw("{\"protocol\":7,\"id\":900,\"type\":\"hello\"}\n");
    reply = client.next([](const QJsonObject &o) { return o.value(QStringLiteral("id")).toInt() == 900; });
    CHECK_EQ(errorCode(reply), QStringLiteral("UNSUPPORTED_PROTOCOL"));
    CHECK_EQ(errorCode(client.call({{QStringLiteral("type"), QStringLiteral("SetMainExecutable")},
                                    {QStringLiteral("game_id"), gameId},
                                    {QStringLiteral("candidate_id"), QStringLiteral("x")}})),
             QStringLiteral("INVALID_ARGUMENT"));

    section("Rescan + rate limit");
    reply = client.call({{QStringLiteral("type"), QStringLiteral("Rescan")}, {QStringLiteral("scope"), gameId}});
    CHECK(ok(reply));
    reply = client.call({{QStringLiteral("type"), QStringLiteral("Rescan")}, {QStringLiteral("mode"), QStringLiteral("cheap")}});
    CHECK(ok(reply));
    reply = client.call({{QStringLiteral("type"), QStringLiteral("Rescan")}, {QStringLiteral("mode"), QStringLiteral("cheap")}});
    CHECK_EQ(errorCode(reply), QStringLiteral("RATE_LIMITED"));
    CHECK(reply.value(QStringLiteral("error")).toObject().value(QStringLiteral("retry_after_ms")).toInteger() > 0);
    CHECK_EQ(errorCode(client.call({{QStringLiteral("type"), QStringLiteral("Rescan")}, {QStringLiteral("mode"), QStringLiteral("deep")}})),
             QStringLiteral("INVALID_ARGUMENT"));
    pumpUntil([&] { return service.waitIdle(50ms); }, 20s);

    section("SubscribeLibraryEvents: backlog, live, resync");
    Client subscriber(socketPath);
    reply = subscriber.call({{QStringLiteral("type"), QStringLiteral("SubscribeLibraryEvents")}, {QStringLiteral("since_seq"), 0}});
    CHECK(ok(reply));
    auto backlog = subscriber.events(500ms);
    bool sawAdded = false;
    qint64 lastSeq = 0;
    bool increasing = true;
    for (const auto &e : backlog) {
        sawAdded = sawAdded || e.value(QStringLiteral("event")).toString() == QStringLiteral("game.added");
        const qint64 seq = e.value(QStringLiteral("seq")).toInteger();
        increasing = increasing && seq > lastSeq;
        lastSeq = seq;
    }
    CHECK(sawAdded);
    CHECK(increasing);

    // Live: a new game shows up as events on the subscription.
    writeBytes(root / "Live Game/Live.exe", buildPe(spec));
    bool sawLive = false;
    const auto deadline = std::chrono::steady_clock::now() + 15s;
    while (!sawLive && std::chrono::steady_clock::now() < deadline) {
        for (const auto &e : subscriber.events(200ms)) {
            sawLive = sawLive || (e.value(QStringLiteral("event")).toString() == QStringLiteral("game.added"));
        }
    }
    CHECK(sawLive);

    // since_seq outside the retained log -> resync_required.
    Client stale(socketPath);
    pumpUntil([&] { return service.waitIdle(50ms); }, 20s);
    {
        // Trim the log through a second WAL connection while the service is idle.
        LibraryStore store;
        store.open(config.databasePath);
        store.purge(std::chrono::seconds(3600), 1);
        store.close(false);
    }
    reply = stale.call({{QStringLiteral("type"), QStringLiteral("SubscribeLibraryEvents")}, {QStringLiteral("since_seq"), 1}});
    CHECK(ok(reply));
    const QJsonObject resync = stale.next([](const QJsonObject &o) {
        return o.value(QStringLiteral("event")).toString() == QStringLiteral("resync_required");
    });
    CHECK(!resync.isEmpty());

    // Slow subscriber: queue limit exceeded -> resync_required, pipeline unaffected.
    server.setSubscriberQueueLimit(1);
    Client slow(socketPath);
    reply = slow.call({{QStringLiteral("type"), QStringLiteral("SubscribeLibraryEvents")}, {QStringLiteral("since_seq"), 0}});
    CHECK(ok(reply));
    const QJsonObject slowResync = slow.next([](const QJsonObject &o) {
        return o.value(QStringLiteral("event")).toString() == QStringLiteral("resync_required");
    });
    CHECK(!slowResync.isEmpty() || server.stats().subscriberResyncs >= 1);

    section("oversized message closes the connection");
    Client big(socketPath);
    big.sendRaw(QByteArray(70 * 1024, 'x'));
    reply = big.next([](const QJsonObject &o) { return o.value(QStringLiteral("status")).toString() == QStringLiteral("error"); });
    CHECK_EQ(errorCode(reply), QStringLiteral("MESSAGE_TOO_LARGE"));

    CHECK(server.stats().rateLimited >= 1);
    service.stop();
}

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    testApi();
    return finish("tst_library_api");
}
