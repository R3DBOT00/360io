#include "library_api.hpp"

#include "sanitize.hpp"

#include <QDateTime>
#include <QDebug>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocalSocket>
#include <QPointer>

#include <grp.h>
#include <pwd.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <vector>

namespace threesixty::daemon::library {

namespace {

constexpr int kProtocolVersion = 1;
constexpr qsizetype kMaxMessageBytes = 64 * 1024;
constexpr qint64 kSubscriberWriteHighWater = 64 * 1024;
constexpr int kMaxConnectionsPerUid = 16;
constexpr int kMaxConnections = 64;

bool inGroup(uid_t uid, gid_t gid, const char *groupName)
{
    struct group *group = ::getgrnam(groupName);
    if (group == nullptr) {
        return false;
    }
    if (gid == group->gr_gid) {
        return true;
    }
    struct passwd *pw = ::getpwuid(uid);
    if (pw == nullptr) {
        return false;
    }
    int count = 64;
    std::vector<gid_t> groups(static_cast<std::size_t>(count));
    if (::getgrouplist(pw->pw_name, pw->pw_gid, groups.data(), &count) < 0) {
        groups.resize(static_cast<std::size_t>(count));
        if (::getgrouplist(pw->pw_name, pw->pw_gid, groups.data(), &count) < 0) {
            return false;
        }
    }
    groups.resize(static_cast<std::size_t>(count));
    for (gid_t g : groups) {
        if (g == group->gr_gid) {
            return true;
        }
    }
    return false;
}

QJsonObject eventJson(const LibraryEvent &event)
{
    QJsonObject object = QJsonDocument::fromJson(QByteArray::fromStdString(event.payloadJson)).object();
    object.insert(QStringLiteral("protocol"), kProtocolVersion);
    object.insert(QStringLiteral("type"), QStringLiteral("event"));
    object.insert(QStringLiteral("seq"), static_cast<qint64>(event.seq));
    object.insert(QStringLiteral("at"), static_cast<qint64>(event.at));
    object.insert(QStringLiteral("event"), QString::fromStdString(event.type));
    if (!event.gameId.empty()) {
        object.insert(QStringLiteral("game_id"), QString::fromStdString(event.gameId));
    }
    return object;
}

} // namespace

LibraryApiServer::LibraryApiServer(LibraryService &service, QObject *parent)
    : QObject(parent)
    , m_service(service)
{
    connect(&m_server, &QLocalServer::newConnection, this, &LibraryApiServer::acceptConnection);
    QPointer<LibraryApiServer> self(this);
    m_subscription = m_service.subscribe([self](const LibraryEvent &event) {
        // Called on the writer thread: hop to the server's thread. A slow
        // subscriber never blocks the pipeline.
        if (self) {
            QMetaObject::invokeMethod(
                self.data(), [self, event] {
                    if (self) {
                        self->deliverEvent(event);
                    }
                },
                Qt::QueuedConnection);
        }
    });
}

LibraryApiServer::~LibraryApiServer()
{
    m_service.unsubscribe(m_subscription);
    // Sockets are children of m_server, which outlives m_clients during
    // member destruction: detach them first so their disconnected() handlers
    // never touch a destroyed client table.
    const QList<QLocalSocket *> sockets = m_clients.keys();
    for (QLocalSocket *socket : sockets) {
        socket->disconnect(this);
        socket->abort();
        delete socket;
    }
    m_clients.clear();
    m_server.close();
}

bool LibraryApiServer::listen(const QString &serverName)
{
    QLocalServer::removeServer(serverName);
    m_server.setSocketOptions(QLocalServer::UserAccessOption | QLocalServer::GroupAccessOption);
    if (!m_server.listen(serverName)) {
        return false;
    }
    // §11.1: socket 0660 owned by group threesixtyio-clients when that group exists
    // (the daemon must be a member). Roles are still decided per peer by
    // SO_PEERCRED; the file mode only keeps everyone else from connecting.
    if (const struct group *clients = ::getgrnam("threesixtyio-clients")) {
        const QByteArray path = QFile::encodeName(m_server.fullServerName());
        if (::chown(path.constData(), static_cast<uid_t>(-1), clients->gr_gid) != 0) {
            qWarning().noquote() << "library: cannot hand socket to group threesixtyio-clients:"
                                 << std::strerror(errno);
        }
    }
    return true;
}

QString LibraryApiServer::errorString() const
{
    return m_server.errorString();
}

LibraryApiServer::Role LibraryApiServer::roleFor(uid_t uid, gid_t gid) const
{
    if (uid == 0 || uid == ::getuid()) {
        return Role::Control;
    }
    if (inGroup(uid, gid, "threesixtyio-library-admin")) {
        return Role::Control;
    }
    if (inGroup(uid, gid, "threesixtyio-clients")) {
        return Role::Read;
    }
    return Role::None;
}

void LibraryApiServer::acceptConnection()
{
    while (QLocalSocket *socket = m_server.nextPendingConnection()) {
        ucred cred {};
        socklen_t len = sizeof cred;
        const int fd = static_cast<int>(socket->socketDescriptor());
        Client client;
        if (fd < 0 || ::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) {
            client.role = Role::None;
        } else {
            client.uid = cred.uid;
            client.role = roleFor(cred.uid, cred.gid);
        }
        int sameUid = 0;
        for (const Client &other : std::as_const(m_clients)) {
            sameUid += other.uid == client.uid ? 1 : 0;
        }
        if (client.role == Role::None || sameUid >= kMaxConnectionsPerUid ||
            m_clients.size() >= kMaxConnections) {
            if (client.role == Role::None) {
                ++m_stats.authDenied;
            }
            sendError(socket, QJsonValue(),
                      client.role == Role::None ? QStringLiteral("PERMISSION_DENIED")
                                                : QStringLiteral("TOO_MANY_CONNECTIONS"));
            socket->disconnectFromServer();
            socket->deleteLater();
            continue;
        }
        m_clients.insert(socket, client);
        connect(socket, &QLocalSocket::readyRead, this, [this, socket] { readClientData(socket); });
        connect(socket, &QLocalSocket::bytesWritten, this, [this, socket] { pump(socket); });
        connect(socket, &QLocalSocket::disconnected, this, [this, socket] {
            m_clients.remove(socket);
            socket->deleteLater();
        });
    }
}

void LibraryApiServer::readClientData(QLocalSocket *socket)
{
    while (m_clients.contains(socket)) {
        if (!socket->canReadLine()) {
            if (socket->bytesAvailable() > kMaxMessageBytes) {
                sendError(socket, QJsonValue(), QStringLiteral("MESSAGE_TOO_LARGE"));
                socket->disconnectFromServer();
            }
            return;
        }
        const QByteArray line = socket->readLine(kMaxMessageBytes + 2);
        if (line.size() > kMaxMessageBytes) {
            sendError(socket, QJsonValue(), QStringLiteral("MESSAGE_TOO_LARGE"));
            socket->disconnectFromServer();
            return;
        }
        const QByteArray trimmed = line.trimmed();
        if (!trimmed.isEmpty()) {
            handleMessage(socket, trimmed);
        }
    }
}

qint64 LibraryApiServer::consume(uid_t uid, const QString &bucketClass)
{
    struct Spec {
        double capacity;
        double perSecond;
    };
    static const std::map<QString, Spec> kSpecs = {
        {QStringLiteral("read"), {100, 50}},
        {QStringLiteral("cover"), {60, 20}},
        {QStringLiteral("rescan_game"), {10, 10.0 / 60}},
        {QStringLiteral("rescan_all_cheap"), {1, 1.0 / 300}},
        {QStringLiteral("rescan_all_full"), {1, 1.0 / 1800}},
        {QStringLiteral("mutation"), {30, 30.0 / 60}},
    };
    const Spec spec = kSpecs.at(bucketClass);
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    auto [it, inserted] = m_buckets.try_emplace({uid, bucketClass});
    Bucket &bucket = it->second;
    if (inserted) {
        bucket.capacity = spec.capacity;
        bucket.refillPerSecond = spec.perSecond;
        bucket.tokens = spec.capacity;
        bucket.lastMs = now;
    }
    bucket.tokens = std::min(bucket.capacity,
                             bucket.tokens + double(now - bucket.lastMs) / 1000.0 * bucket.refillPerSecond);
    bucket.lastMs = now;
    if (bucket.tokens >= 1.0) {
        bucket.tokens -= 1.0;
        return 0;
    }
    return std::max<qint64>(1, qint64((1.0 - bucket.tokens) / bucket.refillPerSecond * 1000.0));
}

void LibraryApiServer::handleMessage(QLocalSocket *socket, const QByteArray &line)
{
    ++m_stats.requests;
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(line, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        sendError(socket, QJsonValue(), QStringLiteral("INVALID_JSON"));
        return;
    }
    const QJsonObject request = document.object();
    const QJsonValue id = request.value(QStringLiteral("id"));
    if (request.value(QStringLiteral("protocol")).toInt(kProtocolVersion) != kProtocolVersion) {
        sendError(socket, id, QStringLiteral("UNSUPPORTED_PROTOCOL"));
        return;
    }
    Client &client = m_clients[socket];
    const QString type = request.value(QStringLiteral("type")).toString();

    static const QStringList kControl = {QStringLiteral("Rescan"), QStringLiteral("SetMainExecutable")};
    static const QStringList kRead = {QStringLiteral("hello"), QStringLiteral("ListGames"),
                                      QStringLiteral("GetGame"), QStringLiteral("GetHealth"),
                                      QStringLiteral("GetProgress"),
                                      QStringLiteral("SubscribeLibraryEvents")};
    if (!kControl.contains(type) && !kRead.contains(type)) {
        sendError(socket, id, QStringLiteral("UNKNOWN_METHOD"));
        return;
    }
    if (kControl.contains(type) && client.role != Role::Control) {
        ++m_stats.authDenied;
        sendError(socket, id, QStringLiteral("PERMISSION_DENIED"));
        return;
    }

    QString bucket = QStringLiteral("read");
    if (type == QStringLiteral("SetMainExecutable")) {
        bucket = QStringLiteral("mutation");
    } else if (type == QStringLiteral("Rescan")) {
        const QString scope = request.value(QStringLiteral("scope")).toString(QStringLiteral("all"));
        const QString mode = request.value(QStringLiteral("mode")).toString(QStringLiteral("cheap"));
        if (mode != QStringLiteral("cheap") && mode != QStringLiteral("full")) {
            // Invalid requests never consume rate-limit tokens.
            sendError(socket, id, QStringLiteral("INVALID_ARGUMENT"), QStringLiteral("mode"));
            return;
        }
        const bool full = mode == QStringLiteral("full");
        bucket = scope == QStringLiteral("all")
            ? (full ? QStringLiteral("rescan_all_full") : QStringLiteral("rescan_all_cheap"))
            : QStringLiteral("rescan_game");
    }
    if (const qint64 retry = consume(client.uid, bucket); retry > 0) {
        ++m_stats.rateLimited;
        sendError(socket, id, QStringLiteral("RATE_LIMITED"), QString(), retry);
        return;
    }

    QJsonObject result;
    if (type == QStringLiteral("hello")) {
        result.insert(QStringLiteral("detail"), QStringLiteral("library-api-ready"));
        result.insert(QStringLiteral("role"),
                      client.role == Role::Control ? QStringLiteral("control") : QStringLiteral("read"));
    } else if (type == QStringLiteral("ListGames")) {
        ListGamesQuery query;
        const QJsonObject filter = request.value(QStringLiteral("filter")).toObject();
        for (const QJsonValue &value : filter.value(QStringLiteral("state")).toArray()) {
            const auto state = gameStateFromName(value.toString().toStdString());
            if (!state) {
                sendError(socket, id, QStringLiteral("INVALID_ARGUMENT"), QStringLiteral("state"));
                return;
            }
            query.states.push_back(*state);
        }
        const QString kind = filter.value(QStringLiteral("kind")).toString();
        if (kind == QStringLiteral("steam")) {
            query.kind = InstallKind::Steam;
        } else if (kind == QStringLiteral("directory")) {
            query.kind = InstallKind::Directory;
        } else if (!kind.isEmpty()) {
            sendError(socket, id, QStringLiteral("INVALID_ARGUMENT"), QStringLiteral("kind"));
            return;
        }
        bool ok = true;
        const QString cursor = request.value(QStringLiteral("cursor")).toString();
        if (!cursor.isEmpty()) {
            query.offset = cursor.toLongLong(&ok);
            if (!ok || query.offset < 0) {
                sendError(socket, id, QStringLiteral("INVALID_ARGUMENT"), QStringLiteral("cursor"));
                return;
            }
        }
        query.limit = std::clamp(request.value(QStringLiteral("limit")).toInt(50), 1, 200);
        result = m_service.listGames(query);
    } else if (type == QStringLiteral("GetGame")) {
        const auto game =
            m_service.getGame(request.value(QStringLiteral("game_id")).toString().toStdString());
        if (!game) {
            sendError(socket, id, QStringLiteral("NOT_FOUND"));
            return;
        }
        result = *game;
    } else if (type == QStringLiteral("GetHealth")) {
        result = m_service.health();
        result.insert(QStringLiteral("api"),
                      QJsonObject{{QStringLiteral("requests_total"), static_cast<qint64>(m_stats.requests)},
                                  {QStringLiteral("rate_limited_total"), static_cast<qint64>(m_stats.rateLimited)},
                                  {QStringLiteral("auth_denied_total"), static_cast<qint64>(m_stats.authDenied)},
                                  {QStringLiteral("subscriber_resyncs_total"),
                                   static_cast<qint64>(m_stats.subscriberResyncs)},
                                  {QStringLiteral("connections"), static_cast<qint64>(m_clients.size())}});
    } else if (type == QStringLiteral("GetProgress")) {
        result = m_service.progress();
    } else if (type == QStringLiteral("Rescan")) {
        const QString scope = request.value(QStringLiteral("scope")).toString(QStringLiteral("all"));
        const QString mode = request.value(QStringLiteral("mode")).toString(QStringLiteral("cheap"));
        if (mode != QStringLiteral("cheap") && mode != QStringLiteral("full")) {
            sendError(socket, id, QStringLiteral("INVALID_ARGUMENT"), QStringLiteral("mode"));
            return;
        }
        const auto reply = m_service.rescan(scope == QStringLiteral("all") ? std::string() : scope.toStdString(),
                                            mode == QStringLiteral("full"));
        if (!reply.ok) {
            sendError(socket, id, QString::fromStdString(reply.error));
            return;
        }
        result.insert(QStringLiteral("request_id"), static_cast<qint64>(reply.requestId));
        result.insert(QStringLiteral("queued"), reply.queued);
    } else if (type == QStringLiteral("SetMainExecutable")) {
        const QJsonValue candidate = request.value(QStringLiteral("candidate_id"));
        std::optional<std::int64_t> candidateId;
        if (!candidate.isNull() && !candidate.isUndefined()) {
            if (!candidate.isDouble()) {
                sendError(socket, id, QStringLiteral("INVALID_ARGUMENT"), QStringLiteral("candidate_id"));
                return;
            }
            candidateId = candidate.toInteger();
        }
        const std::string error = m_service.setMainExecutable(
            request.value(QStringLiteral("game_id")).toString().toStdString(), candidateId);
        if (!error.empty()) {
            sendError(socket, id, QString::fromStdString(error));
            return;
        }
    } else if (type == QStringLiteral("SubscribeLibraryEvents")) {
        client.subscribed = true;
        client.queue.clear();
        const QJsonValue since = request.value(QStringLiteral("since_seq"));
        const qint64 current = m_service.librarySeq();
        client.lastSeq = current;
        result.insert(QStringLiteral("library_seq"), current);
        QJsonObject response{{QStringLiteral("protocol"), kProtocolVersion},
                             {QStringLiteral("id"), id},
                             {QStringLiteral("status"), QStringLiteral("ok")},
                             {QStringLiteral("result"), result}};
        sendLine(socket, response);
        if (!since.isUndefined() && !since.isNull()) {
            bool resync = false;
            const auto backlog = m_service.eventsSince(since.toInteger(), resync);
            if (resync) {
                enqueueEvent(socket, client, LibraryEvent{0, unixMillisNow(), "resync_required", {}, "{}"});
            } else {
                client.lastSeq = since.toInteger();
                for (const LibraryEvent &event : backlog) {
                    enqueueEvent(socket, client, event);
                }
            }
        }
        pump(socket);
        return;
    }

    QJsonObject response{{QStringLiteral("protocol"), kProtocolVersion},
                         {QStringLiteral("id"), id},
                         {QStringLiteral("status"), QStringLiteral("ok")},
                         {QStringLiteral("result"), result}};
    sendLine(socket, response);
}

void LibraryApiServer::enqueueEvent(QLocalSocket *socket, Client &client, const LibraryEvent &event)
{
    if (event.seq != 0) {
        if (event.seq <= client.lastSeq) {
            return; // already delivered (backlog/live overlap)
        }
        client.lastSeq = event.seq;
    }
    if (static_cast<int>(client.queue.size()) >= m_subscriberQueueLimit) {
        // Same semantics as IN_Q_OVERFLOW: drop the queue, ask for a resync.
        client.queue.clear();
        ++m_stats.subscriberResyncs;
        QJsonObject resync{{QStringLiteral("protocol"), kProtocolVersion},
                           {QStringLiteral("type"), QStringLiteral("event")},
                           {QStringLiteral("seq"), static_cast<qint64>(client.lastSeq)},
                           {QStringLiteral("event"), QStringLiteral("resync_required")}};
        client.queue.push_back(QJsonDocument(resync).toJson(QJsonDocument::Compact) + '\n');
        client.subscribed = false;
        return;
    }
    client.queue.push_back(QJsonDocument(eventJson(event)).toJson(QJsonDocument::Compact) + '\n');
    Q_UNUSED(socket);
}

void LibraryApiServer::pump(QLocalSocket *socket)
{
    auto it = m_clients.find(socket);
    if (it == m_clients.end()) {
        return;
    }
    Client &client = it.value();
    while (!client.queue.empty() && socket->bytesToWrite() < kSubscriberWriteHighWater) {
        socket->write(client.queue.front());
        client.queue.pop_front();
    }
}

void LibraryApiServer::deliverEvent(const LibraryEvent &event)
{
    for (auto it = m_clients.begin(); it != m_clients.end(); ++it) {
        if (!it.value().subscribed) {
            continue;
        }
        enqueueEvent(it.key(), it.value(), event);
        pump(it.key());
    }
}

void LibraryApiServer::sendLine(QLocalSocket *socket, const QJsonObject &object)
{
    socket->write(QJsonDocument(object).toJson(QJsonDocument::Compact));
    socket->write("\n");
    socket->flush();
}

void LibraryApiServer::sendError(QLocalSocket *socket, const QJsonValue &id, const QString &code,
                                 const QString &message, qint64 retryAfterMs)
{
    QJsonObject error{{QStringLiteral("code"), code}};
    if (!message.isEmpty()) {
        error.insert(QStringLiteral("message"), message);
    }
    if (retryAfterMs >= 0) {
        error.insert(QStringLiteral("retry_after_ms"), retryAfterMs);
    }
    QJsonObject response{{QStringLiteral("protocol"), kProtocolVersion},
                         {QStringLiteral("status"), QStringLiteral("error")},
                         {QStringLiteral("error"), error}};
    if (!id.isUndefined()) {
        response.insert(QStringLiteral("id"), id);
    }
    sendLine(socket, response);
}

} // namespace threesixty::daemon::library
