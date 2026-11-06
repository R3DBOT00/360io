#pragma once

// Local library API (§11): NDJSON over a local socket, same framing as the
// Kinect bridge ({"protocol":1, "id":n, "type":...}). Peers are identified
// with SO_PEERCRED; methods are split into read/control roles and rate
// limited per UID. The dashboard is just one client among others.

#include "library_service.hpp"

#include <QHash>
#include <QLocalServer>
#include <QObject>

#include <deque>
#include <map>

#include <sys/types.h>

class QLocalSocket;

namespace threesixty::daemon::library {

class LibraryApiServer final : public QObject
{
    Q_OBJECT

public:
    enum class Role { None, Read, Control };

    explicit LibraryApiServer(LibraryService &service, QObject *parent = nullptr);
    ~LibraryApiServer() override;

    bool listen(const QString &serverName);
    QString errorString() const;
    QString fullServerName() const { return m_server.fullServerName(); }

    struct Stats {
        quint64 requests = 0;
        quint64 rateLimited = 0;
        quint64 authDenied = 0;
        quint64 subscriberResyncs = 0;
    };
    const Stats &stats() const { return m_stats; }

    // Test hook: shrink the per-subscriber queue.
    void setSubscriberQueueLimit(int limit) { m_subscriberQueueLimit = limit; }

private:
    struct Bucket {
        double tokens = 0;
        double capacity = 0;
        double refillPerSecond = 0;
        qint64 lastMs = 0;
    };
    struct Client {
        uid_t uid = 0;
        Role role = Role::None;
        bool subscribed = false;
        qint64 lastSeq = 0;
        std::deque<QByteArray> queue;
    };

    void acceptConnection();
    void readClientData(QLocalSocket *socket);
    void handleMessage(QLocalSocket *socket, const QByteArray &line);
    void deliverEvent(const LibraryEvent &event);
    void enqueueEvent(QLocalSocket *socket, Client &client, const LibraryEvent &event);
    void pump(QLocalSocket *socket);
    void sendLine(QLocalSocket *socket, const QJsonObject &object);
    void sendError(QLocalSocket *socket, const QJsonValue &id, const QString &code,
                   const QString &message = QString(), qint64 retryAfterMs = -1);
    Role roleFor(uid_t uid, gid_t gid) const;
    // Returns 0 when allowed, otherwise the suggested retry delay in ms.
    qint64 consume(uid_t uid, const QString &bucketClass);

    LibraryService &m_service;
    QLocalServer m_server;
    QHash<QLocalSocket *, Client> m_clients;
    std::map<std::pair<uid_t, QString>, Bucket> m_buckets;
    int m_subscription = 0;
    int m_subscriberQueueLimit = 1024;
    Stats m_stats;
};

} // namespace threesixty::daemon::library
