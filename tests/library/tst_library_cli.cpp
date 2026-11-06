// End-to-end test of the 360io-library CLI over a fake /games tree in a tmp
// dir: Steam library + plain directories, installer/redist exclusions, PE
// metadata and readable fallback names; offline mode and API socket mode.
#include "test_support.hpp"

#include "library_api.hpp"
#include "library_service.hpp"

#include <QCoreApplication>
#include <QEventLoop>
#include <QJsonArray>
#include <QJsonDocument>
#include <QProcess>
#include <QTimer>

using namespace threesixty::daemon::library;
using namespace libtest;
using namespace std::chrono_literals;

namespace {

struct Run {
    int exitCode = -1;
    QByteArray out;
    QByteArray err;
    QJsonObject json() const { return QJsonDocument::fromJson(out).object(); }
};

// Runs the CLI without blocking the event loop (socket mode needs the API
// server in this process to keep answering).
Run cli(const QStringList &args)
{
    QProcess process;
    QEventLoop loop;
    QObject::connect(&process, &QProcess::finished, &loop, &QEventLoop::quit);
    QObject::connect(&process, &QProcess::errorOccurred, &loop, &QEventLoop::quit);
    QTimer::singleShot(120000, &loop, &QEventLoop::quit);
    process.start(QStringLiteral(THREESIXTY_LIBRARY_CLI), args);
    loop.exec();
    Run run;
    if (process.state() != QProcess::NotRunning) {
        process.kill();
        process.waitForFinished();
        return run;
    }
    run.exitCode = process.exitStatus() == QProcess::NormalExit ? process.exitCode() : -1;
    run.out = process.readAllStandardOutput();
    run.err = process.readAllStandardError();
    if (run.exitCode != 0) {
        std::fprintf(stderr, "   cli %s -> %d: %s\n", args.join(' ').toUtf8().constData(), run.exitCode,
                     run.err.left(400).constData());
    }
    return run;
}

PeSpec named(const std::u16string &product, const std::u16string &description = {})
{
    PeSpec spec;
    spec.tables = {{"040904b0",
                    {{"CompanyName", u"Fake Studio"},
                     {"ProductName", product},
                     {"FileDescription", description.empty() ? product : description},
                     {"ProductVersion", u"1.0.4"}}}};
    spec.padTo = 2u << 20;
    return spec;
}

void writePe(const std::string &path, const PeSpec &spec)
{
    fs::create_directories(fs::path(path).parent_path());
    writeBytes(path, buildPe(spec));
}

// Fake /games: a Steam library, plain game directories and noise.
void buildTree(const TempDir &root)
{
    PeSpec bare;
    bare.withVersion = false;
    bare.padTo = 3u << 20;

    const std::string steam = root / "SteamLibrary/steamapps";
    fs::create_directories(steam);
    writeFile(steam + "/appmanifest_620.acf", acf(620, "Portal 2", "Portal 2"));
    writePe(steam + "/common/Portal 2/portal2.exe", named(u"Portal 2"));
    writePe(steam + "/common/Portal 2/_CommonRedist/vcredist/2019/VC_redist.x64.exe", named(u"Visual C++"));
    writePe(steam + "/common/Portal 2/_CommonRedist/DirectX/Jun2010/DXSETUP.exe", named(u"DirectX"));

    writePe(root / "Hollow_Knight/hollow_knight.exe", bare);
    writePe(root / "Hollow_Knight/UnityCrashHandler64.exe", named(u"Unity"));
    writePe(root / "Hollow_Knight/unins000.exe", named(u"Setup"));

    writePe(root / "Fixture Quest/FixtureQuest.exe", named(u"Fixture Quest", u"Fixture Quest Game"));
    writePe(root / "Fixture Quest/Redist/dotNetFx40_Full_x86_x64.exe", named(u"Microsoft .NET"));
    writePe(root / "Fixture Quest/Engine/Binaries/Win64/CrashReportClient.exe", named(u"CrashReportClient"));
    writePe(root / "Fixture Quest/EasyAntiCheat/EasyAntiCheat_EOS_Setup.exe", named(u"EAC"));

    writePe(root / "Only Installers/unins000.exe", named(u"Setup"));
    writePe(root / "Only Installers/vcredist_x64.exe", named(u"Visual C++"));

    fs::create_directories(root / "Music");
    writeFile(root / "Music/track.ogg", "not a game");
}

std::map<std::string, QJsonObject> byName(const QJsonObject &list)
{
    std::map<std::string, QJsonObject> out;
    for (const QJsonValue &value : list.value(QStringLiteral("games")).toArray()) {
        out[value.toObject().value(QStringLiteral("display_name")).toString().toStdString()] = value.toObject();
    }
    return out;
}

QString mainExe(const QJsonObject &game)
{
    const QJsonArray installs = game.value(QStringLiteral("installs")).toArray();
    return installs.isEmpty() ? QString()
                              : installs.first().toObject().value(QStringLiteral("main_executable")).toObject()
                                    .value(QStringLiteral("rel_path")).toString();
}

void checkCatalogue(const std::map<std::string, QJsonObject> &games, const std::function<QJsonObject(QString)> &show)
{
    // "Music" has no executable and "Only Installers" only excluded ones:
    // neither becomes a game record.
    CHECK_EQ(games.size(), std::size_t(3));
    CHECK(games.count("Music") == 0);
    CHECK(games.count("Only Installers") == 0);
    if (games.size() != 3 || !games.count("Portal 2") || !games.count("Hollow Knight") ||
        !games.count("Fixture Quest")) {
        for (const auto &[name, game] : games) {
            std::fprintf(stderr, "   got %s\n", name.c_str());
        }
        return;
    }
    const auto id = [&](const char *name) {
        return games.at(name).value(QStringLiteral("game_id")).toString();
    };

    CHECK_EQ(games.at("Portal 2").value(QStringLiteral("kind")).toString(), QStringLiteral("steam"));
    CHECK_EQ(games.at("Portal 2").value(QStringLiteral("state")).toString(), QStringLiteral("READY"));
    const QJsonObject portal = show(id("Portal 2"));
    CHECK_EQ(portal.value(QStringLiteral("display_name_source")).toString(), QStringLiteral("steam_acf"));
    CHECK_EQ(portal.value(QStringLiteral("steam_appid")).toInteger(), 620);
    CHECK_EQ(mainExe(portal), QStringLiteral("portal2.exe"));

    // No VS_VERSION_INFO: readable name from the directory, main exe still chosen.
    CHECK_EQ(games.at("Hollow Knight").value(QStringLiteral("state")).toString(), QStringLiteral("READY"));
    const QJsonObject hollow = show(id("Hollow Knight"));
    CHECK_EQ(hollow.value(QStringLiteral("display_name_source")).toString(), QStringLiteral("directory"));
    CHECK_EQ(mainExe(hollow), QStringLiteral("hollow_knight.exe"));

    // PE metadata wins over the directory name.
    const QJsonObject quest = show(id("Fixture Quest"));
    CHECK_EQ(quest.value(QStringLiteral("state")).toString(), QStringLiteral("READY"));
    CHECK_EQ(quest.value(QStringLiteral("display_name_source")).toString(), QStringLiteral("product_name"));
    CHECK_EQ(mainExe(quest), QStringLiteral("FixtureQuest.exe"));
    const QJsonObject questMain = quest.value(QStringLiteral("installs")).toArray().first().toObject()
                                      .value(QStringLiteral("main_executable")).toObject();
    CHECK_EQ(questMain.value(QStringLiteral("company_name")).toString(), QStringLiteral("Fake Studio"));
    CHECK_EQ(questMain.value(QStringLiteral("product_version")).toString(), QStringLiteral("1.0.4"));
}

void testOffline()
{
    section("offline: fake tree scan, list, show, status");
    TempDir root("360io-fakegames");
    TempDir state("360io-clistate");
    buildTree(root);
    const QString db = QString::fromStdString(state / "library/library.db");
    fs::create_directories(state / "library");
    const QStringList base{QStringLiteral("--offline"), QStringLiteral("--policy"), QStringLiteral("any"),
                           QStringLiteral("--root"), QString::fromStdString(root.path()), QStringLiteral("--db"), db};

    const Run list = cli(base + QStringList{QStringLiteral("list"), QStringLiteral("--json")});
    CHECK_EQ(list.exitCode, 0);
    checkCatalogue(byName(list.json()), [&](const QString &id) {
        return cli(base + QStringList{QStringLiteral("show"), id, QStringLiteral("--json")}).json();
    });

    const Run text = cli(base + QStringList{QStringLiteral("list")});
    CHECK_EQ(text.exitCode, 0);
    CHECK(text.out.contains("Hollow Knight"));
    CHECK(!text.out.contains("Only Installers"));
    CHECK(text.out.contains("3 game(s)"));

    const Run status = cli(base + QStringList{QStringLiteral("status"), QStringLiteral("--json")});
    CHECK_EQ(status.exitCode, 0);
    const QJsonObject storage = status.json().value(QStringLiteral("health")).toObject()
                                    .value(QStringLiteral("storage")).toObject();
    CHECK_EQ(storage.value(QStringLiteral("state")).toString(), QStringLiteral("AVAILABLE"));

    // export: every game with its GetGame detail (consumed by the 360io CLI).
    const Run exported = cli(base + QStringList{QStringLiteral("export")});
    CHECK_EQ(exported.exitCode, 0);
    const QJsonArray exportedGames = exported.json().value(QStringLiteral("games")).toArray();
    CHECK_EQ(exportedGames.size(), qsizetype(3));
    for (const QJsonValue &game : exportedGames) {
        CHECK(!game.toObject().value(QStringLiteral("installs")).toArray().isEmpty());
    }
    CHECK_EQ(exported.json().value(QStringLiteral("storage")).toObject().value(QStringLiteral("state")).toString(),
             QStringLiteral("AVAILABLE"));

    // Database persisted: a second run reuses ids; a full rescan keeps them.
    const auto first = byName(list.json());
    const Run again = cli(base + QStringList{QStringLiteral("scan"), QStringLiteral("--full"), QStringLiteral("--json")});
    CHECK_EQ(again.exitCode, 0);
    const auto second = byName(cli(base + QStringList{QStringLiteral("list"), QStringLiteral("--json")}).json());
    CHECK(first.size() == second.size());
    for (const auto &[name, game] : first) {
        CHECK(second.count(name) == 1 &&
              second.at(name).value(QStringLiteral("game_id")) == game.value(QStringLiteral("game_id")));
    }

    // Default policy (directory) rejects tmpfs but never touches the tree.
    if (validateLibraryMount([&] {
            LibraryConfig c;
            c.rootPath = root.path();
            c.mountPolicy = MountPolicy::Directory;
            return c;
        }()).fsType == "tmpfs") {
        TempDir other("360io-clistate2");
        const Run strict = cli({QStringLiteral("--offline"), QStringLiteral("--root"),
                                QString::fromStdString(root.path()), QStringLiteral("--db"),
                                QString::fromStdString(other / "l.db"), QStringLiteral("status"),
                                QStringLiteral("--json")});
        CHECK_EQ(strict.exitCode, 0);
        CHECK_EQ(strict.json().value(QStringLiteral("health")).toObject().value(QStringLiteral("storage"))
                     .toObject().value(QStringLiteral("state")).toString(),
                 QStringLiteral("UNSUPPORTED_FS"));
    }

    const Run usage = cli({QStringLiteral("frobnicate")});
    CHECK_EQ(usage.exitCode, 2);
    const Run noDb = cli({QStringLiteral("--offline"), QStringLiteral("list")});
    CHECK_EQ(noDb.exitCode, 2);
}

void testSocket()
{
    section("socket: CLI against LibraryApiServer");
    TempDir root("360io-fakegames");
    TempDir state("360io-clistate");
    buildTree(root);
    LibraryConfig config;
    config.rootPath = root.path();
    config.databasePath = state / "library.db";
    config.mountPolicy = MountPolicy::AnyFilesystem;
    config.debounce = 100ms;
    config.quietWindow = 300ms;
    config.tick = 50ms;
    LibraryService service(config);
    CHECK(service.start());
    CHECK(service.waitIdle(60s));
    LibraryApiServer api(service);
    const QString socket = QString::fromStdString(state / "library.sock");
    CHECK(api.listen(socket));
    const QStringList base{QStringLiteral("--socket"), socket};

    const Run list = cli(base + QStringList{QStringLiteral("list"), QStringLiteral("--json")});
    CHECK_EQ(list.exitCode, 0);
    checkCatalogue(byName(list.json()), [&](const QString &id) {
        return cli(base + QStringList{QStringLiteral("show"), id, QStringLiteral("--json")}).json();
    });
    const Run status = cli(base + QStringList{QStringLiteral("status")});
    CHECK_EQ(status.exitCode, 0);
    CHECK(status.out.contains("storage:  AVAILABLE"));
    const Run scan = cli(base + QStringList{QStringLiteral("scan")});
    CHECK_EQ(scan.exitCode, 0);
    CHECK(scan.out.contains("rescan queued"));
    CHECK(service.waitIdle(60s));
    const Run missing = cli(base + QStringList{QStringLiteral("show"), QStringLiteral("nope")});
    CHECK_EQ(missing.exitCode, 1);
    service.stop();

    const Run down = cli({QStringLiteral("--socket"), QString::fromStdString(state / "absent.sock"),
                          QStringLiteral("status")});
    CHECK_EQ(down.exitCode, 3);
}

} // namespace

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    testOffline();
    testSocket();
    return finish("library.cli");
}
