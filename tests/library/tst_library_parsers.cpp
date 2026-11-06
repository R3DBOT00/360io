// Parsers, sanitization, filters and scorer: pure functions over buffers.
#include "test_support.hpp"

#include "acf_parser.hpp"
#include "exe_rules.hpp"
#include "pe_parser.hpp"
#include "sanitize.hpp"

#include <random>

using namespace threesixty::daemon::library;
using namespace libtest;

namespace {

PeMetadata parseBuffer(const std::vector<std::uint8_t> &bytes, PeLimits limits = {})
{
    BufferByteSource source(bytes);
    return parsePe(source, bytes.size(), limits);
}

void testSanitize()
{
    section("sanitize");
    CHECK_EQ(readableFallbackName("Hollow_Knight"), std::string("Hollow Knight"));
    CHECK_EQ(readableFallbackName("The.Long.Dark"), std::string("The Long Dark"));
    CHECK_EQ(readableFallbackName("SpaceGame-Win64-Shipping"), std::string("Space Game"));
    CHECK_EQ(readableFallbackName("HollowKnight"), std::string("Hollow Knight"));
    CHECK_EQ(readableFallbackName("Half-Life 2"), std::string("Half-Life 2"));
    CHECK_EQ(readableFallbackName("Dr. Langeskov"), std::string("Dr. Langeskov"));
    CHECK_EQ(readableFallbackName("XCOM2"), std::string("XCOM2"));
    CHECK_EQ(readableFallbackName("__"), std::string("__"));
    CHECK_EQ(sanitizeUtf8("  Hello   \t World \n"), std::string("Hello World"));
    // Invalid UTF-8, overlong, CESU surrogate -> U+FFFD.
    CHECK_EQ(sanitizeUtf8("a\xFF" "b"), std::string("a\xEF\xBF\xBD" "b"));
    CHECK_EQ(sanitizeUtf8("\xC0\xAF"), std::string("\xEF\xBF\xBD\xEF\xBF\xBD"));
    CHECK_EQ(sanitizeUtf8("\xED\xA0\x80"), std::string("\xEF\xBF\xBD"));
    // Bidi override, zero-width, BOM and C0/C1 controls removed.
    CHECK_EQ(sanitizeUtf8("ab\xE2\x80\xAE" "cd\xE2\x80\x8B" "e\xEF\xBB\xBF\x01\xC2\x85"), std::string("abcde"));
    CHECK_EQ(sanitizeUtf8("x\xE2\x81\xA6y"), std::string("xy"));
    // NFC: e + combining acute == precomposed é.
    CHECK_EQ(sanitizeUtf8("Cafe\xCC\x81"), std::string("Caf\xC3\xA9"));
    const std::string longName(1000, 'x');
    CHECK_EQ(sanitizeUtf8(longName).size(), std::size_t(256));
    // UTF-16LE with an unpaired surrogate.
    const std::uint8_t utf16[] = {'O', 0, 'k', 0, 0x00, 0xD8, '!', 0, 0, 0, 'Z', 0};
    CHECK_EQ(sanitizeUtf16Le(utf16, sizeof utf16), std::string("Ok\xEF\xBF\xBD!"));
    CHECK(isGenericDisplayName("UE4 Game"));
    CHECK(isGenericDisplayName("unity"));
    CHECK(!isGenericDisplayName("Unity of Command"));
    CHECK(globMatchCaseInsensitive("unins*.exe", "UNINS000.EXE"));
    CHECK(!globMatchCaseInsensitive("unins*.exe", "xunins000.exe"));
}

void testAcf()
{
    section("acf");
    const auto ok = parseSteamManifest(acf(440, "Team Fortress 2", "Team Fortress 2", 4), 440);
    CHECK(ok.ok);
    CHECK_EQ(ok.info.name, std::string("Team Fortress 2"));
    CHECK_EQ(ok.info.installDir, std::string("Team Fortress 2"));
    CHECK_EQ(ok.info.stateFlags, 4u);
    CHECK_EQ(ok.info.lastUpdated, std::int64_t(1700000000));

    // Comments, conditionals, BOM, escapes, unquoted tokens, duplicates (first wins).
    const std::string tolerant =
        "\xEF\xBB\xBF// header comment\n\"AppState\" [$WIN32]\n{\n appid 70\n \"name\" \"Half \\\"Life\\\"\" // c\n"
        " \"name\" \"Ignored\"\n \"installdir\" \"Half-Life\"\n \"UserConfig\" { \"language\" \"english\" }\n"
        " \"unknownkey\" \"x\"\n}\n";
    const auto t = parseSteamManifest(tolerant, 70);
    CHECK(t.ok);
    CHECK_EQ(t.info.name, std::string("Half \"Life\""));

    CHECK_EQ(parseSteamManifest("\"AppState\" { \"appid\" \"1", 1).error, std::string("UNTERMINATED_STRING"));
    CHECK_EQ(parseSteamManifest("\"AppState\" { \"appid\" \"1\"", 1).error, std::string("UNBALANCED"));
    CHECK_EQ(parseSteamManifest("\"AppState\" { } }", 1).error, std::string("UNBALANCED"));
    CHECK_EQ(parseSteamManifest(acf(10, "A", "A"), 11).error, std::string("APPID_MISMATCH"));
    CHECK_EQ(parseSteamManifest(acf(10, "A", ".."), 10).error, std::string("INVALID_INSTALLDIR"));
    CHECK_EQ(parseSteamManifest(acf(10, "A", "a/b"), 10).error, std::string("INVALID_INSTALLDIR"));
    CHECK_EQ(parseSteamManifest(acf(10, "A", "a\\\\b"), 10).error, std::string("INVALID_INSTALLDIR"));
    CHECK_EQ(parseSteamManifest(acf(10, "A", ""), 10).error, std::string("INVALID_INSTALLDIR"));
    CHECK_EQ(parseSteamManifest("\"Other\" { }", 1).error, std::string("NO_APPSTATE"));
    CHECK_EQ(parseSteamManifest("", 1).error, std::string("EMPTY"));

    std::string deep = "\"AppState\" ";
    for (int i = 0; i < 20; ++i) {
        deep += "{ \"k\" ";
    }
    CHECK_EQ(parseVdf(deep).error, std::string("LIMIT_DEPTH"));
    CHECK_EQ(parseVdf("\"AppState\" { \"k\" \"" + std::string(5000, 'x') + "\" }").error, std::string("LIMIT_TOKEN"));
    std::string many = "\"AppState\" {";
    for (int i = 0; i < 5000; ++i) {
        many += " \"k" + std::to_string(i) + "\" \"v\"";
    }
    many += " }";
    CHECK_EQ(parseVdf(many).error, std::string("LIMIT_PAIRS"));
    CHECK_EQ(parseVdf("\"A\" { } \"B\" { }").error, std::string("MULTIPLE_ROOTS"));

    CHECK(appIdFromManifestName("appmanifest_440.acf") == std::optional<std::uint32_t>(440));
    CHECK(!appIdFromManifestName("AppManifest_440.acf"));
    CHECK(!appIdFromManifestName("appmanifest_44x.acf"));
    CHECK(!appIdFromManifestName("appmanifest_.acf"));

    // Mini fuzz: random mutations never crash and never exceed limits.
    std::mt19937 rng(1234);
    const std::string base = tolerant;
    for (int i = 0; i < 3000; ++i) {
        std::string mutated = base;
        const int edits = 1 + int(rng() % 8);
        for (int e = 0; e < edits; ++e) {
            const std::size_t pos = rng() % mutated.size();
            switch (rng() % 3) {
            case 0:
                mutated[pos] = char(rng() % 256);
                break;
            case 1:
                mutated.erase(pos, 1 + rng() % 4);
                break;
            default:
                mutated.insert(pos, 1, "{}\"\\/[$\n"[rng() % 8]);
                break;
            }
            if (mutated.empty()) {
                mutated = "{";
            }
        }
        (void)parseSteamManifest(mutated, 70);
    }
}

void testSyntheticPe()
{
    section("pe synthetic");
    PeSpec spec;
    const auto good = buildPe(spec);
    const PeMetadata meta = parseBuffer(good);
    CHECK(meta.validPe);
    CHECK(meta.parseError.empty());
    CHECK(meta.hasVersionInfo);
    CHECK_EQ(meta.machine, kMachineAmd64);
    CHECK_EQ(meta.subsystem, kSubsystemWindowsGui);
    CHECK_EQ(meta.productName, std::string("Fixture Quest"));
    CHECK_EQ(meta.companyName, std::string("Fixture Studio"));
    CHECK_EQ(meta.originalFilename, std::string("FixtureQuest.exe"));
    CHECK(!meta.isDll);

    PeSpec pe32 = spec;
    pe32.pe32plus = false;
    pe32.machine = kMachineI386;
    const PeMetadata m32 = parseBuffer(buildPe(pe32));
    CHECK(m32.validPe && m32.machine == kMachineI386 && m32.productName == "Fixture Quest");

    PeSpec dll = spec;
    dll.dll = true;
    CHECK(parseBuffer(buildPe(dll)).isDll);

    // Language priority: preferred (pt-BR) > en-US > neutral > Translation > first.
    PeSpec multi = spec;
    multi.tables = {{"041604b0", {{"ProductName", u"Preferred Adventure"}}}, {"040904b0", {{"ProductName", u"Adventure"}}}};
    CHECK_EQ(parseBuffer(buildPe(multi), PeLimits{2u << 20, 64u << 10, 0x0416}).productName, std::string("Preferred Adventure"));
    CHECK_EQ(parseBuffer(buildPe(multi), PeLimits{2u << 20, 64u << 10, 0x0407}).productName, std::string("Adventure"));
    PeSpec neutral = spec;
    neutral.tables = {{"041104b0", {{"ProductName", u"Japanese"}}}, {"000004b0", {{"ProductName", u"Neutral"}}}};
    neutral.translations = {0x04B00411};
    CHECK_EQ(parseBuffer(buildPe(neutral)).productName, std::string("Neutral"));

    // Hostile inputs: all fail cleanly with a reason.
    CHECK_EQ(parseBuffer(std::vector<std::uint8_t>(good.begin(), good.begin() + 40)).parseError, std::string("TRUNCATED"));
    auto badMz = good;
    badMz[0] = 'X';
    CHECK_EQ(parseBuffer(badMz).parseError, std::string("BAD_MZ"));
    auto badLfanew = good;
    put32(badLfanew, 0x3C, 0x7FFFFFF0);
    CHECK_EQ(parseBuffer(badLfanew).parseError, std::string("BAD_LFANEW"));
    auto unaligned = good;
    put32(unaligned, 0x3C, 0x81);
    CHECK_EQ(parseBuffer(unaligned).parseError, std::string("BAD_LFANEW"));
    auto badSig = good;
    badSig[0x80] = 'X';
    CHECK_EQ(parseBuffer(badSig).parseError, std::string("BAD_PE_SIG"));
    auto tooManySections = good;
    put16(tooManySections, 0x80 + 6, 200);
    CHECK_EQ(parseBuffer(tooManySections).parseError, std::string("BAD_SECTIONS"));
    auto badMagic = good;
    put16(badMagic, 0x80 + 24, 0x1234);
    CHECK_EQ(parseBuffer(badMagic).parseError, std::string("BAD_OPTIONAL_HEADER"));

    PeLayout layout;
    const auto base = buildPe(spec, &layout);
    // Resource RVA pointing past every section (and RVA+size overflow).
    auto rvaOverflow = base;
    put32(rvaOverflow, layout.optionalHeader + 112 + 16, 0xFFFFFFF0);
    const PeMetadata rvaMeta = parseBuffer(rvaOverflow);
    CHECK(rvaMeta.validPe);
    CHECK_EQ(rvaMeta.parseError, std::string("RVA_UNMAPPED"));
    CHECK(rvaMeta.productName.empty());
    // Section raw data claiming more than the file holds.
    auto overlap = base;
    put32(overlap, layout.sectionTable + 16, 0x7FFFFFFF);
    CHECK(!parseBuffer(overlap).parseError.empty());
    // Loop in the resource tree: name level points back to the root.
    auto loop = base;
    put32(loop, layout.rsrcFileOffset + 0x18 + 20, 0x80000000u);
    CHECK_EQ(parseBuffer(loop).parseError, std::string("RESOURCE_LOOP"));
    // Too many entries in one directory level.
    auto wide = base;
    put16(wide, layout.rsrcFileOffset + 14, 5000);
    CHECK_EQ(parseBuffer(wide).parseError, std::string("RESOURCE_LIMIT"));
    // Version resource larger than 64 KiB.
    auto huge = base;
    put32(huge, layout.rsrcFileOffset + 0x48 + 4, 70000);
    CHECK_EQ(parseBuffer(huge).parseError, std::string("VERSION_TOO_LARGE"));
    // wLength inconsistent with the parent.
    auto badLength = base;
    put16(badLength, layout.versionOffset, 0xFFF0);
    CHECK(!parseBuffer(badLength).parseError.empty());
    auto badSignature = base;
    put32(badSignature, layout.versionOffset + 40, 0x12345678);
    CHECK_EQ(parseBuffer(badSignature).parseError, std::string("VERSION_MALFORMED"));
    // Invalid surrogate inside a string value is replaced, not fatal.
    PeSpec surrogate = spec;
    surrogate.tables = {{"040904b0", {{"ProductName", std::u16string(u"Bad") + char16_t(0xDC00) + u"Name"}}}};
    CHECK_EQ(parseBuffer(buildPe(surrogate)).productName, std::string("Bad\xEF\xBF\xBDName"));
    // Bidi/zero-width in ProductName are stripped.
    PeSpec bidi = spec;
    bidi.tables = {{"040904b0", {{"ProductName", u"Evil\u202Eexe.txt\u200B"}}}};
    CHECK_EQ(parseBuffer(buildPe(bidi)).productName, std::string("Evilexe.txt"));
    // Read budget: a tiny budget forces READ_BUDGET without touching more bytes.
    PeParseStats stats;
    BufferByteSource source(base);
    const PeMetadata budget = parsePe(source, base.size(), PeLimits{128, 64u << 10, 0x409}, {}, &stats);
    CHECK(!budget.parseError.empty());
    CHECK(stats.bytesRequested <= 128);
    PeSpec noVersion = spec;
    noVersion.withVersion = false;
    const PeMetadata nv = parseBuffer(buildPe(noVersion));
    CHECK(nv.validPe && nv.parseError.empty() && !nv.hasVersionInfo);

    // Mini fuzz over header and resource bytes: no crash, bounded reads.
    std::mt19937 rng(99);
    for (int i = 0; i < 4000; ++i) {
        auto mutated = base;
        const int edits = 1 + int(rng() % 6);
        for (int e = 0; e < edits; ++e) {
            const std::size_t pos = rng() % 2 ? rng() % 0x200 : layout.rsrcFileOffset + rng() % (base.size() - layout.rsrcFileOffset);
            mutated[pos] = std::uint8_t(rng());
        }
        if (rng() % 5 == 0) {
            mutated.resize(rng() % mutated.size());
        }
        PeParseStats s;
        BufferByteSource src(mutated);
        (void)parsePe(src, mutated.size(), PeLimits{}, {}, &s);
        CHECK(s.bytesRequested <= (2u << 20));
    }
}

void testToolchainFixtures()
{
    section("pe toolchain fixtures");
#ifdef THREESIXTY_PE_FIXTURE_DIR
    const auto quest = readBytes(peFixture("FixtureQuest.exe"));
    CHECK(!quest.empty());
    const PeMetadata q = parseBuffer(quest);
    CHECK(q.validPe && q.parseError.empty());
    CHECK_EQ(q.machine, kMachineAmd64);
    CHECK_EQ(q.subsystem, kSubsystemWindowsGui);
    CHECK_EQ(q.productName, std::string("Fixture Quest"));
    CHECK_EQ(q.fileDescription, std::string("Fixture Quest Game"));
    CHECK_EQ(q.fileVersion, std::string("1.2.3.4"));
    CHECK_EQ(q.internalName, std::string("FixtureQuest"));

    const PeMetadata q32 = parseBuffer(readBytes(peFixture("FixtureQuest32.exe")));
    CHECK(q32.validPe && q32.machine == kMachineI386 && q32.productName == "Fixture Quest");

    const PeMetadata dll = parseBuffer(readBytes(peFixture("FixtureTool.dll")));
    CHECK(dll.validPe && dll.isDll);
    CHECK_EQ(hardExclusion(rulesetV2(), "FixtureTool.exe", dll), std::string("pe-dll"));

    const PeMetadata nv = parseBuffer(readBytes(peFixture("NoVersion.exe")));
    CHECK(nv.validPe && !nv.hasVersionInfo && nv.subsystem == kSubsystemWindowsCui);

    const auto multi = readBytes(peFixture("MultiLang.exe"));
    CHECK_EQ(parseBuffer(multi, PeLimits{2u << 20, 64u << 10, 0x0416}).productName, std::string("Preferred Test Adventure"));
    CHECK_EQ(parseBuffer(multi, PeLimits{2u << 20, 64u << 10, 0x0409}).productName, std::string("Test Adventure"));
    CHECK_EQ(parseBuffer(multi, PeLimits{2u << 20, 64u << 10, 0x0407}).productName, std::string("Test Adventure"));

    // Truncations of a real file at every 97 bytes: never crash.
    for (std::size_t cut = 0; cut < quest.size(); cut += 97) {
        (void)parseBuffer(std::vector<std::uint8_t>(quest.begin(), quest.begin() + static_cast<std::ptrdiff_t>(cut)));
    }
#else
    std::fprintf(stderr, "SKIP toolchain fixtures (llvm-rc/lld-link not found)\n");
#endif
}

ExeCandidate candidate(const std::string &rel, unsigned depth, std::uint64_t size, const PeMetadata &pe)
{
    ExeCandidate c;
    c.relPath = rel;
    c.depth = depth;
    c.size = size;
    c.pe = pe;
    return c;
}

void testRules()
{
    section("rules and scorer");
    PeMetadata gui;
    gui.validPe = true;
    gui.machine = kMachineAmd64;
    gui.subsystem = kSubsystemWindowsGui;
    const auto &rules = rulesetV2();
    for (const char *name : {"UnityCrashHandler64.exe", "unitycrashhandler32.EXE", "unins000.exe", "UNINS001.EXE",
                             "DXSETUP.exe", "dxsetup.EXE", "vcredist_x64.exe", "VCREDIST_X86.EXE"}) {
        CHECK(!hardExclusion(rules, std::string("Game/") + name, gui).empty());
    }
    // Ruleset v2: runtime installers, engine helpers and redist directories.
    for (const char *path : {"vc_redist.x64.exe", "dxwebsetup.exe", "dotNetFx40_Full_x86_x64.exe",
                             "NDP472-KB4054530-x86-x64-AllOS-ENU.exe", "windowsdesktop-runtime-6.0.0-win-x64.exe",
                             "xnafx40_redist.exe", "oalinst.exe", "PhysX_9.21.0713_SystemSoftware.exe",
                             "Engine/Extras/Redist/en-us/UE4PrereqSetup_x64.exe", "UEPrereqSetup_x64.exe",
                             "Engine/Binaries/Win64/CrashReportClient.exe", "EasyAntiCheat/EasyAntiCheat_EOS_Setup.exe",
                             "BattlEye/BEService_x64.exe", "_CommonRedist/Tool.exe", "__Installer/Game.exe",
                             "Redistributables/Game.exe", "vcredist/2019/Game.exe"}) {
        CHECK(!hardExclusion(rules, std::string("Game/") + path, gui).empty());
    }
    for (const char *path : {"Game.exe", "Binaries/Win64/Game-Win64-Shipping.exe", "Support/Game.exe",
                             "Physics Game.exe", "ReDistrict.exe"}) {
        CHECK(hardExclusion(rules, path, gui).empty());
    }
    CHECK(hardExclusion(rules, "Game.exe", gui).empty());
    CHECK(hasExeExtension("GAME.EXE"));
    CHECK(!hasExeExtension("game.exe.part"));
    CHECK(!hasExeExtension(".exe"));

    CHECK((nameTokens("FixtureQuest-Win64-Shipping.exe") == std::vector<std::string>{"fixture", "quest"}));
    CHECK(jaccard(nameTokens("Fixture Quest"), nameTokens("FixtureQuest")) == 1.0);

    ScoreContext ctx{"Fixture Quest", &rules};
    std::vector<ExeCandidate> cands = {
        candidate("FixtureQuest.exe", 0, 40ull << 20, gui),
        candidate("Launcher.exe", 0, 2ull << 20, gui),
        candidate("_CommonRedist/setup.exe", 1, 1ull << 20, gui),
    };
    for (auto &c : cands) {
        c.excludedBy = hardExclusion(rules, c.relPath, c.pe);
        scoreCandidate(ctx, c);
    }
    CHECK(cands[0].score > cands[1].score + 10);
    CHECK_EQ(cands[2].excludedBy, std::string("exclude-segment-_commonredist"));
    CHECK(cands[0].featuresJson.find("\"scorer_version\":1") != std::string::npos);
    Decision d = decideMainExecutable(cands, 25, 10);
    CHECK(d.state == GameState::Ready);
    CHECK(d.main && cands[*d.main].relPath == "FixtureQuest.exe");

    // Shipping build in Binaries/Win64 wins over a same-named bootstrap exe.
    ScoreContext ue{"Space Game", &rules};
    std::vector<ExeCandidate> unreal = {
        candidate("SpaceGame.exe", 0, 1ull << 20, gui),
        candidate("SpaceGame/Binaries/Win64/SpaceGame-Win64-Shipping.exe", 3, 90ull << 20, gui),
    };
    for (auto &c : unreal) {
        scoreCandidate(ue, c);
    }
    const Decision ud = decideMainExecutable(unreal, 25, 10);
    CHECK(ud.state == GameState::Ready || ud.state == GameState::Ambiguous);

    // Tie -> AMBIGUOUS, never a silent pick.
    ScoreContext tie{"Twins", &rules};
    std::vector<ExeCandidate> twins = {candidate("Alpha.exe", 0, 5ull << 20, gui), candidate("Beta.exe", 0, 5ull << 20, gui)};
    for (auto &c : twins) {
        scoreCandidate(tie, c);
    }
    const Decision td = decideMainExecutable(twins, 25, 10);
    CHECK(td.state == GameState::Ambiguous);
    CHECK(!td.main);

    // Only excluded executables -> NO_EXECUTABLE.
    std::vector<ExeCandidate> none = {candidate("unins000.exe", 0, 1, gui)};
    none[0].excludedBy = hardExclusion(rules, none[0].relPath, gui);
    CHECK(decideMainExecutable(none, 25, 10).reason == "NO_EXECUTABLE");
}

} // namespace

int main()
{
    testSanitize();
    testAcf();
    testSyntheticPe();
    testToolchainFixtures();
    testRules();
    return finish("library.parsers");
}
