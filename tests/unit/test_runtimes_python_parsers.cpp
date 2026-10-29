/**
 * test_runtimes_python_parsers.cpp -- tests for the runtimes plugin's `python` action:
 * the pure decision layer (runtimes_python_parsers.hpp) on EVERY OS, and the macOS
 * framework walk (runtimes_macos_parsers.hpp) over a materialized fixture tree on POSIX. The
 * Linux walk's python cases live in test_runtimes_linux_parsers.cpp (they share its harness); the
 * Windows registry walk is test_runtimes_win_walk.cpp.
 *
 * SCOPED GUARD (reasoned exception to the never-guard-a-test-TU rule): the macOS walk is built on
 * the POSIX-only walk layer, so those cases sit in one `#if !defined(_WIN32)` region. The pure
 * cases are unguarded.
 *
 * FIXTURE. tests/unit/fixtures/wave10/runtimes/macos/python_framework.manifest -- the python.org
 * 3.13.1 framework Info.plist as a REAL CAPTURE (provenance in the manifest header), plus
 * RECONSTRUCTION entries it names itself (a binary plist, a version directory with no Resources).
 *
 * MUTATION NOTES: accepting CFBundleShortVersionString without the full-version test returns
 * "3.13.1, (c) ..." as the version; reading Info.plist with the path-form open follows the
 * planted symlink and surfaces the sibling tree; dropping the Frameworks hop's O_NOFOLLOW lists
 * the sibling tree's python; dropping the dedupe keeps both registry views' row.
 */
#include <catch2/catch_test_macros.hpp>

#include "runtimes_fixture_tree.hpp"
#include "runtimes_legs.hpp"
#include "runtimes_python_parsers.hpp"

#include "test_helpers.hpp" // yuzu::test::TempDir

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#if !defined(_WIN32)
#include "local_dispatcher.hpp" // yuzu::agent::LocalDispatcher (a real CommandContext)
#include "runtimes_macos_parsers.hpp"

#include <yuzu/plugin.h>

#include <sstream>
#include <sys/stat.h>
#include <unistd.h>
#endif

#if defined(__APPLE__)
#include <macos_network_mounts.hpp>

#include <cstring>
#include <sys/mount.h>
#endif

namespace rt = yuzu::runtimes;
namespace fs = std::filesystem;
using namespace runtimes_fixture;

namespace {

fs::path macos_fixture() {
#ifdef YUZU_TEST_FIXTURE_DIR
    return fs::path(YUZU_TEST_FIXTURE_DIR) / "wave10" / "runtimes" / "macos" /
           "python_framework.manifest";
#else
    return fs::path("tests/unit/fixtures/wave10/runtimes/macos/python_framework.manifest");
#endif
}

constexpr const char* kPlistRel =
    "Library/Frameworks/Python.framework/Versions/3.13/Resources/Info.plist";

/// The captured python.org Info.plist text, decoded from the manifest (portable: no filesystem
/// materialization), REQUIREd to exist so a missing fixture fails rather than skips.
std::string captured_plist() {
    std::ifstream in(macos_fixture(), std::ios::binary);
    REQUIRE(in.good());
    for (std::string line; std::getline(in, line);) {
        const auto p = parse_manifest_line(line);
        if (p.outcome == LineOutcome::entry && p.entry.rel == kPlistRel) return p.entry.payload;
    }
    FAIL("Info.plist entry not found in " << macos_fixture().string());
    return {};
}

std::vector<std::string> split_fields_escape_aware(const std::string& row) {
    std::vector<std::string> out;
    std::string cur;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '\\' && i + 1 < row.size() && row[i + 1] == '|') {
            cur += '|';
            ++i;
        } else if (row[i] == '|') {
            out.push_back(cur);
            cur.clear();
        } else {
            cur += row[i];
        }
    }
    out.push_back(cur);
    return out;
}

} // namespace

// == pure layer (every OS) ======================================================================

TEST_CASE("python: python3_minor_from_name accepts exactly python3.<digits>", "[runtimes][python]") {
    CHECK(rt::python3_minor_from_name("python3.12") == "3.12");
    CHECK(rt::python3_minor_from_name("python3.9") == "3.9");
    CHECK(rt::python3_minor_from_name("python3.130") == "3.130");
    for (const char* no : {"python3", "python3.", "python3.12-config", "python3.12m", "python2.7",
                           "python312", "python3.x", "Python3.12", "xpython3.12", "python3.12.1", ""}) {
        INFO("name: " << no);
        CHECK_FALSE(rt::python3_minor_from_name(no).has_value());
    }
}

TEST_CASE("python: version shape predicates", "[runtimes][python]") {
    CHECK(rt::looks_like_major_minor("3.12"));
    CHECK_FALSE(rt::looks_like_major_minor("3.12.4"));
    CHECK_FALSE(rt::looks_like_major_minor("3"));
    CHECK_FALSE(rt::looks_like_major_minor(""));
    CHECK_FALSE(rt::looks_like_major_minor("3."));
    CHECK_FALSE(rt::looks_like_major_minor(".12"));
    CHECK(rt::looks_like_full_version("3.12.4"));
    CHECK_FALSE(rt::looks_like_full_version("3.12"));
    CHECK_FALSE(rt::looks_like_full_version("3.12.4rc1"));
    CHECK_FALSE(rt::looks_like_full_version("3.12.4, (c) 2001"));
    CHECK_FALSE(rt::looks_like_full_version(" 3.12.4"));
    CHECK_FALSE(rt::looks_like_full_version("3.12.4.1"));
    CHECK_FALSE(rt::looks_like_full_version(""));
}

TEST_CASE("python: the REAL CAPTURE python.org Info.plist yields its full version and identifier "
          "(REAL CAPTURE)",
          "[runtimes][python][plist]") {
    const auto plist = captured_plist();
    // CFBundleVersion is the full x.y.z; the short string carries a licence suffix.
    CHECK(rt::python_version_from_plist(plist) == "3.13.1");
    CHECK(rt::plist_string_value(plist, "CFBundleShortVersionString") ==
          "3.13.1, (c) 2001-2024 Python Software Foundation.");
    CHECK(rt::plist_string_value(plist, "CFBundleIdentifier") == "org.python.python");
    // A key whose value is not a <string> (CFBundleAllowMixedLocalizations is <true/>) is a miss.
    CHECK_FALSE(rt::plist_string_value(plist, "CFBundleAllowMixedLocalizations").has_value());
    CHECK_FALSE(rt::plist_string_value(plist, "NoSuchKey").has_value());
}

TEST_CASE("python: python_version_from_plist rejects suffixed values and unreadable shapes (SYNTHETIC)",
          "[runtimes][python][plist]") {
    const auto doc = [](std::string_view body) {
        return "<?xml version=\"1.0\"?><plist><dict>" + std::string{body} + "</dict></plist>";
    };
    // Suffixed short string alone: not a version, so the leg falls back to the directory name.
    CHECK_FALSE(rt::python_version_from_plist(
                    doc("<key>CFBundleShortVersionString</key><string>3.12.4, (c) PSF</string>"))
                    .has_value());
    // Suffixed short string beside a clean CFBundleVersion: the latter wins.
    CHECK(rt::python_version_from_plist(
              doc("<key>CFBundleShortVersionString</key><string>3.12.4, (c) PSF</string>"
                  "<key>CFBundleVersion</key><string>3.12.4</string>")) == "3.12.4");
    // A clean short string is used when CFBundleVersion is missing or not a full version.
    CHECK(rt::python_version_from_plist(
              doc("<key>CFBundleVersion</key><string>312</string>"
                  "<key>CFBundleShortVersionString</key><string>3.12.4</string>")) == "3.12.4");
    // major.minor only is not a full version.
    CHECK_FALSE(
        rt::python_version_from_plist(doc("<key>CFBundleVersion</key><string>3.12</string>")).has_value());
    // Binary plist, empty, entity, control character: nothing.
    CHECK_FALSE(rt::python_version_from_plist("bplist00\x01\x02<key>CFBundleVersion</key><string>3.1.2</string>")
                    .has_value());
    CHECK_FALSE(rt::python_version_from_plist("").has_value());
    CHECK_FALSE(rt::python_version_from_plist(doc("<key>CFBundleVersion</key><string>3.1&amp;2</string>"))
                    .has_value());
    CHECK_FALSE(rt::python_version_from_plist(doc("<key>CFBundleVersion</key><string>3.1.2\x01</string>"))
                    .has_value());
}

TEST_CASE("python: the plist reader never reads past an unterminated buffer (SYNTHETIC)",
          "[runtimes][python][plist]") {
    for (const std::string_view cut :
         {"<key>CFBundleVersion</key><string>3.1.2", "<key>CFBundleVersion</key><string",
          "<key>CFBundleVersion</key>", "<key>CFBundleVersion</key", "<key>CFBundleVersion",
          "<key>"}) {
        INFO("buffer: " << cut);
        CHECK_FALSE(rt::python_version_from_plist(cut).has_value());
    }
    // The view is a slice of a larger buffer: bytes after its end must not be consulted.
    const std::string big = "<key>CFBundleVersion</key><string>3.1.2</string>";
    CHECK_FALSE(rt::python_version_from_plist(std::string_view{big}.substr(0, big.size() - 9)).has_value());
}

TEST_CASE("python: python_version_from_pep514 prefers Version, then SysVersion, then the tag",
          "[runtimes][python][pep514]") {
    CHECK(rt::python_version_from_pep514("3.14.6", "3.14", "3.14") == "3.14.6");
    CHECK(rt::python_version_from_pep514("", "3.14", "3.14") == "3.14");
    CHECK(rt::python_version_from_pep514("garbage", "3.14", "3.14-32") == "3.14");
    CHECK(rt::python_version_from_pep514("", "", "3.14-32") == "3.14");
    CHECK(rt::python_version_from_pep514("", "", "3.14") == "3.14");
    CHECK(rt::python_version_from_pep514("", "", "3.14.2") == "3.14");
    CHECK_FALSE(rt::python_version_from_pep514("x", "y", "z").has_value());
    CHECK_FALSE(rt::python_version_from_pep514("", "", "3").has_value());
    CHECK_FALSE(rt::python_version_from_pep514("", "", "").has_value());
}

TEST_CASE("python: dedupe_python_rows keeps the first record per install path", "[runtimes][python]") {
    rt::PythonRecord a{rt::PythonFlavour::cpython, "3.14.6", "C:\\Python314\\", "PythonCore"};
    rt::PythonRecord b = a; // the same install through the 32-bit view
    b.version = "3.14";
    rt::PythonRecord other{rt::PythonFlavour::cpython, "3.12.1", "C:\\Python312\\", "PythonCore"};
    rt::PythonRecord no_path_1{rt::PythonFlavour::cpython, "3.10.1", "", "PythonCore"};
    rt::PythonRecord no_path_2{rt::PythonFlavour::cpython, "3.9.1", "", "PythonCore"};
    std::vector<rt::PythonRecord> recs{a, b, other, no_path_1, no_path_2};
    rt::dedupe_python_rows(recs);
    REQUIRE(recs.size() == 4);
    CHECK(recs[0].version == "3.14.6"); // the first (64-bit) view's record survives
    CHECK(recs[1].version == "3.12.1");
    CHECK(recs[2].version == "3.10.1"); // path-less records are never merged
    CHECK(recs[3].version == "3.9.1");
}

TEST_CASE("python: sort_python_rows orders by version then install path and is stable on ties",
          "[runtimes][python]") {
    using rt::PythonFlavour;
    std::vector<rt::PythonRecord> recs{
        {PythonFlavour::cpython, "3.14.6", "C:\\B\\", "PythonCore"},
        {PythonFlavour::cpython, "3.12.4", "C:\\Z\\", "PythonCore"},
        {PythonFlavour::cpython, "3.14.6", "C:\\A\\", "PythonCore"},
        {PythonFlavour::cpython, "3.12.4", "C:\\Z\\", "second"}, // an exact tie keeps input order
    };
    rt::sort_python_rows(recs);
    REQUIRE(recs.size() == 4);
    CHECK(recs[0].install_path == "C:\\Z\\");
    CHECK(recs[0].vendor == "PythonCore");
    CHECK(recs[1].vendor == "second");
    CHECK(recs[2].install_path == "C:\\A\\");
    CHECK(recs[3].install_path == "C:\\B\\");
    // Sorting after the dedupe leaves the survivor of a duplicate path independent of the sort: the
    // first (64-bit) record stays even though the 32-bit one's version string sorts lower.
    std::vector<rt::PythonRecord> both{
        {PythonFlavour::cpython, "3.14.6", "C:\\Python314\\", "PythonCore"},
        {PythonFlavour::cpython, "3.14", "C:\\Python314\\", "PythonCore"},
    };
    rt::dedupe_python_rows(both);
    rt::sort_python_rows(both);
    REQUIRE(both.size() == 1);
    CHECK(both[0].version == "3.14.6");
}

TEST_CASE("python: python_row renders five fields and cannot be shifted by hostile text",
          "[runtimes][python]") {
    // safe_output_field folds a literal backslash to '/' (documented lossy wire behaviour).
    CHECK(rt::python_row({rt::PythonFlavour::cpython, "3.14.6", "C:\\Python314\\", "PythonCore"}) ==
          "python|cpython|3.14.6|C:/Python314/|PythonCore");
    CHECK(rt::python_row({rt::PythonFlavour::unmodelled, "", "", ""}) == "python|unmodelled|-|-|-");
    const auto piped = rt::python_row({rt::PythonFlavour::cpython, "3.1|2", "/opt/we|ird/", "a|b"});
    const auto f = split_fields_escape_aware(piped);
    REQUIRE(f.size() == 5);
    CHECK(f[2] == "3.1|2");
    CHECK(f[3] == "/opt/we|ird/");
    CHECK(f[4] == "a|b");
    CHECK(rt::flavour_token(rt::PythonFlavour::cpython) == "cpython");
    CHECK(rt::flavour_token(rt::PythonFlavour::unmodelled) == "unmodelled");
}

TEST_CASE("python: the action name round-trips", "[runtimes][python]") {
    CHECK(rt::action_name(rt::Action::python) == "python");
    CHECK(rt::parse_action("python") == rt::Action::python);
}

// == macOS framework walk over the fixture tree (POSIX) =========================================

#if !defined(_WIN32)

namespace {

namespace mac = yuzu::runtimes::mac;
using Acc = yuzu::shared::ConstraintAccumulator;

constexpr const char* kVersions = "Library/Frameworks/Python.framework/Versions";
constexpr const char* kRow313 = "python|cpython|3.13.1|/Library/Frameworks/Python.framework/Versions/3.13|"
                                "org.python.python";
constexpr const char* kRow312 = "python|unmodelled|3.12|/Library/Frameworks/Python.framework/Versions/3.12|-";
constexpr const char* kRow311 = "python|unmodelled|3.11|/Library/Frameworks/Python.framework/Versions/3.11|-";

void write_file(const fs::path& p, const std::string& text) {
    std::error_code ec;
    fs::create_directories(p.parent_path(), ec);
    REQUIRE_FALSE(ec);
    std::ofstream out(p, std::ios::binary);
    REQUIRE(out.good());
    out << text;
}

bool privileged() { return ::geteuid() == 0; }

struct PermRestore {
    fs::path path;
    ~PermRestore() { ::chmod(path.c_str(), 0755); }
};

} // namespace

TEST_CASE("python: mac::python_rows_at reads each framework version (REAL CAPTURE + labelled "
          "reconstructions)",
          "[runtimes][python][macos]") {
    yuzu::test::TempDir dir{"yuzu_test_runtimes_pymac_"};
    std::string err;
    REQUIRE(materialize_manifest_file(dir.path, err, macos_fixture()));
    Acc acc;
    const auto rows = mac::python_rows_at(dir.path, acc);
    // Sorted by directory name: 3.11 (no Resources) and 3.12 (binary plist) fall back to the
    // directory's x.y with no token; 3.13 is the real plist. `Current` (symlink) and `Headers`
    // (not a version) are skipped silently.
    CHECK(rows == std::vector<std::string>{kRow311, kRow312, kRow313});
    CHECK_FALSE(acc.any_failure());
}

TEST_CASE("python: an absent framework is supported with zero rows", "[runtimes][python][macos]") {
    yuzu::test::TempDir dir{"yuzu_test_runtimes_pymac_absent_"};
    Acc acc;
    CHECK(mac::python_rows_at(dir.path, acc).empty());
    CHECK_FALSE(acc.any_failure());
}

TEST_CASE("python: a symlinked Frameworks hop is refused and the sibling tree is never listed "
          "(SYNTHETIC)",
          "[runtimes][python][macos]") {
    // MUTATION: opening the Versions directory with a path-form open follows `Library/Frameworks`
    // and lists the sibling tree (the canary 3.99 row).
    yuzu::test::TempDir dir{"yuzu_test_runtimes_pymac_link_"};
    write_file(dir.path / "elsewhere/Python.framework/Versions/3.99/Resources/Info.plist",
               "<key>CFBundleVersion</key><string>3.99.1</string>");
    fs::create_directories(dir.path / "Library");
    std::error_code ec;
    fs::create_symlink("../elsewhere", dir.path / "Library/Frameworks", ec);
    REQUIRE_FALSE(ec);
    Acc acc;
    CHECK(mac::python_rows_at(dir.path, acc).empty());
    CHECK(acc.reason() == "macos:runtimes:symlink_refused");
}

TEST_CASE("python: a symlinked Versions directory and a symlinked version entry (SYNTHETIC)",
          "[runtimes][python][macos]") {
    SECTION("Versions itself is a symlink: refused") {
        yuzu::test::TempDir dir{"yuzu_test_runtimes_pymac_vlink_"};
        write_file(dir.path / "srv/3.99/Resources/Info.plist", "x");
        fs::create_directories(dir.path / "Library/Frameworks/Python.framework");
        std::error_code ec;
        fs::create_symlink("../../../srv", dir.path / kVersions, ec);
        REQUIRE_FALSE(ec);
        Acc acc;
        CHECK(mac::python_rows_at(dir.path, acc).empty());
        CHECK(acc.reason() == "macos:runtimes:symlink_refused");
    }
    SECTION("a version-named symlink entry is skipped silently, never followed") {
        yuzu::test::TempDir dir{"yuzu_test_runtimes_pymac_elink_"};
        fs::create_directories(dir.path / kVersions / "3.12");
        std::error_code ec;
        fs::create_symlink("3.12", dir.path / kVersions / "3.12.9", ec); // not x.y anyway
        fs::create_symlink("3.12", dir.path / kVersions / "3.13", ec);   // x.y but a symlink
        REQUIRE_FALSE(ec);
        Acc acc;
        CHECK(mac::python_rows_at(dir.path, acc) == std::vector<std::string>{kRow312});
        CHECK_FALSE(acc.any_failure());
    }
}

TEST_CASE("python: an unreadable or hostile Info.plist keeps the row at the directory version with no "
          "token (SYNTHETIC)",
          "[runtimes][python][macos]") {
    yuzu::test::TempDir dir{"yuzu_test_runtimes_pymac_plist_"};
    const fs::path v = dir.path / kVersions;
    fs::create_directories(v / "3.10/Resources/Info.plist"); // a directory named Info.plist
    write_file(v / "3.11/secret.txt", "<key>CFBundleVersion</key><string>9.9.9</string>");
    fs::create_directories(v / "3.11/Resources");
    std::error_code ec;
    fs::create_symlink("../secret.txt", v / "3.11/Resources/Info.plist", ec); // never followed
    REQUIRE_FALSE(ec);
    write_file(v / "3.12/Resources/Info.plist", std::string(256 * 1024 + 1, 'x')); // over the bound
    Acc acc;
    CHECK(mac::python_rows_at(dir.path, acc) ==
          std::vector<std::string>{
              "python|unmodelled|3.10|/Library/Frameworks/Python.framework/Versions/3.10|-", kRow311,
              kRow312});
    CHECK_FALSE(acc.any_failure());
}

TEST_CASE("python: an unopenable Versions directory is permission_denied, never absent (SYNTHETIC)",
          "[runtimes][python][macos]") {
    if (privileged()) SKIP("permission bits are bypassed at euid 0");
    yuzu::test::TempDir dir{"yuzu_test_runtimes_pymac_eacces_"};
    fs::create_directories(dir.path / kVersions / "3.13");
    const PermRestore restore{dir.path / kVersions};
    REQUIRE(::chmod((dir.path / kVersions).c_str(), 0000) == 0);
    Acc acc;
    CHECK(mac::python_rows_at(dir.path, acc).empty());
    CHECK(acc.reason() == "macos:runtimes:permission_denied");
}

TEST_CASE("python: the macOS row budget bounds the rows and reports row_cap (SYNTHETIC)",
          "[runtimes][python][macos][cap]") {
    yuzu::test::TempDir dir{"yuzu_test_runtimes_pymac_cap_"};
    for (const char* v : {"3.10", "3.11", "3.12"}) fs::create_directories(dir.path / kVersions / v);
    yuzu::runtimes::lnx::WalkConfig cfg;
    cfg.limits.rows = 2;
    Acc acc;
    const auto rows = mac::python_rows_at(dir.path, acc, cfg);
    CHECK(rows.size() == 2);
    CHECK(acc.reason() == "macos:runtimes:row_cap");
}

namespace {

// -- CommandContext-level harness ---------------------------------------------------------
// Drives the PRODUCTION macOS leg body (mac::run_macos_at) through a real CommandContext via
// LocalDispatcher (the test_runtimes_linux_parsers.cpp precedent), so what is asserted is the rows
// the command emits AND the typed result status it reports, not only the walk's return values.

struct LegRun {
    int rc = -1;
    std::vector<std::string> rows;
    YuzuResultStatus status = YUZU_RESULT_STATUS_UNDECLARED;
    YuzuResultCompleteness completeness = YUZU_RESULT_COMPLETENESS_UNKNOWN;
    std::string provenance;
};

const fs::path* g_leg_root = nullptr;
const rt::lnx::WalkConfig* g_leg_cfg = nullptr;

int leg_execute(YuzuCommandContext* raw, const char* action, const YuzuParam* /*params*/,
                std::size_t /*param_count*/) {
    yuzu::CommandContext ctx{raw};
    const auto a = rt::parse_action(action);
    if (!a) return 1;
    return mac::run_macos_at(ctx, *a, *g_leg_root, *g_leg_cfg);
}

LegRun run_leg(rt::Action action, const fs::path& root, const rt::lnx::WalkConfig& cfg = {}) {
    g_leg_root = &root;
    g_leg_cfg = &cfg;
    yuzu::test::ScopeExit reset{[] { // even if the run throws
        g_leg_root = nullptr;
        g_leg_cfg = nullptr;
    }};
    YuzuPluginDescriptor descriptor{};
    descriptor.execute = &leg_execute;
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(&descriptor, rt::action_name(action));

    LegRun out;
    out.rc = result.rc;
    out.status = result.result_status;
    out.completeness = result.result_completeness;
    out.provenance = result.result_provenance;
    std::istringstream lines(result.captured);
    for (std::string line; std::getline(lines, line);)
        if (!line.empty()) out.rows.push_back(line);
    return out;
}

} // namespace

TEST_CASE("python: run_macos_at emits the status row first and reports OK/FULL for a clean read",
          "[runtimes][python][macos]") {
    // MUTATION: reporting CONSTRAINED regardless, dropping the status row, or discarding the rows
    // before emit_read turns this red.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_pymac_leg_"};
    std::string err;
    REQUIRE(materialize_manifest_file(dir.path, err, macos_fixture()));
    const auto run = run_leg(rt::Action::python, dir.path);
    CHECK(run.rc == 0);
    CHECK(run.rows == std::vector<std::string>{"status|python|supported|-", kRow311, kRow312, kRow313});
    CHECK(run.status == YUZU_RESULT_STATUS_OK);
    CHECK(run.completeness == YUZU_RESULT_COMPLETENESS_FULL);
    CHECK(run.provenance.empty());
}

TEST_CASE("python: a refused framework hop is a constrained status row and CONSTRAINED/PARTIAL "
          "through the dispatch (SYNTHETIC)",
          "[runtimes][python][macos]") {
    // A symlink needs no permission bits, so this holds at euid 0 too. MUTATION: reporting OK/FULL
    // regardless of the accumulator, or emitting no status row, turns this red.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_pymac_legfail_"};
    write_file(dir.path / "elsewhere/Python.framework/Versions/3.99/Resources/Info.plist",
               "<key>CFBundleVersion</key><string>3.99.1</string>");
    fs::create_directories(dir.path / "Library");
    std::error_code ec;
    fs::create_symlink("../elsewhere", dir.path / "Library/Frameworks", ec);
    REQUIRE_FALSE(ec);
    const auto run = run_leg(rt::Action::python, dir.path);
    CHECK(run.rc == 0);
    CHECK(run.rows ==
          std::vector<std::string>{"status|python|constrained|macos:runtimes:symlink_refused"});
    CHECK(run.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(run.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(run.provenance == "macos:runtimes:symlink_refused");
}

TEST_CASE("python: a framework root on, under or containing a network mount is never opened "
          "(SYNTHETIC)",
          "[runtimes][python][macos][mounts]") {
    // The fixture tree holds three readable versions: had the walk opened the Versions directory,
    // rows would come back. MUTATION: dropping cfg from the python_rows_at call in run_macos_at (or
    // from open_path) returns the rows and no token.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_pymac_mount_"};
    std::string err;
    REQUIRE(materialize_manifest_file(dir.path, err, macos_fixture()));
    const std::string versions = std::string{"/"} + kVersions;
    // Exactly the Versions path, an ancestor (/Library), and a descendant (a version's Resources).
    for (const std::string mount : {versions, std::string{"/Library"}, versions + "/3.13/Resources"}) {
        INFO("mount: " << mount);
        rt::lnx::WalkConfig cfg;
        cfg.network_mounts = {mount};
        Acc acc;
        CHECK(mac::python_rows_at(dir.path, acc, cfg).empty());
        CHECK(acc.reason() == "macos:runtimes:network_fs_skipped");
    }
    // Positive control: a mount elsewhere skips nothing.
    rt::lnx::WalkConfig other;
    other.network_mounts = {"/Volumes/share", "/Library/Frameworks/Other.framework"};
    Acc acc;
    CHECK(mac::python_rows_at(dir.path, acc, other) ==
          std::vector<std::string>{kRow311, kRow312, kRow313});
    CHECK_FALSE(acc.any_failure());
}

TEST_CASE("python: run_macos_at hands the guard to the walk and reports CONSTRAINED/PARTIAL (SYNTHETIC)",
          "[runtimes][python][macos][mounts]") {
    yuzu::test::TempDir dir{"yuzu_test_runtimes_pymac_legmount_"};
    std::string err;
    REQUIRE(materialize_manifest_file(dir.path, err, macos_fixture()));
    rt::lnx::WalkConfig cfg;
    cfg.network_mounts = {std::string{"/"} + kVersions};
    const auto run = run_leg(rt::Action::python, dir.path, cfg);
    CHECK(run.rc == 0);
    CHECK(run.rows ==
          std::vector<std::string>{"status|python|constrained|macos:runtimes:network_fs_skipped"});
    CHECK(run.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(run.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(run.provenance == "macos:runtimes:network_fs_skipped");
}

TEST_CASE("python: an unreadable mount table is recorded and the walk still runs (SYNTHETIC)",
          "[runtimes][python][macos][mounts]") {
    // The walk runs guarded only by the mounts read, as on Linux: rows are kept, the status row is
    // constrained. MUTATION: dropping the token (or returning early) turns this red.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_pymac_nomounts_"};
    std::string err;
    REQUIRE(materialize_manifest_file(dir.path, err, macos_fixture()));
    rt::lnx::WalkConfig cfg;
    cfg.mountinfo_unreadable = true;
    const auto run = run_leg(rt::Action::python, dir.path, cfg);
    CHECK(run.rows == std::vector<std::string>{"status|python|constrained|macos:runtimes:mountinfo_unreadable",
                                               kRow311, kRow312, kRow313});
    CHECK(run.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(run.provenance == "macos:runtimes:mountinfo_unreadable");
}

#if defined(__APPLE__)

namespace {

struct StatfsTable {
    struct statfs row[6]{};
    void set(int i, const char* fstype, const char* on) {
        std::strncpy(row[i].f_fstypename, fstype, sizeof row[i].f_fstypename - 1);
        std::strncpy(row[i].f_mntonname, on, sizeof row[i].f_mntonname - 1);
    }
};

} // namespace

TEST_CASE("macos_network_mount_points keeps network types and respells Data-volume mounts (SYNTHETIC)",
          "[runtimes][python][macos][mounts]") {
    // MUTATION: keeping apfs, dropping the stripped spelling, or stripping a name that merely
    // starts with the volume prefix turns a check red.
    StatfsTable t;
    t.set(0, "apfs", "/");
    t.set(1, "nfs", "/Volumes/share");
    t.set(2, "apfs", "/System/Volumes/Data");
    t.set(3, "autofs", "/System/Volumes/Data/home");
    t.set(4, "smbfs", "/System/Volumes/DataX/vol");
    CHECK(yuzu::shared::macos_network_mount_points(t.row, 5) ==
          std::vector<std::string>{"/Volumes/share", "/System/Volumes/Data/home", "/home",
                                   "/System/Volumes/DataX/vol"});
    // A trailing-slash spelling of the volume root must not respell to "/" (that would skip every root).
    t.set(5, "nfs", "/System/Volumes/Data/");
    CHECK(yuzu::shared::macos_network_mount_points(t.row, 6).back() == "/System/Volumes/Data/");
    CHECK(yuzu::shared::macos_network_mount_points(t.row, 6).size() == 5);
    CHECK(yuzu::shared::macos_network_mount_points(t.row, 0).empty());
}

TEST_CASE("python: a Data-volume network mount over /Library skips the framework root (SYNTHETIC)",
          "[runtimes][python][macos][mounts]") {
    // The table names the mount `/System/Volumes/Data/Library`; the walk compares the logical
    // `/Library/...` spelling, which only the stripped entry catches.
    StatfsTable t;
    t.set(0, "nfs", "/System/Volumes/Data/Library");
    yuzu::test::TempDir dir{"yuzu_test_runtimes_pymac_datavol_"};
    std::string err;
    REQUIRE(materialize_manifest_file(dir.path, err, macos_fixture()));
    rt::lnx::WalkConfig cfg;
    cfg.network_mounts = yuzu::shared::macos_network_mount_points(t.row, 1);
    Acc acc;
    CHECK(mac::python_rows_at(dir.path, acc, cfg).empty());
    CHECK(acc.reason() == "macos:runtimes:network_fs_skipped");
}

TEST_CASE("python: mac::production_config reads the live mount table", "[runtimes][python][macos][mounts]") {
    // Smoke only: getmntinfo_r_np(MNT_NOWAIT) always lists the root mount, so the read succeeds.
    CHECK_FALSE(mac::production_config().mountinfo_unreadable);
}

TEST_CASE("python: mac::production_config maps the mount reader's answer onto the walk guard",
          "[runtimes][python][macos][mounts]") {
    // A failed read is `mountinfo_unreadable` with no mounts (the walk then runs guarded only by
    // that read); a successful one carries its list through and leaves the flag clear.
    const auto cfg_failed =
        mac::production_config([]() -> std::optional<std::vector<std::string>> { return std::nullopt; });
    CHECK(cfg_failed.mountinfo_unreadable);
    CHECK(cfg_failed.network_mounts.empty());

    const auto cfg_ok = mac::production_config([]() -> std::optional<std::vector<std::string>> {
        return std::vector<std::string>{"/Volumes/x"};
    });
    CHECK_FALSE(cfg_ok.mountinfo_unreadable);
    CHECK(cfg_ok.network_mounts == std::vector<std::string>{"/Volumes/x"});
}

#endif // defined(__APPLE__)

TEST_CASE("python: mac::forward_tokens re-spells linux: causes as macos: causes", "[runtimes][python][macos]") {
    Acc from, to;
    from.add_failure("linux:runtimes:permission_denied");
    from.add_failure("linux:runtimes:row_cap");
    mac::forward_tokens(from, to);
    CHECK(to.reason() == "macos:runtimes:permission_denied,macos:runtimes:row_cap");
}

#endif // !defined(_WIN32)
