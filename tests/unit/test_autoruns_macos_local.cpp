/**
 * test_autoruns_macos_local.cpp — macOS leg (P14) tests.
 *
 * UNGUARDED, deliberately, on every platform (precedent:
 * test_autoruns_local_dispatcher.cpp's own banner on why a compiled-out leg
 * must still have a test TU that loads it). Two halves:
 *
 *   1. `plist_to_launchd_fields` (autoruns_macos.hpp, header-only, Apple-only
 *      body) exercised directly against A2's REAL CAPTURE XML and binary
 *      plist fixtures — this is the ONE function real captures must drive
 *      through, since a symbol inside the dlopen'd autoruns plugin is not
 *      reachable from this test binary. Compiled only inside `#ifdef
 *      __APPLE__`: the header's non-Apple branch is a fixed, argument-
 *      independent stub with nothing fixture-shaped to assert against.
 *
 *   2. The actual autoruns plugin loaded via PluginHandle::load and driven
 *      through LocalDispatcher's "list" action (same technique as
 *      test_autoruns_local_dispatcher.cpp, scoped here to the macOS-specific
 *      assertions that dispatcher test does not make): on Apple,
 *      mac_system_launchdaemons reports supported with >= 50 rows; on every
 *      other OS, every macOS SourceId reports unsupported|foreign_os.
 */
#include <catch2/catch_test_macros.hpp>

#include "autoruns_catalog.hpp"
#include "autoruns_macos.hpp"
#include "autoruns_parsers.hpp"

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"
#include "test_helpers.hpp"

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::autoruns;

namespace {

fs::path fixture_path(const std::string& rel) {
    return fs::path{YUZU_TEST_FIXTURE_DIR} / "wave7" / "autoruns" / "macos" / rel;
}

std::vector<std::uint8_t> read_fixture(const std::string& rel) {
    const fs::path p = fixture_path(rel);
    REQUIRE(fs::exists(p));
    std::ifstream f(p, std::ios::binary);
    std::vector<std::uint8_t> out((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    REQUIRE_FALSE(out.empty());
    return out;
}

std::vector<std::string> captured_rows(const std::string& captured) {
    std::vector<std::string> out;
    std::istringstream ss(captured);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) out.push_back(line);
    }
    return out;
}

std::vector<std::string> fields_of(const std::string& row) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : row) {
        if (c == '|') { out.push_back(cur); cur.clear(); }
        else cur += c;
    }
    out.push_back(cur);
    return out;
}

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

fs::path find_autoruns_plugin() {
    const std::string lib_name = std::string{"autoruns"} + kPluginExt;
    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT"))
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "autoruns" / lib_name);
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "autoruns" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "autoruns" / lib_name);
    for (const char* b : {"build-macos", "build-linux", "build-windows"})
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "autoruns" / lib_name);
    for (const auto& c : candidates)
        if (std::error_code ec; fs::exists(c, ec)) return c;
    return {};
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor{nullptr};
    explicit operator bool() const { return descriptor != nullptr; }
};

std::optional<LoadedPlugin> load_autoruns_plugin() {
    auto path = find_autoruns_plugin();
    if (path.empty()) return std::nullopt;
    auto loaded = yuzu::agent::PluginHandle::load(path);
    if (!loaded) return std::nullopt;
    const auto* d = loaded->descriptor();
    if (!d) return std::nullopt;
    return LoadedPlugin{std::move(*loaded), d};
}

void skip_if_plugin_missing() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr)
        FAIL("autoruns plugin library not found under meson test -- it did not build, or "
             "link_depends is not forcing it to build before this test runs");
    WARN("autoruns plugin library not found -- skipping the LocalDispatcher round-trip");
}

} // namespace

// ── plist_to_launchd_fields over REAL CAPTURE fixtures (Apple-only) ───────

#if defined(__APPLE__)

TEST_CASE("autoruns macOS: plist_to_launchd_fields on a real XML LaunchAgent plist "
          "(homebrew.mxcl.postgresql@18.plist, real capture)",
          "[autoruns][macos]") {
    const auto bytes = read_fixture("homebrew.mxcl.postgresql@18.plist");
    const auto result = plist_to_launchd_fields(std::span<const std::uint8_t>{bytes.data(), bytes.size()});
    REQUIRE(result.has_value());
    CHECK(result->label == "homebrew.mxcl.postgresql@18");
    CHECK(result->program.empty()); // no `Program` key in this real capture
    REQUIRE_FALSE(result->program_arguments.empty());
    CHECK(result->program_arguments.front() == "/opt/homebrew/opt/postgresql@18/bin/postgres");
    CHECK_FALSE(result->disabled_present); // no `Disabled` key in this real capture
}

TEST_CASE("autoruns macOS: plist_to_launchd_fields on a real XML LaunchDaemon plist with "
          "an explicit Program key (com.docker.socket.plist, real capture)",
          "[autoruns][macos]") {
    const auto bytes = read_fixture("com.docker.socket.plist");
    const auto result = plist_to_launchd_fields(std::span<const std::uint8_t>{bytes.data(), bytes.size()});
    REQUIRE(result.has_value());
    CHECK(result->label == "com.docker.socket");
    CHECK(result->program == "/Library/PrivilegedHelperTools/com.docker.socket");
}

TEST_CASE("autoruns macOS: plist_to_launchd_fields on a real BINARY plist "
          "(com.apple.AppleCredentialManagerDaemon.plist, real capture, bplist00 magic)",
          "[autoruns][macos]") {
    const auto bytes = read_fixture("com.apple.AppleCredentialManagerDaemon.plist");
    REQUIRE(bytes.size() >= 8);
    CHECK(std::string(bytes.begin(), bytes.begin() + 6) == "bplist"); // confirms the fixture IS binary
    const auto result = plist_to_launchd_fields(std::span<const std::uint8_t>{bytes.data(), bytes.size()});
    REQUIRE(result.has_value());
    CHECK(result->label == "com.apple.AppleCredentialManagerDaemon");
    CHECK(result->program.empty());
    REQUIRE_FALSE(result->program_arguments.empty());
    CHECK(result->program_arguments.front() ==
         "/System/Library/PrivateFrameworks/AppleCredentialManager.framework/AppleCredentialManagerDaemon");
    CHECK_FALSE(result->disabled_present);
}

TEST_CASE("autoruns macOS: plist_to_launchd_fields on a second real BINARY plist "
          "(com.apple.AssetCacheLocatorService.plist, real capture)",
          "[autoruns][macos]") {
    const auto bytes = read_fixture("com.apple.AssetCacheLocatorService.plist");
    const auto result = plist_to_launchd_fields(std::span<const std::uint8_t>{bytes.data(), bytes.size()});
    REQUIRE(result.has_value());
    CHECK(result->label == "com.apple.AssetCacheLocatorService");
    REQUIRE(result->program_arguments.size() >= 2);
    CHECK(result->program_arguments[1] == "-d");
}

TEST_CASE("autoruns macOS: launchd_row_from_fields over a real XML capture's parsed fields "
          "produces the expected autorun row shape",
          "[autoruns][macos]") {
    const auto bytes = read_fixture("com.docker.vmnetd.plist");
    const auto result = plist_to_launchd_fields(std::span<const std::uint8_t>{bytes.data(), bytes.size()});
    REQUIRE(result.has_value());
    const Row row = launchd_row_from_fields(SourceId::mac_launchdaemons, *result,
                                            "/Library/LaunchDaemons/com.docker.vmnetd.plist",
                                            Scope::system, 0);
    CHECK(row.source_id == SourceId::mac_launchdaemons);
    CHECK(row.entry == result->label);
    CHECK(row.signed_state == Signed::not_checked); // not under /System/Library
    CHECK(row.enabled == Enabled::enabled); // no Disabled key in this real capture
}

TEST_CASE("autoruns macOS: a plist with none of Disabled/RunAtLoad/KeepAlive/Start* "
          "still reports enabled, not unmodelled (RECONSTRUCTION: pins the documented "
          "divergence from the objective's literal key list -- see "
          "docs/wave7/integration-autoruns-macos.md #4 and autoruns_macos.hpp's SCOPE "
          "NOTE: LaunchdFields, P11, carries no members for those four keys, so this "
          "leg cannot reach the `unmodelled` branch the objective describes)",
          "[autoruns][macos]") {
    static constexpr std::string_view kBarePlist =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">"
        "<plist version=\"1.0\"><dict>"
        "<key>Label</key><string>com.example.bare</string>"
        "</dict></plist>";
    const std::vector<std::uint8_t> bytes(kBarePlist.begin(), kBarePlist.end());
    const auto result = plist_to_launchd_fields(std::span<const std::uint8_t>{bytes.data(), bytes.size()});
    REQUIRE(result.has_value());
    CHECK_FALSE(result->disabled_present);
    const Row row = launchd_row_from_fields(SourceId::mac_launchagents, *result,
                                            "/Library/LaunchAgents/com.example.bare.plist",
                                            Scope::system, 0);
    CHECK(row.enabled == Enabled::enabled);
}

TEST_CASE("autoruns macOS: a truncated plist yields a typed error, never a crash or an "
          "empty success (RECONSTRUCTION: a real capture cut to its first 16 bytes)",
          "[autoruns][macos]") {
    auto bytes = read_fixture("homebrew.mxcl.postgresql@18.plist");
    REQUIRE(bytes.size() > 16);
    bytes.resize(16); // "<?xml version=\"1" -- an unterminated document
    const auto result = plist_to_launchd_fields(std::span<const std::uint8_t>{bytes.data(), bytes.size()});
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == PlistError::unparseable);
}

TEST_CASE("autoruns macOS: an empty byte span yields a typed error, never a crash",
          "[autoruns][macos]") {
    const auto result = plist_to_launchd_fields(std::span<const std::uint8_t>{});
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == PlistError::unparseable);
}

TEST_CASE("autoruns macOS: a well-formed plist whose root is not a dictionary "
          "(RECONSTRUCTION: a bare XML array) is unparseable for launchd purposes",
          "[autoruns][macos]") {
    static constexpr std::string_view kArrayPlist =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">"
        "<plist version=\"1.0\"><array><string>not a dict</string></array></plist>";
    const std::vector<std::uint8_t> bytes(kArrayPlist.begin(), kArrayPlist.end());
    const auto result = plist_to_launchd_fields(std::span<const std::uint8_t>{bytes.data(), bytes.size()});
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == PlistError::unparseable);
}

#endif // __APPLE__

// ── is_benign_absent_errno (portable -- every OS) ──────────────────────────

TEST_CASE("autoruns macOS: is_benign_absent_errno distinguishes a genuinely-absent "
          "path from a real open constraint (RECONSTRUCTION: pins the fix for a "
          "code-review finding -- open_dir_no_follow used to discard errno entirely, "
          "reporting EACCES the same as ENOENT: an unreadable location as an empty "
          "success instead of constrained + reason)",
          "[autoruns][macos]") {
    CHECK(is_benign_absent_errno(ENOENT));
    CHECK_FALSE(is_benign_absent_errno(EACCES));
    CHECK_FALSE(is_benign_absent_errno(ELOOP));
    CHECK_FALSE(is_benign_absent_errno(ENOTDIR));
}

// ── the real plugin, via LocalDispatcher (every OS) ────────────────────────

TEST_CASE("autoruns plugin: macOS SourceIds report correctly for this build's own OS",
          "[autoruns][macos][actions]") {
    auto plugin = load_autoruns_plugin();
    if (!plugin) {
        skip_if_plugin_missing();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "list");
    CHECK(result.rc == 0);

    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());

    std::set<std::string> macos_ids;
    for (const auto& decl : kSourceCatalog)
        if (decl.macos != YUZU_SUPPORT_UNSUPPORTED) macos_ids.insert(std::string{source_id_string(decl.id)});
    REQUIRE(macos_ids.size() == 8);

    std::set<std::string> seen_macos_status;
    std::size_t system_launchdaemon_rows = 0;

#if defined(__APPLE__)
    for (const auto& r : rows) {
        const auto f = fields_of(r);
        if (f[0] != "source") continue;
        if (macos_ids.count(f[1]) == 0) continue;
        seen_macos_status.insert(f[1]);
        if (f[1] == "mac_system_launchdaemons") {
            CHECK(f[2] == "supported");
            system_launchdaemon_rows = f[3] == "-" ? 0 : static_cast<std::size_t>(std::stoul(f[3]));
        }
        if (f[1] == "mac_login_items") {
            CHECK(f[2] == "constrained");
            CHECK(f[3] == "0");
            CHECK(f[4] == "btm_private_database_no_public_api");
        }
    }
    // Every macOS SourceId emits one source| line.
    CHECK(seen_macos_status.size() == macos_ids.size());
    CHECK(system_launchdaemon_rows >= 50);
#else
    for (const auto& r : rows) {
        const auto f = fields_of(r);
        if (f[0] != "source") continue;
        if (macos_ids.count(f[1]) == 0) continue;
        seen_macos_status.insert(f[1]);
        CHECK(f[2] == "unsupported");
        CHECK(f[4] == "foreign_os");
    }
    CHECK(seen_macos_status.size() == macos_ids.size());
#endif
}


// ── #4241/#4186 fault-injection tests (Apple-only: StatFns, walk_dir_names,
// collect_user_launchagents, note_dir_constraint are all Apple-only symbols)
// ────────────────────────────────────────────────────────────────────────
#if defined(__APPLE__)

// Direct source inclusion, macOS-only, mirroring autoruns_linux.cpp's
// identical seam (see that file's own banner, and
// YUZU_AUTORUNS_MACOS_UNIT_TEST_INTERNALS_ONLY's definition comment in
// autoruns_macos.cpp): StatFns, stat_constraint_token's callers,
// DirCollectOutcome, walk_dir_names, note_dir_constraint, and
// collect_user_launchagents all have internal (anonymous-namespace)
// linkage, so there is no header seam to reach them through otherwise. This
// TU never statically links the real plugin either way (the TEST_CASEs
// above load it via PluginHandle::load/dlopen at runtime), so a second
// compilation of the same free functions here creates no ODR/duplicate-
// symbol conflict.
// Excluding collect_macos leaves 5 of its helper functions
// (source_in_filter/emit_status/parse_plist_root/emond_fields_from_dict/
// collect_launchd_dir) with no caller in THIS compilation of the TU -- they
// are all real, used call sites in the actual (non-test) build of this same
// file, where collect_macos is present. -Wunused-function is non-fatal
// project-wide (werror=false, root meson.build) but is silenced narrowly
// here, scoped to just the include, rather than annotating five production
// functions [[maybe_unused]] for a warning that only fires in this one
// test-only re-inclusion.
#define YUZU_AUTORUNS_MACOS_UNIT_TEST_INTERNALS_ONLY 1
#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
#include "../../agents/plugins/autoruns/src/autoruns_macos.cpp"
#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
#undef YUZU_AUTORUNS_MACOS_UNIT_TEST_INTERNALS_ONLY

TEST_CASE("autoruns macOS: stat_constraint_token maps a stat/fstatat errno to a "
          "reason token, ENOENT to nullopt (benign, matching is_benign_absent_errno)",
          "[autoruns][macos]") {
    CHECK_FALSE(stat_constraint_token(ENOENT).has_value());
    REQUIRE(stat_constraint_token(EACCES).has_value());
    CHECK(*stat_constraint_token(EACCES) == "permission_denied");
    REQUIRE(stat_constraint_token(ELOOP).has_value());
    CHECK(*stat_constraint_token(ELOOP) == "symlink_refused");
    REQUIRE(stat_constraint_token(EIO).has_value());
    CHECK(*stat_constraint_token(EIO) == "stat_failed");
}

TEST_CASE("autoruns macOS: walk_dir_names surfaces a real fstatat() failure as a "
          "constraint instead of silently skipping the entry (#4241, site 1)",
          "[autoruns][macos]") {
    yuzu::test::TempDir dir("yuzu_test_autoruns_macos_walkdirnames_");
    fs::create_directories(dir.path);
    { std::ofstream(dir.path / "script.sh") << "#!/bin/sh\n"; }

    SECTION("an injected EIO on the one entry is reported constrained, stat_failed") {
        StatFns failing;
        failing.fstatat_fn = [](int, const char*, struct stat*, int) -> int {
            errno = EIO;
            return -1;
        };
        int seen = 0;
        const auto result = walk_dir_names(
            dir.path.string(), [&](const char*, std::int64_t) { ++seen; }, failing);
        CHECK(seen == 0); // the failing entry never reaches on_entry
        CHECK(result.constrained);
        CHECK(result.reason == "stat_failed");
    }

    SECTION("an injected ENOENT (benign race) is NOT reported constrained") {
        StatFns benign;
        benign.fstatat_fn = [](int, const char*, struct stat*, int) -> int {
            errno = ENOENT;
            return -1;
        };
        int seen = 0;
        const auto result = walk_dir_names(
            dir.path.string(), [&](const char*, std::int64_t) { ++seen; }, benign);
        CHECK(seen == 0);
        CHECK_FALSE(result.constrained);
    }

    SECTION("the real (uninjected) syscall still works against a real file") {
        int seen = 0;
        const auto result = walk_dir_names(dir.path.string(),
                                           [&](const char*, std::int64_t) { ++seen; });
        CHECK(seen == 1);
        CHECK_FALSE(result.constrained);
    }
}

TEST_CASE("autoruns macOS: collect_user_launchagents surfaces a real fstat() "
          "failure on a user's home directory as a constraint instead of silently "
          "skipping that user (#4241, site 2)",
          "[autoruns][macos]") {
    yuzu::test::TempDir users_dir("yuzu_test_autoruns_macos_users_");
    fs::create_directories(users_dir.path / "alice" / "Library" / "LaunchAgents");
    // chown isn't available to an unprivileged test process, so st_uid on a
    // freshly-created temp dir is already this process's own uid -- >= 500
    // on every real macOS account, satisfying the "real user home" filter
    // without needing root.

    // nullptr is safe here: both SECTIONs below inject an fstat() failure
    // on the home directory itself, so the walk never reaches
    // collect_launchd_dir_handle's ctx.write_output call -- ctx stays
    // completely untouched (CommandContext's constructor is a noexcept
    // pointer store, never dereferenced until write_output/report_progress/
    // set_result_status is actually called).
    yuzu::CommandContext ctx{nullptr};

    SECTION("an injected EACCES on the home fstat is reported permission_denied") {
        StatFns failing;
        failing.fstat_fn = [](int, struct stat*) -> int {
            errno = EACCES;
            return -1;
        };
        const auto outcome = collect_user_launchagents(ctx, failing, users_dir.path.string());
        CHECK(outcome.acc.any_failure());
        CHECK(outcome.acc.reason() == "permission_denied");
        CHECK(outcome.rows == 0);
    }

    SECTION("an injected ENOENT (benign race) is NOT reported constrained") {
        StatFns benign;
        benign.fstat_fn = [](int, struct stat*) -> int {
            errno = ENOENT;
            return -1;
        };
        const auto outcome = collect_user_launchagents(ctx, benign, users_dir.path.string());
        CHECK_FALSE(outcome.acc.any_failure());
    }
}

TEST_CASE("autoruns macOS: collect_user_launchagents's outer (/Users) and inner "
          "(per-user LaunchAgents) walks produce distinctly-suffixed row_cap tokens "
          "when BOTH hit their (now independently injectable) cap on a real temp-dir "
          "tree -- drives the actual production branch selection, not just the "
          "accumulator's dedup behavior in isolation (#4186, closing the coverage gap "
          "an adversarial functional review found in this test's first version: the "
          "original only fed hand-picked strings straight to note_dir_constraint, so "
          "reverting either call site's suffix back to plain row_cap would have left "
          "every assertion here green)",
          "[autoruns][macos]") {
    yuzu::test::TempDir users_dir("yuzu_test_autoruns_macos_compound_cap_");
    // Two real per-user homes so outer_cap=1 genuinely truncates (one processed,
    // one left for the lookahead to find).
    fs::create_directories(users_dir.path / "alice" / "Library" / "LaunchAgents");
    fs::create_directories(users_dir.path / "bob" / "Library" / "LaunchAgents");
    // Two real entries in EACH user's LaunchAgents so inner_cap=1 genuinely
    // truncates too, whichever of alice/bob the outer walk happens to visit
    // (readdir order is unspecified) -- the cap counts every real entry
    // visited, not just ones that parse as a valid plist (walk_plist_dir_handle's
    // own banner), so plain non-.plist files are sufficient here.
    for (const char* user : {"alice", "bob"}) {
        const auto agents_dir = users_dir.path / user / "Library" / "LaunchAgents";
        { std::ofstream(agents_dir / "a.plist") << "not parsed in this test"; }
        { std::ofstream(agents_dir / "b.plist") << "not parsed in this test"; }
    }

    yuzu::CommandContext ctx{nullptr}; // safe: file content is deliberately
                                       // unparseable, so no row ever reaches
                                       // ctx.write_output in this test
    const auto outcome =
        collect_user_launchagents(ctx, StatFns{}, users_dir.path.string(), /*outer_cap=*/1,
                                  /*inner_cap=*/1);

    CHECK(outcome.acc.any_failure());
    const std::string reason = outcome.acc.reason();
    CHECK(reason.find("row_cap:users") != std::string::npos);
    CHECK(reason.find("row_cap:launchagents") != std::string::npos);
    // Neither walk hitting its cap is ever reported as the OTHER walk's
    // token, nor as the old, ambiguous unsuffixed "row_cap" -- a regression
    // to plain row_cap at either call site would make this substring search
    // spuriously match too (it's a substring of both suffixed forms), so
    // this also catches a reversion to the unsuffixed token, not just a
    // swap between the two suffixes.
    CHECK(reason.find("row_cap") != std::string::npos); // sanity: token family present at all
}

TEST_CASE("autoruns macOS: ConstraintAccumulator's exact-match dedup survives both "
          "insertion orders of a plain token alongside a suffixed sibling (#4186) -- "
          "exercises note_dir_constraint directly, isolating the accumulator's own "
          "dedup contract from the production branch-selection logic the test above "
          "covers",
          "[autoruns][macos]") {
    // The specific regression this guards: a PLAIN "row_cap" token arriving
    // alongside a suffixed one must survive as its own distinct entry, not
    // be absorbed by (or absorb) the suffixed one -- the exact conflation
    // ConstraintAccumulator's exact-string dedup exists to prevent, that
    // this file's former substring-matching accumulator was vulnerable to.
    // Both insertion orders are asserted: "row_cap" then "row_cap:users"
    // does NOT discriminate old vs. new (the old algorithm's
    // `reason.find(token)` check with reason="row_cap" and the LONGER
    // token="row_cap:users" also returns npos -- both algorithms keep both
    // tokens here). The REVERSE order is the one that actually catches the
    // regression: under the OLD algorithm, reason="row_cap:users" already
    // CONTAINS "row_cap" as a substring, so `note_dir_constraint(outcome,
    // "row_cap")` second would have been wrongly treated as "already
    // recorded" and silently dropped -- losing the plain row_cap token
    // entirely. The new exact-match accumulator keeps both, in insertion
    // order, either way.
    DirCollectOutcome mixed;
    note_dir_constraint(mixed, "row_cap");
    note_dir_constraint(mixed, "row_cap:users");
    CHECK(mixed.acc.reason() == "row_cap,row_cap:users");

    DirCollectOutcome mixed_reversed;
    note_dir_constraint(mixed_reversed, "row_cap:users");
    note_dir_constraint(mixed_reversed, "row_cap");
    CHECK(mixed_reversed.acc.reason() == "row_cap:users,row_cap");
}

#endif // defined(__APPLE__)
