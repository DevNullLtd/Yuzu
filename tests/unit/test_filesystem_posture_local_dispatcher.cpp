/**
 * test_filesystem_posture_local_dispatcher.cpp — PKG-CORE (Wave-1): loads
 * the ACTUAL built filesystem_posture plugin
 * (filesystem_posture.dylib / .so / .dll)
 * via PluginHandle::load and drives it through yuzu::agent::LocalDispatcher
 * (test_network_config_local_dispatcher.cpp's pattern), exercising all three
 * actions' real per-OS legs end to end on the build host.
 *
 * Assertions are OUTCOME-specific rather than only `rc == 0` (every action
 * returns 0 on every path by design -- see filesystem_posture_legs.hpp):
 * field count and enumerated-token shape per row. The field split is
 * escape-aware (peer L3): yuzu::util::safe_output_field escapes a literal
 * '|' as '\|', so a naive split('|') would overcount fields on any row
 * whose escaped text happens to contain a pipe.
 *
 * RUNS ON ALL THREE PLATFORMS. This TU was previously `#ifndef _WIN32`,
 * guarded solely by the since-retired "Windows legs are compile-verified
 * only" stance -- LocalDispatcher and PluginHandle are both platform-neutral,
 * so nothing technical required the exclusion. That guard is why a Windows
 * snapshots leg built on FSCTL_SRV_ENUMERATE_SNAPSHOTS -- a control no header
 * in SDK 10.0.26100.0 declares, so the real path was compiled OUT -- shipped
 * green: no test ever loaded the Windows plugin.
 *
 * Note that the row-shape assertions alone would NOT have caught it: the
 * compiled-out leg emitted a perfectly well-formed
 * `snapshot|-|-|none|built without FSCTL_SRV_ENUMERATE_SNAPSHOTS` row. The
 * assertion that catches it is the BUILD-COMPLETENESS one below, which fails
 * when a leg reports that its own SDK guard excluded it.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"

#include "filesystem_posture_legs.hpp"

#include <cstdlib>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

// Escape-aware split: a backslash-preceded '|' is DATA (safe_output_field's
// own escape for a literal pipe), never a field separator. safe_output_field
// folds every literal backslash in the source value to '/' before escaping,
// so an observed "\|" in plugin output is unambiguous.
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

// Returns every non-empty captured row (peer PKG-008): filtering by prefix
// let a wrong-prefix row disappear silently instead of failing the shape
// assertions below, so every row -- not just the ones matching the expected
// prefix -- must be checked.
// CDX-P2-03 / K2: the real-action tests below asserted rc and row shape but
// never result_status, so a leg that reports CONSTRAINED/PARTIAL on a
// perfectly healthy host passed 238 assertions cleanly. That is exactly how
// the unbraced-if defect (every macOS snapshots run falsely PARTIAL, with a
// fabricated "malformed reply buffer" provenance) shipped green.
//
// The assertion is deliberately an INVARIANT rather than "status must be OK":
// a host with a genuinely unreadable volume SHOULD report PARTIAL, and the
// test must not fail there. What must always hold is that a degraded status
// is EXPLICABLE FROM THE OUTPUT -- if the run says it degraded, some row has
// to show it.
// Every caller sits inside #ifndef _WIN32 / #ifdef __APPLE__, so on the MSVC
// leg this would be an unreferenced static function — silent at /W3 but
// -Wunused-function under clang-cl (Gate 3, cpp-expert).
#ifndef _WIN32
std::vector<std::string> split_row(const std::string& row) {
    std::vector<std::string> f;
    std::string cur;
    for (char c : row) {
        if (c == '|') {
            f.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    f.push_back(cur);
    return f;
}
#endif // !_WIN32

// UP-5 (Gate 4, unhappy-path): the "a degraded run must be explicable from its
// own rows" invariants below were each gated on CONSTRAINED alone. This change
// made PERMISSION_DENIED reachable from these very legs, so on exactly the
// hosts where degradation happens — an unprivileged one — those invariants
// silently asserted nothing. Both statuses are degradations and both must be
// explicable.
bool is_degraded(YuzuResultStatus s) {
    return s == YUZU_RESULT_STATUS_CONSTRAINED || s == YUZU_RESULT_STATUS_PERMISSION_DENIED;
}

std::vector<std::string> captured_rows(const std::string& captured) {
    std::vector<std::string> out;
    std::istringstream ss(captured);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (!line.empty())
            out.push_back(line);
    }
    return out;
}

// Mirrors test_network_config_local_dispatcher.cpp's require_plugin_or_skip:
// under `meson test` (MESON_BUILD_ROOT always set), a missing plugin means
// the build is genuinely broken and must NOT report "All tests passed".
void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) {
        FAIL("filesystem_posture plugin library not found under meson test — the plugin did not "
             "build, or link_depends is not forcing it to build before this test runs");
    }
    WARN("filesystem_posture plugin library not found -- skipping LocalDispatcher round-trip "
         "test (run from the build root, or via `meson test`, to exercise it)");
}

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

// Candidate-path ladder: mirrors test_license_scan_actions.cpp:46-60 (5
// candidates -- an optional MESON_BUILD_ROOT-relative path plus 4 fixed
// relative-to-cwd fallbacks).
fs::path find_filesystem_posture_plugin() {
    const std::string lib_name = std::string{"filesystem_posture"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" /
                                "filesystem_posture" / lib_name);
    }
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "filesystem_posture" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "filesystem_posture" /
                            lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" /
                            "filesystem_posture" / lib_name);
    candidates.emplace_back(fs::path{"build-windows"} / "agents" / "plugins" /
                            "filesystem_posture" / lib_name);
    candidates.emplace_back(fs::path{"build-linux"} / "agents" / "plugins" /
                            "filesystem_posture" / lib_name);

    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec)
            return fs::absolute(p, ec);
    }
    return {};
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor;
};

std::optional<LoadedPlugin> load_filesystem_posture_plugin() {
    auto plugin_path = find_filesystem_posture_plugin();
    if (plugin_path.empty())
        return std::nullopt;
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    if (!handle.has_value())
        return std::nullopt;
    const auto* descriptor = handle->descriptor();
    if (!descriptor)
        return std::nullopt;
    return LoadedPlugin{std::move(*handle), descriptor};
}

const char* kQuotaTokens[] = {"configured",       "none",     "not_enabled",       "unsupported_fs",
                              "no_block_device", "permission_denied", "unavailable"};

const char* kSnapshotKinds[] = {"apfs", "btrfs_subvolume", "device_mapper", "vss", "none"};

bool one_of(const std::string& v, const char* const* set, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) {
        if (v == set[i])
            return true;
    }
    return false;
}

// Callback that exercises mark_result_partial twice (peer PKG-002): the only
// deterministic way to prove the degraded-result seam -- constrained/partial
// status plus last-writer-wins provenance -- actually reaches LocalDispatcher
// rather than merely being called somewhere the compiler accepts.
int exercise_mark_result_partial(YuzuCommandContext* raw, const char* /*action*/,
                                 const YuzuParam* /*params*/, std::size_t /*param_count*/) {
    yuzu::CommandContext ctx{raw};
    yuzu::filesystem_posture::mark_result_partial(ctx, "first", "first failure");
    yuzu::filesystem_posture::mark_result_partial(ctx, "second", "second failure");
    return 0;
}

int exercise_mark_result_denied(YuzuCommandContext* raw, const char* /*action*/,
                                const YuzuParam* /*params*/, std::size_t /*param_count*/) {
    yuzu::CommandContext ctx{raw};
    yuzu::filesystem_posture::mark_result_denied(ctx, "denied", "access denied");
    return 0;
}

} // namespace

TEST_CASE("filesystem_posture: mark_result_partial's degraded status and last-writer provenance "
         "reach LocalDispatcher (peer PKG-002)",
         "[filesystem_posture][status]") {
    YuzuPluginDescriptor descriptor{};
    descriptor.execute = &exercise_mark_result_partial;

    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(&descriptor, "probe");

    CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(result.result_provenance == "second");
}

// QE-2 (Gate 3, quality-engineer): mark_result_denied is the whole of SG-2's
// closure — the descriptor and four operator-facing docs state that a denied
// read reports `permission_denied`, and before this test nothing asserted the
// helper set that status rather than CONSTRAINED. Platform-neutral: a synthetic
// descriptor through LocalDispatcher, no OS call and no plugin load.
TEST_CASE("filesystem_posture: mark_result_denied reports PERMISSION_DENIED rather than CONSTRAINED",
         "[filesystem_posture][status]") {
    YuzuPluginDescriptor descriptor{};
    descriptor.execute = &exercise_mark_result_denied;

    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(&descriptor, "probe");

    CHECK(result.result_status == YUZU_RESULT_STATUS_PERMISSION_DENIED);
    CHECK(result.result_status != YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(result.result_provenance == "denied");
}

TEST_CASE("filesystem_posture plugin: mounts action shape", "[filesystem_posture][posix_actions]") {
    auto plugin = load_filesystem_posture_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "mounts");
    CHECK(result.rc == 0);

    const auto rows = captured_rows(result.captured);
    // Every host has at least a root mount.
    REQUIRE_FALSE(rows.empty());

    // CDX-P2-03, corrected for Linux (governance CP-1). The original assertion
    // -- "rows present therefore no degradation is reachable" -- reasons from
    // macOS, where emit_mounts returns early with no rows if getmntinfo fails.
    // On Linux emit_mounts legitimately marks partial WHILE emitting rows (the
    // 4 MiB read cap, a per-mount statvfs failure, a malformed line, the entry
    // cap), and this test runs on the Linux CI leg -- one statvfs EACCES would
    // have turned it red for a correct reason. Assert the same
    // explicable-from-the-rows invariant the other two actions use: a degraded
    // mounts run must show a row whose capacity columns degraded to "-".
    //
    // POSIX ONLY. On Windows emit_mounts also marks partial for a
    // FindFirstVolumeW/FindNextVolumeW failure, which is an ENUMERATION-level
    // degradation with no row of its own -- every row already emitted stays
    // healthy, so a Windows CONSTRAINED run legitimately shows no degraded
    // row and this invariant would fail for a correct reason. That is the
    // same class of mistake as CP-1 (reasoning from one platform's
    // degradation model and asserting it on another), so it is scoped rather
    // than weakened for everyone.
#ifndef _WIN32
    if (is_degraded(result.result_status)) {
        bool any_degraded_row = false;
        for (const auto& r : rows) {
            const auto f = split_row(r);
            if (f.size() > 7 && (f[5] == "-" || f[6] == "-" || f[7] == "-"))
                any_degraded_row = true;
        }
        CHECK(any_degraded_row);
    }
#endif

    for (const auto& r : rows) {
        const auto f = split_fields_escape_aware(r);
        REQUIRE(f.size() == 9);
        CHECK(f[0] == "mount");
    }
}

TEST_CASE("filesystem_posture plugin: quotas action shape", "[filesystem_posture][posix_actions]") {
    auto plugin = load_filesystem_posture_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "quotas");
    CHECK(result.rc == 0);

    const auto rows = captured_rows(result.captured);
    // Every host has at least a root mount, so at least one quota row.
    REQUIRE_FALSE(rows.empty());
    for (const auto& r : rows) {
        const auto f = split_fields_escape_aware(r);
        REQUIRE(f.size() == 7);
        CHECK(f[0] == "quota");
        CHECK(f[2] == "volume");
        CHECK(one_of(f[3], kQuotaTokens, std::size(kQuotaTokens)));
    }

    // CDX-P2-03: a degraded quota run must be explicable from its own rows.
    // emit_quotas degrades exactly when a probe returns permission_denied or
    // unavailable, and both states are visible in the row's state column -- so
    // a degraded status with every row healthy means the status is lying.
    // Since CP-1 a denial reports PERMISSION_DENIED rather than CONSTRAINED,
    // which is why the guard below tests is_degraded() and not one status
    // (Gate 4, consistency-auditor CA-5a: the narrower guard silently stopped
    // covering the denial case it was written for).
    //
    // POSIX ONLY, for the same reason as the mounts invariant above: the
    // Windows leg marks partial on a volume-enumeration failure, which is not
    // visible in any row.
#ifndef _WIN32
    if (is_degraded(result.result_status)) {
        bool any_degraded_row = false;
        for (const auto& r : rows) {
            const auto f = split_row(r);
            // f[2] is the SCOPE literal ("volume"); the state is f[3] -- as this
            // same test's shape loop above asserts. Reading f[2] here made the
            // invariant unreachable, so it asserted nothing on a healthy host
            // and failed unconditionally on a degraded one (governance G4-03).
            if (f.size() > 3 && (f[3] == "permission_denied" || f[3] == "unavailable"))
                any_degraded_row = true;
        }
        CHECK(any_degraded_row);
    }
#endif

    // BUILD-COMPLETENESS (Windows). A row whose detail says the leg was built
    // without its own SDK header means the __has_include guard excluded the
    // real implementation and this build ships a permanent stub. That is a
    // BUILD defect, not a host condition, so it fails here rather than being
    // reported as a runtime degradation an operator might rationalise away.
    // quota row: quota|mount|volume|state|limit|reserved|detail -> detail is f[6].
#ifdef _WIN32
    for (const auto& r : rows) {
        const auto f = split_fields_escape_aware(r);
        if (f.size() > 6) {
            INFO("quota row: " << r);
            CHECK(f[6].find("built without") == std::string::npos);
        }
    }
#endif
}

TEST_CASE("filesystem_posture plugin: snapshots action shape",
         "[filesystem_posture][posix_actions]") {
    auto plugin = load_filesystem_posture_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "snapshots");
    CHECK(result.rc == 0);

    const auto rows = captured_rows(result.captured);
    // Every host has at least a root mount, so at least one snapshot row.
    REQUIRE_FALSE(rows.empty());
    for (const auto& r : rows) {
        const auto f = split_fields_escape_aware(r);
        REQUIRE(f.size() == 5);
        CHECK(f[0] == "snapshot");
        CHECK(one_of(f[3], kSnapshotKinds, std::size(kSnapshotKinds)));
    }

    // CDX-P2-03 / K1 REGRESSION PIN: this is the assertion whose absence let
    // an unbraced `if` report CONSTRAINED/PARTIAL on every macOS snapshots
    // run, with a fabricated "malformed reply buffer" provenance, while 238
    // assertions passed. A healthy row is (kind=apfs, detail="-") or the
    // single genuinely-empty "none" sentinel; if EVERY row is healthy the run
    // must not claim it degraded.
    //
    // Scoped to __APPLE__: both "healthy" shapes it tests for are literally
    // the macOS leg's (kind "apfs", and that leg's exact empty sentinel), so
    // on any other platform it is satisfied by construction and asserts
    // nothing. Naming the scope keeps that honest instead of leaving it
    // looking like a cross-platform invariant.
#ifdef __APPLE__
    if (is_degraded(result.result_status)) {
        bool any_unhealthy_row = false;
        for (const auto& r : rows) {
            const auto f = split_row(r);
            if (f.size() < 5)
                continue;
            const bool healthy_named = (f[3] == "apfs" && f[4] == "-");
            const bool healthy_empty = (f[3] == "none" && f[4] == "no APFS snapshots present");
            if (!healthy_named && !healthy_empty)
                any_unhealthy_row = true;
        }
        CHECK(any_unhealthy_row);
    }
#endif

    // BUILD-COMPLETENESS (Windows) -- THE REGRESSION PIN FOR THIS LEG.
    // The retired FSCTL_SRV_ENUMERATE_SNAPSHOTS implementation emitted a
    // well-formed `snapshot|-|-|none|built without FSCTL_SRV_ENUMERATE_SNAPSHOTS`
    // row on every run, because no header in SDK 10.0.26100.0 declares that
    // control, so its #ifdef compiled the real path out. Every shape and
    // vocabulary assertion above passed on it. This is the assertion that
    // fails on a leg whose SDK guard excluded its own implementation.
    // snapshot row: snapshot|mount|name|kind|detail -> detail is f[4].
#ifdef _WIN32
    for (const auto& r : rows) {
        const auto f = split_fields_escape_aware(r);
        if (f.size() > 4) {
            INFO("snapshot row: " << r);
            CHECK(f[4].find("built without") == std::string::npos);
        }
    }
#endif
}

// (end of the formerly Windows-excluded region -- see the banner)
