/**
 * test_installed_apps_actions.cpp -- Wave 4 PR4.3a dispatch remediation:
 * loads the ACTUAL built installed_apps plugin (installed_apps.dylib/.so, the
 * same artifact the agent daemon loads in production) via PluginHandle::load
 * and drives it through yuzu::agent::LocalDispatcher, same pattern as
 * test_users_posix_actions.cpp -- this proves the migrated argv (probe_tool_path
 * + run_bounded_subprocess, replacing popen()/command_exists()) actually
 * reaches a real dpkg-query/rpm/pacman/system_profiler binary on the test
 * host, end to end, not just that the pure parsers in
 * installed_apps_parsers.hpp accept a fixture string.
 *
 * `list` is the fast, local, always-available action (no params; on macOS one
 * bounded in-process CFBundle read per listed app for bundle_id, inside the noise
 * of the single system_profiler call on this Mac, 2026-09-21) -- assertions are on
 * rc and output SHAPE (every emitted line matches the `app|` wire prefix), never
 * on specific app names/counts, which are host-dependent, with ONE deliberate
 * exception: the `list` case asserts value-level facts every Mac guarantees
 * (`*.app` rows under `/System/Applications/` with `com.apple.*` bundle ids,
 * absolute locations), because shape-only checks survive reverting either half of the
 * ADR-0028 wiring (see that case's own comment).
 *
 * TEST-EFFICIENCY JUSTIFICATION (CLAUDE.md unit-suite discipline requires one
 * whenever a test's runtime depends on process creation):
 *   - What it costs, measured on this host (macOS 26, arm64, 2026-08-24):
 *     `list` 1.4-2.3 s wall (2026-09-21; the 2026-08-24 base figure was 4.5 s),
 *     `list_inventory` a few seconds more. `list` is
 *     dominated by one `system_profiler` call plus that in-process pass (no
 *     process fan-out); the pkgutil receipt leg is a bounded per-id loop under
 *     kMaxPkgutilPackages.
 *   - Why a pure-function test cannot replace it: the pure parsers in
 *     installed_apps_parsers.hpp are already exhaustively covered by
 *     test_installed_apps_parsers.cpp. What is NOT reachable that way is the
 *     thing this PR actually changes -- that the migrated argv reaches a real
 *     binary, and that the collector wires enrichment and receipts into
 *     emitted rows. A fixture string re-asserts the parser and proves nothing
 *     about the migration; external functional review specifically found that
 *     the parser-only tests survive reverting every changed call site.
 *   - Bound: these two cases are the ONLY process-spawning tests added here,
 *     and both are macOS/POSIX-gated. Everything else added by this PR is a
 *     pure-function case. If the cost ever becomes a problem, the right move
 *     is an integration tag, not weaker assertions.
 */
#include <catch2/catch_test_macros.hpp>

#ifndef _WIN32

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"
#include "test_helpers.hpp" // yuzu::test::unique_temp_path -- cache-invalidation marker filename

#include <cstdlib>
#include <filesystem>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

#if defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

// Mirrors test_users_posix_actions.cpp's find_users_plugin(), pointed at the
// installed_apps plugin's own build output.
fs::path find_installed_apps_plugin() {
    const std::string lib_name = std::string{"installed_apps"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "installed_apps" /
                                lib_name);
    }
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "installed_apps" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "installed_apps" / lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" / "installed_apps" /
                            lib_name);
    candidates.emplace_back(fs::path{"build-linux"} / "agents" / "plugins" / "installed_apps" /
                            lib_name);

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

std::optional<LoadedPlugin> load_installed_apps_plugin() {
    auto plugin_path = find_installed_apps_plugin();
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

// Every line of `list`'s output is either a real `app|name|version|publisher|
// install_date|install_location|bundle_id` row or the plugin's own honest-empty
// sentinel ("app|No applications found|-|-|-|-|-") -- both share the `app|`
// prefix, so a single prefix check covers both shapes.
std::size_t count_non_matching_lines(const std::string& captured, std::string_view prefix) {
    std::istringstream iss(captured);
    std::string line;
    std::size_t bad = 0;
    while (std::getline(iss, line)) {
        if (line.empty())
            continue;
        if (line.compare(0, prefix.size(), prefix) != 0)
            ++bad;
    }
    return bad;
}

/// Escape-aware field split (shape of test_peripherals_local_dispatcher.cpp's
/// helper): a backslash-escaped '|' does not start a new field.
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

TEST_CASE("installed_apps plugin: list executes real dpkg-query/rpm/pacman/system_profiler argv",
          "[installed_apps][posix_actions]") {
    auto plugin = load_installed_apps_plugin();
    if (!plugin) {
        // SKIP, not WARN-and-return: a bare `return` retires the case with ZERO
        // assertions and Catch2 reports it as PASSED, so a plugin that stopped
        // loading would read as a green test. SKIP reports it as skipped
        // instead. (Named false-green policy floor; tests/meson.build's
        // link_depends means the artifact is built whenever this runs.)
        SKIP("installed_apps plugin library not found -- cannot drive LocalDispatcher");
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "list");

    // rc==0 is the real signal here: a wrong/reverted argv (a stale
    // popen()/command_exists() call, a wrong tool path, or a malformed
    // format string the real tool rejects) would surface as a non-zero rc
    // or garbage output -- this call proves the migrated argv actually
    // reached a real tool on this host, not just that it compiles.
    CHECK(result.rc == 0);
    CHECK_FALSE(result.captured.empty());

    // Shape invariant: every emitted line is an `app|...` row, whether a
    // real app/package or the plugin's own "No applications found" sentinel
    // -- never a stray error string or fragment from a reverted parser.
    CHECK(count_non_matching_lines(result.captured, "app|") == 0);

    // Wire contract (ADR-0028 binding condition): every row is
    // app|name|version|publisher|install_date|install_location|bundle_id --
    // exactly 7 escape-aware tokens on every host, the sentinel included, because
    // format_app_row escapes every field; a `|` in a real name is escaped, not a
    // delimiter.
    std::istringstream iss(result.captured);
    std::string line;
    std::size_t rows = 0, bad_field_count = 0, empty_field = 0;
    [[maybe_unused]] std::size_t abs_location_rows = 0, system_app_rows = 0, bundle_rows = 0,
                                 non_dash_trailing = 0;
    while (std::getline(iss, line)) {
        if (line.empty())
            continue;
        ++rows;
        const auto fields = split_fields_escape_aware(line);
        if (fields.size() != 7) {
            ++bad_field_count;
            continue;
        }
        // Empty optional columns render "-", never an empty string (a
        // shifted column would surface here as an empty field).
        for (std::size_t i = 1; i < fields.size(); ++i)
            if (fields[i].empty())
                ++empty_field;
#if defined(__APPLE__)
        if (!fields[5].empty() && fields[5].front() == '/')
            ++abs_location_rows;
        if (fields[5].starts_with("/System/Applications/") && fields[6].starts_with("com.apple."))
            ++system_app_rows;
        if (fields[6] != "-")
            ++bundle_rows;
#elif defined(__linux__)
        if (fields[5] != "-" || fields[6] != "-")
            ++non_dash_trailing;
#endif
    }
    CHECK(rows > 0);
    CHECK(bad_field_count == 0);
    CHECK(empty_field == 0);

    // The shape checks above are satisfied by "-" in both trailing columns, so on
    // their own they survive reverting either half of the feature: (A) dropping
    // with_bundle_ids leaves every bundle_id "-"; (B) returning {} for the location
    // leaves every install_location "-". These value-level checks fail both.
    // Every Mac lists /System/Applications/*.app with a com.apple.* bundle id.
#if defined(__APPLE__)
    CHECK(abs_location_rows > 0);
#ifdef YUZU_HAVE_SECURITY_FRAMEWORK
    CHECK(system_app_rows > 0);
#else
    CHECK(bundle_rows == 0); // no Security framework: the stub yields "-" for every row
#endif
#elif defined(__linux__)
    // Linux has no install location or bundle id concept: both columns are "-" by design.
    CHECK(non_dash_trailing == 0);
#endif
}

#if defined(__APPLE__)

// Round-3 sync-speed fix coverage: the profiler memo cache
// (installed_apps_plugin.cpp's ProfilerCache/get_inventory_macos, anonymous-
// namespace so not directly includable) and the receipt-read/pkgutil-fallback
// parity it sits in front of. `installed_apps_parsers.hpp` and
// `installed_apps_macos_receipts.hpp` are both public, OS-scoped headers this
// plugin's own .cpp includes -- reused verbatim here, not re-implemented, so
// a parity test is never checking its own re-derivation of the contract.
#include "installed_apps_macos_receipts.hpp"
#include "installed_apps_parsers.hpp"

#include <yuzu/agent/subprocess_runner.hpp>

#include <chrono>
#include <cstdio>
#include <fstream>

namespace parsers = yuzu::installed_apps::parsers;
namespace macos_receipts = yuzu::installed_apps::macos_receipts;

// Gate-1 remediation (external functional review): NOTHING dispatched
// `list_inventory`, so the whole point of this PR on macOS -- the #2273
// enrichment fields and the new pkgutil receipt rows -- could regress with
// every other assertion still green. The pure parsers prove they can PARSE
// their inputs; only a dispatch proves the collector actually WIRES them into
// emitted rows.
//
// Assertions are on the row CONTRACT (field count, allowed enum values,
// cross-field consistency), never on host-specific names or counts -- except
// the two macOS invariants that hold on any Mac: /System/Applications is
// populated with Apple-signed apps, and pkgutil always holds receipts.
TEST_CASE("installed_apps plugin: list_inventory emits enriched macOS app rows and pkgutil receipts",
          "[installed_apps][posix_actions][macos_inventory]") {
    auto plugin = load_installed_apps_plugin();
    if (!plugin)
        SKIP("installed_apps plugin library not found -- cannot drive LocalDispatcher");

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "list_inventory");

    // Two legal outcomes, and the test asserts the CONTRACT of whichever
    // occurred rather than assuming a healthy host. Adversarial review
    // reproduced `system_profiler` exiting 0 having written nothing, which made
    // an unconditional "there are apps" assertion flaky in exactly the way a
    // shared CI runner would hit. That degraded case is now a first-class
    // outcome (rc=1, publish nothing), so assert THAT here instead of skipping:
    // a partial inventory must never be emitted alongside a degraded result.
    if (result.rc != 0) {
        CHECK(result.rc == 1);
        // The whole point of the degraded path: nothing is published, so the
        // daily sync skips the cycle rather than committing a partial set.
        CHECK(result.captured.empty());
        // SKIP, not return. This is the ONLY test of the enrichment + receipt
        // integration, so a degraded run leaves that integration UNVERIFIED --
        // and a `return` here would report the case as PASSED, which is the
        // vacuous green this suite's policy floor forbids (phase-2 review).
        // Reporting skipped keeps the degraded-contract assertions above while
        // telling the truth about what was not covered.
        SKIP("system_profiler degraded on this host -- degraded contract verified, but the "
             "enrichment/receipt integration was NOT exercised");
    }

    REQUIRE_FALSE(result.captured.empty());

    std::size_t app_rows = 0, pkg_rows = 0;
    std::size_t signed_apps = 0, unsigned_apps = 0, apps_with_publisher = 0;
    std::size_t bad_prefix = 0, bad_field_count = 0, bad_sig_value = 0;
    std::size_t pkg_bad_ecosystem = 0, pkg_non_numeric_date = 0;
    std::size_t publisher_without_signature = 0;

    std::istringstream iss(result.captured);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.empty())
            continue;
        if (line.rfind("inv|", 0) != 0) {
            ++bad_prefix;
            continue;
        }
        // ADR-0016 blob v2: "inv" + exactly 12 fields. Splitting manually
        // (not on a parser helper) keeps this a genuine wire-shape check.
        std::vector<std::string> f;
        std::size_t start = 0;
        while (true) {
            const auto bar = line.find('|', start);
            if (bar == std::string::npos) {
                f.push_back(line.substr(start));
                break;
            }
            f.push_back(line.substr(start, bar - start));
            start = bar + 1;
        }
        if (f.size() != 13) { // "inv" + 12 fields
            ++bad_field_count;
            continue;
        }
        const std::string& kind = f[5];
        const std::string& ecosystem = f[6];
        const std::string& publisher = f[3];
        const std::string& install_date = f[4];
        const std::string& signature = f[10];

        if (signature != "" && signature != "signed" && signature != "unsigned")
            ++bad_sig_value;

        if (kind == "app") {
            ++app_rows;
            if (signature == "signed")
                ++signed_apps;
            else if (signature == "unsigned")
                ++unsigned_apps;
            if (!publisher.empty()) {
                ++apps_with_publisher;
                // A publisher is read off the signing leaf certificate, so it
                // can never be present on a row we called unsigned.
                if (signature != "signed")
                    ++publisher_without_signature;
            }
        } else if (kind == "pkg") {
            ++pkg_rows;
            if (ecosystem != "macos_pkgutil")
                ++pkg_bad_ecosystem;
            // pkgutil receipts carry raw epoch seconds, never a formatted date.
            if (!install_date.empty() &&
                install_date.find_first_not_of("0123456789") != std::string::npos)
                ++pkg_non_numeric_date;
        }
    }

    CHECK(bad_prefix == 0);
    CHECK(bad_field_count == 0);
    CHECK(bad_sig_value == 0);
    CHECK(publisher_without_signature == 0);

    // The #2273 enrichment actually ran and populated the previously
    // always-empty fields.
    CHECK(app_rows > 0);
    CHECK(signed_apps > 0);          // /System/Applications is Apple-signed
    CHECK(apps_with_publisher > 0);  // leaf-certificate CN extraction works

    // The new pkgutil receipt leg actually emitted rows.
    CHECK(pkg_rows > 0);
    CHECK(pkg_bad_ecosystem == 0);
    CHECK(pkg_non_numeric_date == 0);

    // Every classified app row is either signed or unsigned, and rows whose
    // bundle had no Location: line carry neither -- so the classified count can
    // never exceed the app-row count. A regression that double-counted or
    // mis-bucketed would break this.
    CHECK(signed_apps + unsigned_apps <= app_rows);

    // NOTE: no cap assertion here, deliberately. An earlier revision asserted
    // `<= 500` against constants that later became 5000 -- it could not observe
    // the cap it claimed to verify (false green) and would have failed any Mac
    // with more than 500 app bundles (false red). The guards are no longer
    // observable from this seam at all: exceeding either one now DEGRADES the
    // collection, so the run returns rc=1 and never reaches this branch. The
    // degraded contract is asserted in the rc!=0 branch above; asserting a
    // bound here would be asserting something unreachable by construction.
}

// Round-3 sync-speed fix: the profiler memo cache (ProfilerCache/
// apps_root_signature/get_inventory_macos, installed_apps_plugin.cpp) lives
// in that .cpp's anonymous namespace, so it is not directly includable from a
// test. The least invasive way to observe its behaviour from outside is
// exactly what it exists to do: dispatch `list_inventory` twice in one
// process and show the second call is a fast, byte-identical repeat of the
// first -- never touching the cache's internals.
//
// TEST-EFFICIENCY JUSTIFICATION: this necessarily spawns real
// system_profiler/pkgutil argv (same cost class as the sibling dispatch test
// above -- "a few seconds" on this host per that test's own header comment).
// It is the ONLY way to observe the cache's hit/miss behaviour at all: the
// cache sits between the collector and the wire format, with no seam a pure
// unit test could reach.
TEST_CASE("installed_apps plugin: list_inventory memo cache serves an identical, faster repeat",
          "[installed_apps][posix_actions][macos_inventory][cache]") {
    auto plugin = load_installed_apps_plugin();
    if (!plugin)
        SKIP("installed_apps plugin library not found -- cannot drive LocalDispatcher");

    yuzu::agent::LocalDispatcher dispatcher;

    const auto t0 = std::chrono::steady_clock::now();
    auto first = dispatcher.run(plugin->descriptor, "list_inventory");
    const auto t1 = std::chrono::steady_clock::now();

    if (first.rc != 0) {
        // Same degraded contract as the sibling test above: get_inventory_macos
        // NEVER memoizes a degraded outcome (installed_apps_plugin.cpp resets
        // cache.result rather than storing it), so there is nothing cached to
        // prove a hit against on this run.
        CHECK(first.captured.empty());
        SKIP("system_profiler/pkgutil degraded on this host -- the memo cache was "
             "never populated, so its hit behaviour is NOT exercised here");
    }
    REQUIRE_FALSE(first.captured.empty());

    const auto first_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    const auto t2 = std::chrono::steady_clock::now();
    auto second = dispatcher.run(plugin->descriptor, "list_inventory");
    const auto t3 = std::chrono::steady_clock::now();
    const auto second_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t3 - t2).count();

    INFO("first=" << first_ms << "ms second=" << second_ms << "ms");

    // The cached result must be the EXACT same bytes, not merely fast -- this
    // is what catches a cache bug that serves stale/wrong/truncated data.
    CHECK(second.rc == first.rc);
    CHECK(second.captured == first.captured);

    // Absolute ceiling: a real cache hit is a mutex lock + a struct copy, not
    // a fresh system_profiler+pkgutil collection. The sibling dispatch test's
    // own header comment puts an UNCACHED list_inventory at "a few seconds"
    // on this host -- 2s is generous headroom above a genuine cache hit while
    // staying far below any plausible uncached run, even under CI load.
    CHECK(second_ms < 2000);

    // Relative check, guarded: only meaningful when the first call was itself
    // slow enough that a ratio isn't noise -- an unusually quiet host could
    // make the FIRST call fast too, which would make ANY ratio flaky; the
    // absolute ceiling above is the real proof in that case.
    if (first_ms >= 500) {
        CHECK(second_ms * 3 <= first_ms);
    }

    SECTION("touching a per-user Applications root invalidates the cache") {
        // apps_root_signature() lstat()s every local user's own
        // ~/Applications (installed_apps_plugin.cpp). Creating then removing
        // one throwaway file inside an EXISTING such directory changes its
        // mtime -- and so the signature -- without changing anything the
        // collection itself reports (the file is not a .app bundle and
        // pkgutil never looks at it), so this is safe to run on a shared dev
        // host and leaves it exactly as found.
        const char* home = std::getenv("HOME");
        std::error_code ec;
        const auto apps_dir = home ? (fs::path(home) / "Applications") : fs::path{};
        if (apps_dir.empty() || !fs::is_directory(apps_dir, ec)) {
            SKIP("no ~/Applications directory on this host -- cache-invalidation "
                 "signature path cannot be exercised without creating a new root "
                 "the signature scan doesn't already cover");
        }

        // yuzu_test_ prefix (Defender-exclusion convention) + the shared
        // process-salted unique-name generator -- never a thread-id hash or a
        // clock read (#473/#482) -- even though this filename never leaves
        // this host.
        const auto marker =
            apps_dir / yuzu::test::unique_temp_path("yuzu_test_cache_invalidate_").filename();
        {
            std::ofstream touch(marker);
            REQUIRE(touch.is_open());
        }
        struct Cleanup {
            fs::path p;
            ~Cleanup() {
                std::error_code rm_ec;
                fs::remove(p, rm_ec);
            }
        } cleanup{marker};

        const auto t4 = std::chrono::steady_clock::now();
        auto third = dispatcher.run(plugin->descriptor, "list_inventory");
        const auto t5 = std::chrono::steady_clock::now();
        const auto third_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t5 - t4).count();

        if (third.rc != 0)
            SKIP("system_profiler/pkgutil degraded on the invalidated re-collection -- "
                 "invalidation itself cannot be distinguished from a transient tool "
                 "hiccup here");

        INFO("second=" << second_ms << "ms third=" << third_ms << "ms");
        // Mirror image of the cache-hit check above: a signature match would
        // return in the same fast window `second` did; a genuine invalidation
        // re-runs the full collection, which is not fast by the same margin.
        CHECK(third_ms > second_ms * 2);
    }
}

// Receipt-read / pkgutil-fallback parity (round-3 sync-speed fix, item 4).
// installed_apps_plugin.cpp's get_inventory_macos_uncached tries
// macos_receipts::read_receipt_plist(id) FIRST and falls back to spawning
// `pkgutil --pkg-info <id>` (parsed by parsers::parse_pkgutil_pkg_info) only
// on a miss -- so proving the two AGREE on a real package, independently,
// proves the fallback is a pure speed optimisation and never a second source
// of truth, without needing to force the plugin down one path artificially.
//
// TEST-EFFICIENCY JUSTIFICATION: one bounded pkgutil spawn (the same shape
// the plugin's own fallback call makes) plus a handful of small file reads --
// no different in cost class from the parser/receipts unit tests already in
// this suite.
TEST_CASE("installed_apps plugin: receipt-plist read and pkgutil --pkg-info fallback agree",
          "[installed_apps][macos][receipts][parity]") {
    // Command Line Tools' Executables package is present on essentially every
    // macOS host that can build this repo, but never assumed -- checked here,
    // SKIPped loudly (never silently reported as a pass) if absent, matching
    // this suite's false-green policy floor.
    static constexpr const char* kPkgId = "com.apple.pkg.CLTools_Executables";

    const auto pkgutil_path = yuzu::agent::probe_tool_path({"/usr/sbin/pkgutil"});
    if (pkgutil_path.empty())
        SKIP("pkgutil not found at /usr/sbin/pkgutil on this host");

    const auto probe = yuzu::agent::run_bounded_subprocess(
        {pkgutil_path, "--pkg-info", kPkgId},
        yuzu::agent::SubprocessOptions{.deadline = std::chrono::seconds{20}});
    if (probe.termination_reason != yuzu::agent::TerminationReason::exited ||
        probe.exit_code != 0) {
        SKIP(std::string(kPkgId) +
             " is not installed on this host (pkgutil --pkg-info exited " +
             std::to_string(probe.exit_code) +
             ") -- receipt/pkgutil parity cannot be exercised here");
    }

    // The SAME parser the plugin's own fallback branch calls -- this
    // comparison is against exactly what the fallback path produces, not a
    // re-implementation of it.
    const auto via_pkgutil = parsers::parse_pkgutil_pkg_info(probe.output);
    REQUIRE_FALSE(via_pkgutil.version.empty());
    REQUIRE_FALSE(via_pkgutil.install_time.empty());

    const auto via_receipt = macos_receipts::read_receipt_plist(kPkgId);
    if (!via_receipt) {
        SKIP(std::string(kPkgId) +
             "'s receipt plist was not readable on this host (missing/permissions) -- "
             "the in-process read path can't be compared here; the plugin would itself "
             "fall back to pkgutil in this exact case");
    }

    CHECK(via_receipt->version == via_pkgutil.version);
    CHECK(via_receipt->install_time == via_pkgutil.install_time);
}

#endif // __APPLE__

#endif // !_WIN32
