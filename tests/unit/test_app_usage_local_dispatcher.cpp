/**
 * test_app_usage_local_dispatcher.cpp — loads the ACTUAL built app_usage
 * plugin (app_usage.dylib/.so/.dll) via PluginHandle::load and drives it
 * through yuzu::agent::LocalDispatcher (test_power_health_local_dispatcher
 * .cpp's pattern).
 *
 * Two shapes:
 *   - The UNGUARDED case: init() is never called, exactly the seam this
 *     package's spec calls out (CommandContext has no get_config; only
 *     PluginContext, init()'s argument, does). Proves execute() alone
 *     still resolves a sane tar.db path on a host with no live tar.db.
 *   - The StandalonePluginContext-seeded case (adjudication P6): builds a
 *     REAL tar.db (via app_usage_test_seed.hpp, the one justified
 *     `yuzu_test_`-prefixed temp file — the plugin opens tar.db by path,
 *     so there is no way to exercise the production acquisition path
 *     without a real file on disk), points `agent.data_dir` at it through
 *     StandalonePluginContext, runs the loaded plugin's real init(), and
 *     REQUIREs actual `usage|`/`last_used|` rows — never accepts a
 *     `constrained` token here, because this path knows its db exists.
 *
 * RUNS ON ALL THREE PLATFORMS unconditionally, per
 * test_filesystem_posture_local_dispatcher.cpp's precedent for why a
 * platform-guarded dispatcher TU hides a dead leg.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "app_usage_parsers.hpp"
#include "app_usage_test_seed.hpp"
#include "local_dispatcher.hpp"
#include "test_helpers.hpp"

#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <sqlite3.h>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
namespace seed = yuzu::test::app_usage;

namespace {

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

std::vector<std::string> split_fields(const std::string& row) {
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

void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) {
        FAIL("app_usage plugin library not found under meson test — the plugin did not build, "
             "or link_depends is not forcing it to build before this test runs");
    }
    WARN("app_usage plugin library not found -- skipping LocalDispatcher round-trip test (run "
         "from the build root, or via `meson test`, to exercise it)");
}

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
constexpr const char* kPlatformDefaultDbDir = "C:\\ProgramData\\yuzu\\agent";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
constexpr const char* kPlatformDefaultDbDir = "/var/lib/yuzu/agent";
#else
constexpr const char* kPluginExt = ".so";
constexpr const char* kPlatformDefaultDbDir = "/var/lib/yuzu/agent";
#endif

fs::path find_app_usage_plugin() {
    const std::string lib_name = std::string{"app_usage"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "app_usage" /
                                lib_name);
    }
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "app_usage" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "app_usage" / lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" / "app_usage" /
                            lib_name);
    candidates.emplace_back(fs::path{"build-windows"} / "agents" / "plugins" / "app_usage" /
                            lib_name);
    candidates.emplace_back(fs::path{"build-linux"} / "agents" / "plugins" / "app_usage" /
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

std::optional<LoadedPlugin> load_app_usage_plugin() {
    auto plugin_path = find_app_usage_plugin();
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

} // namespace

TEST_CASE("app_usage plugin: ABI4 descriptors declare all three OS legs for every action, "
         "never #ifdef'd out (plugin.h:115-136)",
          "[app_usage][descriptors]") {
    auto plugin = load_app_usage_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    REQUIRE(plugin->descriptor->action_descriptor_count == 3);
    REQUIRE(plugin->descriptor->action_descriptors != nullptr);

    for (std::size_t i = 0; i < plugin->descriptor->action_descriptor_count; ++i) {
        const auto& d = plugin->descriptor->action_descriptors[i];
        INFO("action: " << (d.action ? d.action : "<null>"));
        CHECK(d.linux_leg.support != YUZU_SUPPORT_UNDECLARED);
        CHECK(d.macos_leg.support != YUZU_SUPPORT_UNDECLARED);
        CHECK(d.windows_leg.support != YUZU_SUPPORT_UNDECLARED);
    }
}

TEST_CASE("app_usage plugin: summary — real tar.db if present, else an explicit "
         "constrained|tar_db_unavailable|<path under the platform default dir>, never empty",
          "[app_usage][actions]") {
    auto plugin = load_app_usage_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    // UNGUARDED — no init() call, exactly this package's seam decision:
    // execute() must resolve a sane db path on its own.
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "summary");

    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty()); // never an empty success

    const auto first = split_fields(rows.front());
    if (first[0] == "constrained" && rows.size() >= 1 &&
        rows.front().rfind("constrained|tar_db_unavailable|", 0) == 0) {
        // "no db at path" distinguished from "no path": the resolved path
        // must be non-empty and end in tar.db under the platform default
        // dir -- proving execute() actually resolved a real path rather
        // than looking nowhere.
        CHECK(result.rc == 1);
        const auto fields = split_fields(rows.front());
        REQUIRE(fields.size() >= 3);
        const std::string& resolved_path = fields[2];
        CHECK_FALSE(resolved_path.empty());
        CHECK(resolved_path.size() >= 6);
        CHECK(resolved_path.compare(resolved_path.size() - 6, 6, "tar.db") == 0);
        CHECK(resolved_path.find(kPlatformDefaultDbDir) == 0);
        return;
    }

    // A real tar.db was found on this host — meta + (zero or more) usage rows,
    // or an explicit constrained token if that host's tar.db predates
    // usage_daily or has usage_enabled=false (review M2 — legitimately rc 0).
    CHECK(result.rc == 0);
    if (rows.front().rfind("constrained|usage_source_disabled", 0) == 0 ||
        rows.front().rfind("constrained|usage_schema_missing", 0) == 0) {
        SUCCEED("openable tar.db without a usage source: constrained token accepted");
        return;
    }
    CHECK(rows.front().rfind("meta|", 0) == 0);
    for (std::size_t i = 1; i < rows.size(); ++i)
        CHECK(rows[i].rfind("usage|", 0) == 0);
}

TEST_CASE("app_usage plugin: foreground is always constrained, rc 0 -- a permanent "
         "by-design degraded outcome, never a hard failure",
          "[app_usage][actions]") {
    auto plugin = load_app_usage_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "foreground");

    // rc must be 0: agent.cpp derives the wire CommandResponse status purely
    // from rc (0=SUCCESS, nonzero=FAILURE), independent of this typed status
    // — a nonzero rc here would record this documented "always constrained"
    // outcome as a hard failure in the executions history.
    CHECK(result.rc == 0);
    CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);

    const auto rows = captured_rows(result.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows.front().rfind("constrained|foreground_not_captured|", 0) == 0);
}

// ───────────────────── P6: StandalonePluginContext-seeded production path ──

TEST_CASE("app_usage plugin: StandalonePluginContext-seeded real tar.db — init() resolves "
         "agent.data_dir and execute() returns REAL summary/last_used rows, never "
         "'constrained' (P6, proves the production acquisition path)",
          "[app_usage][actions][p6]") {
    auto plugin = load_app_usage_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    REQUIRE(plugin->descriptor->init != nullptr);
    REQUIRE(plugin->descriptor->shutdown != nullptr);

    // The one justified temp file (this package's spec, "boundaries"): the
    // plugin opens tar.db by path, so there is no way to exercise the
    // production acquisition path without a real file on disk. `yuzu_test_`
    // prefix is the Defender-exclusion rule; yuzu::test::TempDir removes the
    // directory recursively in its destructor (test_helpers.hpp).
    yuzu::test::TempDir dir_guard{"yuzu_test_app_usage_"};
    std::error_code ec;
    fs::create_directories(dir_guard.path, ec);
    REQUIRE_FALSE(ec);
    const fs::path& data_dir = dir_guard.path;

    // day_ts must fall inside the plugin's default 30-day trailing window
    // (run_summary filters on it; run_last_used's all-exe query does not,
    // but the row must still be "today" to look like real data) — align to
    // the start of the current UTC day, matching the plugin's own
    // align_to_day (app_usage_plugin.cpp).
    constexpr int64_t kSecondsPerDay = 86400;
    const auto now = static_cast<int64_t>(std::time(nullptr));
    const int64_t today_ts = now - (now % kSecondsPerDay);

    sqlite3* writer = nullptr;
    REQUIRE(sqlite3_open((data_dir / "tar.db").string().c_str(), &writer) == SQLITE_OK);
    seed::exec_or_fail(writer, "PRAGMA journal_mode=WAL");
    seed::create_schema(writer);
    seed::insert_usage_daily(writer, today_ts, "p6_seeded.exe", /*run_count=*/1,
                             /*total_seconds=*/60, /*first_seen=*/now, /*last_seen=*/now,
                             /*superseded_runs=*/0, /*expired_runs=*/0);
    seed::insert_tar_config(writer, "usage_enabled", "true");
    seed::insert_tar_config(writer, "usage_feeder_enabled", "true");
    sqlite3_close(writer);

    yuzu::agent::StandalonePluginContext ctx("app_usage", {{"agent.data_dir", data_dir.string()}});
    REQUIRE(plugin->descriptor->init(ctx.get()) == 0);

    yuzu::agent::LocalDispatcher dispatcher;
    const auto summary = dispatcher.run(plugin->descriptor, "summary");
    CHECK(summary.rc == 0);
    const auto summary_rows = captured_rows(summary.captured);
    REQUIRE_FALSE(summary_rows.empty());
    REQUIRE(summary_rows.front().rfind("meta|", 0) == 0);
    bool saw_seeded_row = false;
    for (const auto& row : summary_rows) {
        if (row.rfind("usage|p6_seeded.exe|", 0) == 0)
            saw_seeded_row = true;
    }
    CHECK(saw_seeded_row);

    const auto last_used = dispatcher.run(plugin->descriptor, "last_used");
    CHECK(last_used.rc == 0);
    const auto last_used_rows = captured_rows(last_used.captured);
    bool saw_seeded_last_used = false;
    for (const auto& row : last_used_rows) {
        if (row.rfind("last_used|p6_seeded.exe|", 0) == 0)
            saw_seeded_last_used = true;
    }
    CHECK(saw_seeded_last_used);

    plugin->descriptor->shutdown(ctx.get());
}

// ── regression: tar_config PREPARE failure must map to Errored, never ──────
// silently to Enabled (governance Gate 7 finding — b88c3b690's fix had zero
// regression coverage; every existing test only exercised the "value
// present but malformed" and "key absent" cases, never a genuine SQL
// prepare failure).

TEST_CASE("app_usage plugin: a tar_config PREPARE failure (table missing) maps to "
         "usage_source_errored, never silently to Enabled -- regression for b88c3b690",
          "[app_usage][actions][regression]") {
    auto plugin = load_app_usage_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    REQUIRE(plugin->descriptor->init != nullptr);
    REQUIRE(plugin->descriptor->shutdown != nullptr);

    yuzu::test::TempDir dir_guard{"yuzu_test_app_usage_tarcfg_fail_"};
    std::error_code ec;
    fs::create_directories(dir_guard.path, ec);
    REQUIRE_FALSE(ec);
    const fs::path& data_dir = dir_guard.path;

    constexpr int64_t kSecondsPerDay = 86400;
    const auto now = static_cast<int64_t>(std::time(nullptr));
    const int64_t today_ts = now - (now % kSecondsPerDay);

    sqlite3* writer = nullptr;
    REQUIRE(sqlite3_open((data_dir / "tar.db").string().c_str(), &writer) == SQLITE_OK);
    seed::exec_or_fail(writer, "PRAGMA journal_mode=WAL");
    // usage_daily exists (so the schema-missing branch is not what fires),
    // but tar_config is deliberately NEVER created -- get_tar_config's
    // sqlite3_prepare_v2 genuinely FAILS (SQLITE_ERROR, "no such table"),
    // distinct from a well-formed query returning zero rows for an absent
    // key. check_usage_source_state must map this to SourceState::Errored,
    // not fall through to source_state_from_config's nullopt->Enabled path.
    seed::exec_or_fail(writer,
                       "CREATE TABLE usage_daily (day_ts INTEGER, exe_key TEXT, "
                       "run_count INTEGER, total_seconds INTEGER, first_seen INTEGER, "
                       "last_seen INTEGER, superseded_runs INTEGER, expired_runs INTEGER)");
    seed::insert_usage_daily(writer, today_ts, "regression.exe", /*run_count=*/1,
                             /*total_seconds=*/60, /*first_seen=*/now, /*last_seen=*/now,
                             /*superseded_runs=*/0, /*expired_runs=*/0);
    sqlite3_close(writer);

    yuzu::agent::StandalonePluginContext ctx("app_usage", {{"agent.data_dir", data_dir.string()}});
    REQUIRE(plugin->descriptor->init(ctx.get()) == 0);

    yuzu::agent::LocalDispatcher dispatcher;
    const auto summary = dispatcher.run(plugin->descriptor, "summary");
    // check_usage_source_state's Errored branch reports CONSTRAINED, rc 0 --
    // never a silent Enabled that falls through to run_summary/read_meta as
    // if the tar_config read had simply found nothing.
    CHECK(summary.rc == 0);
    const auto summary_rows = captured_rows(summary.captured);
    REQUIRE(summary_rows.size() == 1);
    CHECK(summary_rows.front().rfind("constrained|usage_source_errored|", 0) == 0);

    const auto last_used = dispatcher.run(plugin->descriptor, "last_used");
    CHECK(last_used.rc == 0);
    const auto last_used_rows = captured_rows(last_used.captured);
    REQUIRE(last_used_rows.size() == 1);
    CHECK(last_used_rows.front().rfind("constrained|usage_source_errored|", 0) == 0);

    plugin->descriptor->shutdown(ctx.get());
}

// ── regression: exe="" behaves as OMITTED, never as a literal-key filter ───
// (governance Gate 7 round 2, consistency-auditor F1). Before this fix, an
// empty exe value normalised to the "(unknown)" sentinel and filtered on
// THAT literal key -- silently returning near-zero rows instead of "every
// executable", contradicting content/definitions/app_usage.yaml's own
// "omit to return every executable" framing.

TEST_CASE("app_usage plugin: last_used with exe=\"\" returns every executable, matching "
         "omitted-exe semantics -- regression for the (unknown)-sentinel trap",
          "[app_usage][actions][regression]") {
    auto plugin = load_app_usage_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    REQUIRE(plugin->descriptor->init != nullptr);
    REQUIRE(plugin->descriptor->shutdown != nullptr);

    yuzu::test::TempDir dir_guard{"yuzu_test_app_usage_exe_blank_"};
    std::error_code ec;
    fs::create_directories(dir_guard.path, ec);
    REQUIRE_FALSE(ec);
    const fs::path& data_dir = dir_guard.path;

    constexpr int64_t kSecondsPerDay = 86400;
    const auto now = static_cast<int64_t>(std::time(nullptr));
    const int64_t today_ts = now - (now % kSecondsPerDay);

    sqlite3* writer = nullptr;
    REQUIRE(sqlite3_open((data_dir / "tar.db").string().c_str(), &writer) == SQLITE_OK);
    seed::exec_or_fail(writer, "PRAGMA journal_mode=WAL");
    seed::create_schema(writer);
    // Two distinct executables -- an unfiltered "last_used" must return
    // both; a filter on the "(unknown)" sentinel would return neither.
    seed::insert_usage_daily(writer, today_ts, "blank_a.exe", 1, 60, now, now, 0, 0);
    seed::insert_usage_daily(writer, today_ts, "blank_b.exe", 1, 60, now, now, 0, 0);
    seed::insert_tar_config(writer, "usage_enabled", "true");
    // Round-3 review should-fix: a missing usage_feeder_enabled key now
    // gates last_used (see the dedicated missing-key regression test) --
    // every OTHER real-data fixture in this file must seed it explicitly,
    // matching what a genuinely reachable host always has by the time
    // usage_daily holds any row (TAR's fold writes this key first).
    seed::insert_tar_config(writer, "usage_feeder_enabled", "true");
    sqlite3_close(writer);

    yuzu::agent::StandalonePluginContext ctx("app_usage", {{"agent.data_dir", data_dir.string()}});
    REQUIRE(plugin->descriptor->init(ctx.get()) == 0);

    yuzu::agent::LocalDispatcher dispatcher;
    const YuzuParam params[] = {{"exe", ""}};
    const auto last_used = dispatcher.run(plugin->descriptor, "last_used", params);
    CHECK(last_used.rc == 0);
    const auto rows = captured_rows(last_used.captured);
    bool saw_a = false, saw_b = false;
    for (const auto& row : rows) {
        if (row.rfind("last_used|blank_a.exe|", 0) == 0)
            saw_a = true;
        if (row.rfind("last_used|blank_b.exe|", 0) == 0)
            saw_b = true;
    }
    CHECK(saw_a);
    CHECK(saw_b);

    plugin->descriptor->shutdown(ctx.get());
}

// ── round-3 review blocker: last_used must refuse a feeder-dead source ─────

TEST_CASE("app_usage plugin: last_used with usage_feeder_enabled=false reports "
         "constrained|usage_feeder_disabled, never a real (stale) row -- round-3 review "
         "blocker regression",
          "[app_usage][actions][regression]") {
    auto plugin = load_app_usage_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    REQUIRE(plugin->descriptor->init != nullptr);
    REQUIRE(plugin->descriptor->shutdown != nullptr);

    yuzu::test::TempDir dir_guard{"yuzu_test_app_usage_feeder_disabled_"};
    std::error_code ec;
    fs::create_directories(dir_guard.path, ec);
    REQUIRE_FALSE(ec);
    const fs::path& data_dir = dir_guard.path;

    constexpr int64_t kSecondsPerDay = 86400;
    const auto now = static_cast<int64_t>(std::time(nullptr));
    const int64_t today_ts = now - (now % kSecondsPerDay);

    sqlite3* writer = nullptr;
    REQUIRE(sqlite3_open((data_dir / "tar.db").string().c_str(), &writer) == SQLITE_OK);
    seed::exec_or_fail(writer, "PRAGMA journal_mode=WAL");
    seed::create_schema(writer);
    // A real, otherwise-valid row -- if the feeder check did nothing, this
    // row would come back as a normal last_used| result.
    seed::insert_usage_daily(writer, today_ts, "frozen.exe", 1, 60, now, now, 0, 0);
    seed::insert_tar_config(writer, "usage_enabled", "true");
    seed::insert_tar_config(writer, "usage_feeder_enabled", "false");
    sqlite3_close(writer);

    yuzu::agent::StandalonePluginContext ctx("app_usage", {{"agent.data_dir", data_dir.string()}});
    REQUIRE(plugin->descriptor->init(ctx.get()) == 0);

    yuzu::agent::LocalDispatcher dispatcher;
    const auto last_used = dispatcher.run(plugin->descriptor, "last_used");
    CHECK(last_used.rc == 0);
    const auto rows = captured_rows(last_used.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows.front() == "constrained|usage_feeder_disabled");

    // summary is NOT gated the same way -- it surfaces feeder_enabled via
    // its own meta| row instead of refusing to run.
    const auto summary = dispatcher.run(plugin->descriptor, "summary");
    CHECK(summary.rc == 0);
    const auto summary_rows = captured_rows(summary.captured);
    REQUIRE_FALSE(summary_rows.empty());
    CHECK(summary_rows.front().find("feeder_enabled|0") != std::string::npos);

    plugin->descriptor->shutdown(ctx.get());
}

TEST_CASE("app_usage plugin: last_used with a garbage usage_feeder_enabled value reports "
         "constrained|usage_feeder_errored, never silently Enabled",
          "[app_usage][actions][regression]") {
    auto plugin = load_app_usage_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    REQUIRE(plugin->descriptor->init != nullptr);
    REQUIRE(plugin->descriptor->shutdown != nullptr);

    yuzu::test::TempDir dir_guard{"yuzu_test_app_usage_feeder_errored_"};
    std::error_code ec;
    fs::create_directories(dir_guard.path, ec);
    REQUIRE_FALSE(ec);
    const fs::path& data_dir = dir_guard.path;

    sqlite3* writer = nullptr;
    REQUIRE(sqlite3_open((data_dir / "tar.db").string().c_str(), &writer) == SQLITE_OK);
    seed::exec_or_fail(writer, "PRAGMA journal_mode=WAL");
    seed::create_schema(writer);
    seed::insert_tar_config(writer, "usage_enabled", "true");
    seed::insert_tar_config(writer, "usage_feeder_enabled", "corrupted-value");
    sqlite3_close(writer);

    yuzu::agent::StandalonePluginContext ctx("app_usage", {{"agent.data_dir", data_dir.string()}});
    REQUIRE(plugin->descriptor->init(ctx.get()) == 0);

    yuzu::agent::LocalDispatcher dispatcher;
    const auto last_used = dispatcher.run(plugin->descriptor, "last_used");
    CHECK(last_used.rc == 0);
    const auto rows = captured_rows(last_used.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows.front().rfind("constrained|usage_feeder_errored|", 0) == 0);

    plugin->descriptor->shutdown(ctx.get());
}

// Round-3 review round-2 should-fix: usage_feeder_enabled has no TAR-default
// "safe missing" semantics the way usage_enabled does -- TAR's fold writes
// this key unconditionally before it ever writes a usage_daily row, so a
// genuinely ABSENT key (never written at all, not just "false") on a
// reachable host is itself an anomaly. Confirms the omitted-key case is
// treated the same as an explicit "false" (constrained), never silently
// Enabled the way usage_enabled's own missing-key case correctly is.
TEST_CASE("app_usage plugin: last_used with usage_feeder_enabled entirely OMITTED (never "
         "written, not just false) reports constrained|usage_feeder_disabled -- missing "
         "has no safe default for this key, unlike usage_enabled",
          "[app_usage][actions][regression]") {
    auto plugin = load_app_usage_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    REQUIRE(plugin->descriptor->init != nullptr);
    REQUIRE(plugin->descriptor->shutdown != nullptr);

    yuzu::test::TempDir dir_guard{"yuzu_test_app_usage_feeder_missing_"};
    std::error_code ec;
    fs::create_directories(dir_guard.path, ec);
    REQUIRE_FALSE(ec);
    const fs::path& data_dir = dir_guard.path;

    constexpr int64_t kSecondsPerDay = 86400;
    const auto now = static_cast<int64_t>(std::time(nullptr));
    const int64_t today_ts = now - (now % kSecondsPerDay);

    // Round-3 review Blocker (policy floor): RAII-owned, matching the
    // corruption-fixture idiom below in this same file -- take ownership
    // before the REQUIRE so a failed open still unwinds through a live
    // owner rather than leaking the handle.
    std::unique_ptr<sqlite3, decltype(&sqlite3_close)> writer{nullptr, &sqlite3_close};
    {
        sqlite3* raw = nullptr;
        const int rc = sqlite3_open((data_dir / "tar.db").string().c_str(), &raw);
        writer.reset(raw);
        REQUIRE(rc == SQLITE_OK);
    }
    seed::exec_or_fail(writer.get(), "PRAGMA journal_mode=WAL");
    seed::create_schema(writer.get());
    // A real row present, to prove this isn't just the "no data" path --
    // if the feeder-missing case were mishandled as Enabled, this row
    // would come back as a normal last_used| line instead of the
    // constrained marker.
    seed::insert_usage_daily(writer.get(), today_ts, "frozen_no_feeder_key.exe", 1, 60, now, now,
                             0, 0);
    seed::insert_tar_config(writer.get(), "usage_enabled", "true");
    // Deliberately no usage_feeder_enabled row at all.
    writer.reset();

    yuzu::agent::StandalonePluginContext ctx("app_usage", {{"agent.data_dir", data_dir.string()}});
    REQUIRE(plugin->descriptor->init(ctx.get()) == 0);

    yuzu::agent::LocalDispatcher dispatcher;
    const auto last_used = dispatcher.run(plugin->descriptor, "last_used");
    CHECK(last_used.rc == 0);
    const auto rows = captured_rows(last_used.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows.front() == "constrained|usage_feeder_disabled");

    plugin->descriptor->shutdown(ctx.get());
}

// ── round-3 review MEDIUM: last_used's unfiltered form must be bounded ─────

TEST_CASE("app_usage plugin: last_used (unfiltered) caps at kMaxLastUsedRows and reports "
         "a trailing last_used_truncated row -- round-3 review resource-exhaustion regression",
          "[app_usage][actions][regression]") {
    auto plugin = load_app_usage_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    REQUIRE(plugin->descriptor->init != nullptr);
    REQUIRE(plugin->descriptor->shutdown != nullptr);

    yuzu::test::TempDir dir_guard{"yuzu_test_app_usage_truncate_"};
    std::error_code ec;
    fs::create_directories(dir_guard.path, ec);
    REQUIRE_FALSE(ec);
    const fs::path& data_dir = dir_guard.path;

    constexpr int64_t kSecondsPerDay = 86400;
    const auto now = static_cast<int64_t>(std::time(nullptr));
    const int64_t today_ts = now - (now % kSecondsPerDay);

    sqlite3* writer = nullptr;
    REQUIRE(sqlite3_open((data_dir / "tar.db").string().c_str(), &writer) == SQLITE_OK);
    seed::exec_or_fail(writer, "PRAGMA journal_mode=WAL");
    seed::create_schema(writer);
    const auto over_cap =
        static_cast<int64_t>(yuzu::app_usage::kMaxLastUsedRows) + 5;
    // One transaction for all ~5000 rows -- insert_usage_daily autocommits
    // per call otherwise, which would fsync the WAL thousands of times and
    // make this the slowest test in the suite for no reason.
    seed::exec_or_fail(writer, "BEGIN");
    for (int64_t i = 0; i < over_cap; ++i) {
        seed::insert_usage_daily(writer, today_ts, "exe_" + std::to_string(i), 1, 60, now, now, 0,
                                 0);
    }
    seed::exec_or_fail(writer, "COMMIT");
    seed::insert_tar_config(writer, "usage_enabled", "true");
    seed::insert_tar_config(writer, "usage_feeder_enabled", "true");
    sqlite3_close(writer);

    yuzu::agent::StandalonePluginContext ctx("app_usage", {{"agent.data_dir", data_dir.string()}});
    REQUIRE(plugin->descriptor->init(ctx.get()) == 0);

    yuzu::agent::LocalDispatcher dispatcher;
    const auto last_used = dispatcher.run(plugin->descriptor, "last_used");
    CHECK(last_used.rc == 0);
    const auto rows = captured_rows(last_used.captured);
    // kMaxLastUsedRows real rows plus exactly one trailing truncation marker.
    REQUIRE(rows.size() == yuzu::app_usage::kMaxLastUsedRows + 1);
    std::size_t real_rows = 0;
    for (std::size_t i = 0; i < rows.size() - 1; ++i) {
        REQUIRE(rows[i].rfind("last_used|", 0) == 0);
        ++real_rows;
    }
    CHECK(real_rows == static_cast<std::size_t>(yuzu::app_usage::kMaxLastUsedRows));
    CHECK(rows.back() ==
         "constrained|last_used_truncated|" + std::to_string(yuzu::app_usage::kMaxLastUsedRows));

    plugin->descriptor->shutdown(ctx.get());
}

// ── round-3 review HIGH: a corrupt tar.db must never be silently served ────

TEST_CASE("app_usage plugin: a corrupt tar.db fails the open-time quick_check and reports "
         "constrained|tar_db_corrupt, rc 1, never a fabricated success",
          "[app_usage][actions][regression]") {
    auto plugin = load_app_usage_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    REQUIRE(plugin->descriptor->init != nullptr);
    REQUIRE(plugin->descriptor->shutdown != nullptr);

    yuzu::test::TempDir dir_guard{"yuzu_test_app_usage_corrupt_db_"};
    std::error_code ec;
    fs::create_directories(dir_guard.path, ec);
    REQUIRE_FALSE(ec);
    const fs::path& data_dir = dir_guard.path;

    // Same technique test_app_usage_parsers.cpp's usage_daily_table_exists
    // corruption test uses: sqlite3_open() succeeds lazily, so the failure
    // only surfaces on the first real access. NOTE: this specific "not a
    // valid sqlite file at all" byte sequence fails at sqlite3_prepare_v2
    // itself (SQLITE_NOTADB) -- it never reaches quick_check_ok's own
    // sqlite3_step/"ok"-text-comparison line, which is the ACTUAL new logic
    // this round's HIGH finding added (mutation-testing this in isolation
    // confirmed it: neutering the text=="ok" comparison does NOT redden this
    // test). It still correctly proves the outer open_readonly failure path
    // reports tar_db_corrupt/rc=1 for a garbage file, which is real
    // coverage -- just not of quick_check's comparison logic. See the
    // sibling test below for that.
    {
        std::ofstream f(data_dir / "tar.db", std::ios::binary | std::ios::trunc);
        f << "not a valid sqlite database file -- forces quick_check to fail closed";
    }

    yuzu::agent::StandalonePluginContext ctx("app_usage", {{"agent.data_dir", data_dir.string()}});
    REQUIRE(plugin->descriptor->init(ctx.get()) == 0);

    yuzu::agent::LocalDispatcher dispatcher;
    const auto last_used = dispatcher.run(plugin->descriptor, "last_used");
    CHECK(last_used.rc == 1);
    const auto rows = captured_rows(last_used.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows.front().rfind("constrained|tar_db_corrupt|", 0) == 0);

    plugin->descriptor->shutdown(ctx.get());
}

TEST_CASE("app_usage plugin: a WELL-FORMED tar.db with a corrupted data page fails "
         "quick_check's own \"ok\"-text comparison, never a fabricated success -- "
         "quality-engineer false-green finding, closes the gap the garbage-bytes "
         "test above cannot reach",
          "[app_usage][actions][regression]") {
    auto plugin = load_app_usage_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    REQUIRE(plugin->descriptor->init != nullptr);
    REQUIRE(plugin->descriptor->shutdown != nullptr);

    yuzu::test::TempDir dir_guard{"yuzu_test_app_usage_page_corrupt_"};
    std::error_code ec;
    fs::create_directories(dir_guard.path, ec);
    REQUIRE_FALSE(ec);
    const fs::path& data_dir = dir_guard.path;
    const fs::path db_path = data_dir / "tar.db";

    constexpr int64_t kSecondsPerDay = 86400;
    const auto now = static_cast<int64_t>(std::time(nullptr));
    const int64_t today_ts = now - (now % kSecondsPerDay);

    // Enough rows to push usage_daily past page 1 -- corrupting page 1 alone
    // (the schema/sqlite_master page) risks failing at open/prepare time
    // same as the garbage-bytes test above, rather than reaching
    // quick_check's per-page scan.
    //
    // Round-3 review Blocker (policy floor): RAII-owned, unlike this file's
    // other seed blocks' raw sqlite3*/sqlite3_close -- those are a
    // pre-existing convention this test merely sits beside (SHOULD, not a
    // floor, per governance's "pre-existing cleanup in a file this change
    // merely touches" carve-out), but this block is new code in this PR's
    // diff, which the floor does gate.
    int64_t page_size = 0;
    {
        std::unique_ptr<sqlite3, decltype(&sqlite3_close)> writer{nullptr, &sqlite3_close};
        {
            sqlite3* raw = nullptr;
            const int rc = sqlite3_open(db_path.string().c_str(), &raw);
            // Take ownership BEFORE the REQUIRE, not after -- sqlite3_open
            // can allocate a handle even when it returns non-OK (same
            // gap open_readonly's own RAII fix, above in this same
            // commit, closes in production); resetting unconditionally
            // first means a failed REQUIRE still unwinds through a live
            // owner rather than leaking `raw`.
            writer.reset(raw);
            REQUIRE(rc == SQLITE_OK);
        }
        seed::exec_or_fail(writer.get(),
                           "PRAGMA journal_mode=DELETE"); // single-file, no -wal sidecar
        seed::create_schema(writer.get());
        seed::exec_or_fail(writer.get(), "BEGIN");
        for (int i = 0; i < 300; ++i) {
            seed::insert_usage_daily(writer.get(), today_ts, "exe_" + std::to_string(i), 1, 60,
                                     now, now, 0, 0);
        }
        seed::exec_or_fail(writer.get(), "COMMIT");
        // Read the ACTUAL page size rather than assuming SQLite's default
        // (governance Gate 4 consistency-auditor NICE finding) -- a future
        // vcpkg/platform SQLite built with a different compiled-in default
        // would otherwise silently corrupt bytes outside real table data,
        // false-greening this exact regression again.
        std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> stmt{nullptr,
                                                                        &sqlite3_finalize};
        {
            sqlite3_stmt* raw_stmt = nullptr;
            REQUIRE(sqlite3_prepare_v2(writer.get(), "PRAGMA page_size", -1, &raw_stmt,
                                       nullptr) == SQLITE_OK);
            stmt.reset(raw_stmt);
        }
        REQUIRE(sqlite3_step(stmt.get()) == SQLITE_ROW);
        page_size = sqlite3_column_int64(stmt.get(), 0);
    }
    REQUIRE(page_size > 0);

    const auto file_size = fs::file_size(db_path, ec);
    REQUIRE_FALSE(ec);
    const auto corrupt_offset = page_size * 2; // page 3 (0-indexed byte offset)
    REQUIRE(file_size > static_cast<uintmax_t>(corrupt_offset)); // a 3rd page exists to corrupt

    {
        std::fstream f(db_path, std::ios::binary | std::ios::in | std::ios::out);
        REQUIRE(f.is_open());
        // Page 3+ -- past the schema page (1) and comfortably into real
        // table data, never the 100-byte file header sqlite3_open itself
        // parses.
        f.seekp(corrupt_offset);
        std::string garbage(256, '\xFF');
        f.write(garbage.data(), static_cast<std::streamsize>(garbage.size()));
        REQUIRE(f.good());
    }

    yuzu::agent::StandalonePluginContext ctx("app_usage", {{"agent.data_dir", data_dir.string()}});
    REQUIRE(plugin->descriptor->init(ctx.get()) == 0);

    yuzu::agent::LocalDispatcher dispatcher;
    const auto last_used = dispatcher.run(plugin->descriptor, "last_used");
    CHECK(last_used.rc == 1);
    const auto rows = captured_rows(last_used.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows.front().rfind("constrained|tar_db_corrupt|", 0) == 0);

    plugin->descriptor->shutdown(ctx.get());
}
