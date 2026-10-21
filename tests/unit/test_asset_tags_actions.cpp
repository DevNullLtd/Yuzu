/**
 * test_asset_tags_actions.cpp -- loads the ACTUAL built asset_tags plugin
 * (asset_tags.dylib/.so/.dll) via PluginHandle::load and drives every action
 * through yuzu::agent::LocalDispatcher (test_app_usage_local_dispatcher.cpp's
 * pattern). Closes the gap code-review F-codex-1/-4/-5 named: the helper
 * tests stay green if the plugin stops calling the helpers, so the wiring --
 * cap, escape, bounded log, typed result status, init()-time recovery -- is
 * asserted here against the production execute()/init() paths.
 *
 * Two shapes:
 *   - NO DATA DIR (init() with no agent.data_dir, so no store path; the interval is
 *     pinned to its 30 s floor, as in the late-sync case, so a lost check-thread wakeup
 *     cannot stall a run for 300 s):
 *     the S19/S20 wiring through sync/status/get/changes and both error
 *     echoes. Plugin state is process-global inside the loaded library, and
 *     init() returns it to its defaults, so every assertion is relative to
 *     state this case itself establishes (the bounded log makes
 *     `change_count|50` exact after 51+ changes).
 *   - StandalonePluginContext-seeded init() lifecycle: a corrupt snapshot
 *     plus a malformed interval fall back to defaults, sync persists, a
 *     persist failure reports CONSTRAINED/PARTIAL `asset_tags:persist_failed`
 *     with truthful rows; then a valid snapshot plus a floored interval load.
 *     Both cycles live in ONE case, in this order. shutdown() wakes the
 *     plugin's check thread at once (the dedicated shutdown case below pins
 *     that), so this case runs in milliseconds and no assertion depends on
 *     time.
 *
 * RUNS ON ALL THREE PLATFORMS unconditionally (the plugin has no per-OS leg).
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

// Real definitions first (pragma once keeps them real inside the plugin TU
// pulled in below, where the macro never reaches them).
#include "asset_tags_parsers.hpp"
#include "asset_tags_store.hpp"
#include "local_dispatcher.hpp"
#include "test_helpers.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <expected>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::asset_tags;

namespace {

// TU-inclusion seam (precedent: test_asset_tags_sync_lock.cpp) for the typed
// WriteWarning escalation: do_sync's one persist call is renamed to a function
// that performs the REAL write and then substitutes a chosen warning, because
// fchmod/directory-fsync failures cannot be provoked on a real fd portably.
// Everything else -- the flag reads, the decision, the retained diagnostic, the
// status rows -- is the production plugin code.
std::optional<WriteWarning> g_injected_warning;

std::expected<std::optional<WriteWarning>, IoError>
test_write_state_file_atomic(const fs::path& dest, std::string_view bytes) {
    auto r = write_state_file_atomic(dest, bytes);
    if (r && g_injected_warning)
        return g_injected_warning;
    return r;
}

} // namespace

#undef YUZU_PLUGIN_EXPORT
#define YUZU_PLUGIN_EXPORT(ClassName) /* no C export in the test executable */
#define write_state_file_atomic test_write_state_file_atomic
// AssetTagsPlugin has external linkage; test_asset_tags_sync_lock.cpp includes the
// same TU into this executable, so give this copy its own class name (else the
// linker coalesces the two differing definitions -- ODR violation).
#define AssetTagsPlugin AssetTagsPluginActionsSeam
#include "asset_tags_plugin.cpp"
#undef AssetTagsPlugin
#undef write_state_file_atomic
#undef YUZU_PLUGIN_EXPORT

namespace {

AssetTagsPluginActionsSeam& tu_plugin() {
    static AssetTagsPluginActionsSeam p;
    return p;
}

int tu_execute(YuzuCommandContext* ctx, const char* action, const YuzuParam* params,
               size_t param_count) {
    yuzu::CommandContext cmd_ctx{ctx};
    yuzu::Params p{{params, param_count}};
    return tu_plugin().execute(cmd_ctx, action, p);
}

const YuzuPluginDescriptor kTuDescriptor{
    .abi_version = YUZU_PLUGIN_ABI_VERSION,
    .name = "asset_tags",
    .version = "0.1.0",
    .description = "asset_tags (TU-inclusion seam)",
    .actions = tu_plugin().actions(),
    .init = nullptr,
    .shutdown = nullptr,
    .execute = tu_execute,
    .sdk_version = YUZU_PLUGIN_SDK_VERSION,
    .action_descriptors = nullptr,
    .action_descriptor_count = 0,
};

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

// Escape-aware split: "\|" is a literal pipe (safe_output_field's escape),
// never a separator -- mirrors server/core/src/result_parsing.hpp.
std::vector<std::string> split_fields(const std::string& row) {
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

bool has_row(const std::vector<std::string>& rows, const std::string& exact) {
    for (const auto& r : rows)
        if (r == exact)
            return true;
    return false;
}

std::optional<std::string> row_with_prefix(const std::vector<std::string>& rows,
                                           const std::string& prefix) {
    for (const auto& r : rows)
        if (r.rfind(prefix, 0) == 0)
            return r;
    return std::nullopt;
}

void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) {
        FAIL("asset_tags plugin library not found under meson test -- the plugin did not build, "
             "or link_depends is not forcing it to build before this test runs");
    }
    WARN("asset_tags plugin library not found -- skipping LocalDispatcher round-trip test (run "
         "from the build root, or via `meson test`, to exercise it)");
}

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

fs::path find_asset_tags_plugin() {
    const std::string lib_name = std::string{"asset_tags"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "asset_tags" /
                                lib_name);
    }
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "asset_tags" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "asset_tags" / lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" / "asset_tags" /
                            lib_name);
    candidates.emplace_back(fs::path{"build-windows"} / "agents" / "plugins" / "asset_tags" /
                            lib_name);
    candidates.emplace_back(fs::path{"build-linux"} / "agents" / "plugins" / "asset_tags" /
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

std::optional<LoadedPlugin> load_asset_tags_plugin() {
    auto plugin_path = find_asset_tags_plugin();
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

// Owns the parameter strings for the duration of one dispatch.
struct SyncParams {
    std::string role, environment, location, service;
    std::vector<YuzuParam> raw;
    SyncParams(std::string r, std::string e, std::string l, std::string s)
        : role(std::move(r)), environment(std::move(e)), location(std::move(l)),
          service(std::move(s)) {
        raw = {{"role", role.c_str()},
               {"environment", environment.c_str()},
               {"location", location.c_str()},
               {"service", service.c_str()}};
    }
};

yuzu::agent::LocalDispatcher::Result sync(const LoadedPlugin& plugin, const SyncParams& p) {
    yuzu::agent::LocalDispatcher dispatcher;
    return dispatcher.run(plugin.descriptor, "sync", p.raw);
}

yuzu::agent::LocalDispatcher::Result run(const LoadedPlugin& plugin, const char* action,
                                         std::vector<YuzuParam> params = {}) {
    yuzu::agent::LocalDispatcher dispatcher;
    return dispatcher.run(plugin.descriptor, action, params);
}

} // namespace

TEST_CASE("asset_tags plugin: sync/status/get/changes route every field through the cap, the "
          "escape and the bounded log (no data dir)",
          "[agent][asset_tags_actions]") {
    auto plugin = load_asset_tags_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    REQUIRE(plugin->descriptor->init != nullptr);
    REQUIRE(plugin->descriptor->shutdown != nullptr);

    // init() with no agent.data_dir: the plugin's globals can outlive an earlier case (a loader
    // can keep the image mapped across dlclose), and init() is what returns them to their defaults
    // -- an empty store path, an empty cache, the default interval (#6053). With no data_dir there
    // is still no store path, so every write below is skipped.
    yuzu::agent::StandalonePluginContext ctx("asset_tags", {{"asset_tags.check_interval", "30"}});
    REQUIRE(plugin->descriptor->init(ctx.get()) == 0);
    yuzu::test::ScopeExit shutdown_on_exit{[&] { plugin->descriptor->shutdown(ctx.get()); }};

    // Start from a known cache: all four categories empty.
    REQUIRE(sync(*plugin, SyncParams{"", "", "", ""}).rc == 0);

    // The persist-failure counters are process-lifetime by design, and the plugin image can
    // survive from an earlier case (a loader can keep it mapped across dlclose), so an
    // earlier case's failure may already be counted. What this case pins is that ITS writes add
    // none: compare against the counters as they stand now, not against zero (#6053).
    auto baseline = captured_rows(run(*plugin, "status").captured);
    REQUIRE(baseline.size() == 10);
    const std::string base_failures = baseline[8];
    const std::string base_error = baseline[9];

    const std::string over_cap(kMaxValueBytes + 1, 'a');
    const std::string capped(kMaxValueBytes, 'a');
    const SyncParams first{over_cap, "a\r\nb", "Rack A|3", "x\\y"};
    auto r = sync(*plugin, first);
    CHECK(r.rc == 0);
    // No store path without a data dir: the write is skipped and reported OK/FULL.
    CHECK(r.result_status == YUZU_RESULT_STATUS_OK);
    CHECK(r.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
    CHECK(r.result_provenance.empty());

    auto rows = captured_rows(r.captured);
    REQUIRE(rows.size() == 9);
    CHECK(rows[0] == "sync|tag_added|role|" + capped);
    CHECK(rows[1] == "sync|tag_added|environment|a  b");
    CHECK(rows[2] == "sync|tag_added|location|Rack A\\|3");
    CHECK(rows[3] == "sync|tag_added|service|x/y");
    CHECK(rows[4] == "tag|role|" + capped);
    CHECK(rows[5] == "tag|environment|a  b");
    CHECK(rows[6] == "tag|location|Rack A\\|3");
    CHECK(rows[7] == "tag|service|x/y");
    CHECK(rows[8].rfind("last_sync|", 0) == 0);
    auto fields = split_fields(rows[2]);
    REQUIRE(fields.size() == 4);
    CHECK(fields[3] == "Rack A|3"); // one row, one value, pipe intact after decoding

    // Same values again: no change recorded.
    rows = captured_rows(sync(*plugin, first).captured);
    REQUIRE_FALSE(rows.empty());
    CHECK(rows[0] == "sync|no_changes");

    // status: every value row escaped, metadata shape intact.
    r = run(*plugin, "status");
    CHECK(r.rc == 0);
    rows = captured_rows(r.captured);
    REQUIRE(rows.size() == 10);
    CHECK(rows[0] == "tag|role|" + capped);
    CHECK(rows[1] == "tag|environment|a  b");
    CHECK(rows[2] == "tag|location|Rack A\\|3");
    CHECK(rows[3] == "tag|service|x/y");
    CHECK(rows[4].rfind("last_sync|", 0) == 0);
    CHECK(rows[5] == "stale|false");
    CHECK(rows[6].rfind("check_interval|", 0) == 0);
    CHECK(rows[7].rfind("change_count|", 0) == 0);
    CHECK(rows[8] == base_failures);
    CHECK(rows[9] == base_error);

    // get: value escaped; caller echo in the error row escaped; missing key.
    std::string key = "location";
    r = run(*plugin, "get", {{"key", key.c_str()}});
    CHECK(r.rc == 0);
    rows = captured_rows(r.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "tag|location|Rack A\\|3");

    key = "colour|x\n";
    r = run(*plugin, "get", {{"key", key.c_str()}});
    CHECK(r.rc == 1);
    rows = captured_rows(r.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "error|unknown category: colour\\|x ");

    r = run(*plugin, "get");
    CHECK(r.rc == 1);
    rows = captured_rows(r.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "error|missing required parameter: key");

    // Unknown action: the action name is caller text and is escaped too.
    r = run(*plugin, "bogus|x");
    CHECK(r.rc == 1);
    rows = captured_rows(r.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "unknown action: bogus\\|x");

    // changes: the location record is one 5-field row with the pipe intact.
    r = run(*plugin, "changes");
    CHECK(r.rc == 0);
    rows = captured_rows(r.captured);
    REQUIRE(rows.size() >= 2);
    auto loc = row_with_prefix(rows, "change|location||Rack A\\|3|");
    REQUIRE(loc.has_value());
    fields = split_fields(*loc);
    REQUIRE(fields.size() == 5);
    CHECK(fields[3] == "Rack A|3");
    CHECK(rows.back().rfind("total_changes|", 0) == 0);

    // Bounded log through the plugin: 51 role flips leave exactly 50 records.
    for (int i = 0; i < 51; ++i) {
        const SyncParams flip{(i % 2 == 0) ? "r1" : "r2", "", "", ""};
        REQUIRE(sync(*plugin, flip).rc == 0);
    }
    rows = captured_rows(run(*plugin, "status").captured);
    CHECK(has_row(rows, "change_count|" + std::to_string(kMaxChangeLog)));
    rows = captured_rows(run(*plugin, "changes").captured);
    REQUIRE(rows.size() == kMaxChangeLog + 1);
    for (std::size_t i = 0; i < kMaxChangeLog; ++i)
        CHECK(rows[i].rfind("change|", 0) == 0);
    CHECK(rows.back() == "total_changes|" + std::to_string(kMaxChangeLog));
}

TEST_CASE("asset_tags plugin: init() recovery, persistence and the typed sync status through "
          "the real plugin (StandalonePluginContext)",
          "[agent][asset_tags_actions]") {
    auto plugin = load_asset_tags_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    REQUIRE(plugin->descriptor->init != nullptr);
    REQUIRE(plugin->descriptor->shutdown != nullptr);

    yuzu::test::TempDir dir{"yuzu_test_asset_tags_actions_"};
    std::error_code ec;

    // The persist-failure counters are process-lifetime by design and the plugin image can
    // survive from an earlier case, so an earlier case's failure may already be counted. The
    // counters are read once, right after cycle 1's init(), and every later assertion is
    // relative to that baseline (#6053).
    std::uint64_t base_failures = 0;

    // ── Cycle 1: corrupt snapshot + malformed interval → defaults; sync
    //    persists; a persist failure is declared, never hidden. ─────────────
    {
        const fs::path data_dir = dir.path / "data";
        fs::create_directories(data_dir, ec);
        REQUIRE_FALSE(ec);
        const fs::path store = data_dir / "asset_tags.json";
        {
            std::ofstream f(store, std::ios::binary);
            f << R"({"tags":{"role":5}})"; // wrong-typed: rejected whole
        }

        yuzu::agent::StandalonePluginContext ctx(
            "asset_tags",
            {{"agent.data_dir", data_dir.string()}, {"asset_tags.check_interval", "30x"}});
        REQUIRE(plugin->descriptor->init(ctx.get()) == 0);
        // shutdown() joins the plugin's check thread; run it on every exit
        // from this block, including a fatal REQUIRE below, or an unwound
        // cycle leaves that thread alive in a dlclose'd library (PluginHandle
        // dlcloses on destruction) -- a crash, not a leak.
        yuzu::test::ScopeExit shutdown_on_exit{[&] { plugin->descriptor->shutdown(ctx.get()); }};

        auto rows = captured_rows(run(*plugin, "status").captured);
        REQUIRE(rows.size() == 10);
        CHECK(rows[0] == "tag|role|");
        CHECK(rows[4] == "last_sync|0");
        CHECK(rows[5] == "stale|true");
        CHECK(rows[6] == "check_interval|300"); // malformed value: default kept
        CHECK(rows[7] == "change_count|0");
        REQUIRE(rows[8].rfind("persist_failures|", 0) == 0);
        base_failures = std::stoull(rows[8].substr(std::string{"persist_failures|"}.size()));

        auto r = sync(*plugin, SyncParams{"db", "", "", ""});
        CHECK(r.rc == 0);
        CHECK(r.result_status == YUZU_RESULT_STATUS_OK);
        CHECK(r.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
        CHECK(r.result_provenance.empty());
        CHECK(has_row(captured_rows(r.captured), "sync|tag_added|role|db"));

        // The corrupt file was replaced by this sync's atomic write.
        auto text = read_state_file(store);
        REQUIRE(text.has_value());
        REQUIRE(text->has_value());
        auto parsed = parse_state(**text);
        REQUIRE(parsed.has_value());
        CHECK(parsed->tags.at("role") == "db");
        CHECK_FALSE(parsed->stale);

        // Make the next write fail: the data dir becomes a regular file.
        fs::remove_all(data_dir, ec);
        REQUIRE_FALSE(ec);
        {
            std::ofstream blocker(data_dir, std::ios::binary);
            blocker << "x";
        }
        REQUIRE(fs::is_regular_file(data_dir));

        r = sync(*plugin, SyncParams{"web", "", "", ""});
        CHECK(r.rc == 0); // the in-memory state advanced; the rows are truthful
        CHECK(r.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
        CHECK(r.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
        CHECK(r.result_provenance == "asset_tags:persist_failed");
        rows = captured_rows(r.captured);
        CHECK(has_row(rows, "sync|tag_changed|role|db|web"));
        CHECK(has_row(rows, "tag|role|web"));
        rows = captured_rows(run(*plugin, "status").captured);
        CHECK(has_row(rows, "tag|role|web"));
        CHECK(has_row(rows, "persist_failures|" + std::to_string(base_failures + 1)));
        // A non-empty, non-"-" message; no rows count dependence.
        const std::string err_prefix = "last_persist_error|";
        bool saw_err = false;
        for (const auto& row : rows)
            if (row.rfind(err_prefix, 0) == 0 && row.size() > err_prefix.size() &&
                row != "last_persist_error|-")
                saw_err = true;
        CHECK(saw_err);
    }

    // ── Cycle 2: a valid snapshot and a below-floor interval load. ─────────
    {
        const fs::path data_dir = dir.path / "data2";
        fs::create_directories(data_dir, ec);
        REQUIRE_FALSE(ec);

        AssetTagState seed;
        apply_sync(seed, CategoryValues{"db", "Production", "", ""}, 100);
        REQUIRE(write_state_file_atomic(data_dir / "asset_tags.json", serialize_state(seed))
                    .has_value());

        yuzu::agent::StandalonePluginContext ctx(
            "asset_tags",
            {{"agent.data_dir", data_dir.string()}, {"asset_tags.check_interval", "10"}});
        REQUIRE(plugin->descriptor->init(ctx.get()) == 0);
        yuzu::test::ScopeExit shutdown_on_exit{[&] { plugin->descriptor->shutdown(ctx.get()); }};

        auto rows = captured_rows(run(*plugin, "status").captured);
        REQUIRE(rows.size() == 10);
        CHECK(rows[0] == "tag|role|db");
        CHECK(rows[1] == "tag|environment|Production");
        CHECK(rows[2] == "tag|location|");
        CHECK(rows[3] == "tag|service|");
        CHECK(rows[4] == "last_sync|100");
        CHECK(rows[5] == "stale|false");
        CHECK(rows[6] == "check_interval|30"); // floored
        CHECK(rows[7] == "change_count|2");
        // Process-lifetime counters: cycle 1's failure is still counted.
        CHECK(rows[8] == "persist_failures|" + std::to_string(base_failures + 1));
        CHECK(rows[9] != "last_persist_error|-");
        CHECK(rows[9].rfind("last_persist_error|", 0) == 0);
    }
}

TEST_CASE("asset_tags sync: typed WriteWarning flags escalate the result status through the "
          "production do_sync path",
          "[agent][asset_tags_actions]") {
    yuzu::test::TempDir dir{"yuzu_test_asset_tags_warn_"};
    {
        std::lock_guard<std::mutex> lock(g_mu);
        g_state = {};
        g_store_path = dir.path / "asset_tags.json";
        g_persist_failures = 0;
        g_last_persist_error.clear();
    }
    yuzu::test::ScopeExit reset_globals{[] {
        std::lock_guard<std::mutex> lock(g_mu);
        g_state = {};
        g_store_path.clear();
        g_persist_failures = 0;
        g_last_persist_error.clear();
        g_injected_warning.reset();
    }};

    struct Case {
        const char* name;
        bool mode, dir;
        YuzuResultCompleteness completeness;
        const char* provenance;
        const char* row_prefix;
    };
    const Case cases[] = {
        {"mode only", true, false, YUZU_RESULT_COMPLETENESS_FULL,
         "asset_tags:persist_mode_reassert_failed", "last_persist_error|mode_reassert_failed: "},
        {"dir only", false, true, YUZU_RESULT_COMPLETENESS_FULL, "asset_tags:persist_dir_unsynced",
         "last_persist_error|dir_fsync_failed: "},
        {"both", true, true, YUZU_RESULT_COMPLETENESS_FULL, "asset_tags:persist_mode_reassert_failed",
         "last_persist_error|mode_reassert_failed+dir_fsync_failed: "},
    };

    int i = 0;
    for (const auto& c : cases) {
        INFO(c.name);
        // First cause deliberately longer than the diagnostic cap: the second
        // cause must still be visible through the typed labels.
        g_injected_warning =
            WriteWarning{std::string(kMaxValueBytes * 2, 'p') + "; fsync of d failed", c.mode, c.dir};
        const std::string role = "r" + std::to_string(i++);
        const std::array<YuzuParam, 1> params{{{"role", role.c_str()}}};

        yuzu::agent::LocalDispatcher dispatcher;
        auto r = dispatcher.run(&kTuDescriptor, "sync", params);
        CHECK(r.rc == 0);
        CHECK(r.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
        CHECK(r.result_completeness == c.completeness);
        CHECK(r.result_provenance == c.provenance);

        auto rows = captured_rows(dispatcher.run(&kTuDescriptor, "status", {}).captured);
        CHECK(has_row(rows, "persist_failures|0")); // a warning is not a failed write
        auto err = row_with_prefix(rows, "last_persist_error|");
        REQUIRE(err.has_value());
        CHECK(err->rfind(c.row_prefix, 0) == 0);
    }

    // No warning: OK/FULL again; the retained diagnostic is the last one seen.
    g_injected_warning.reset();
    const std::array<YuzuParam, 1> params{{{"role", "r-clean"}}};
    yuzu::agent::LocalDispatcher dispatcher;
    auto r = dispatcher.run(&kTuDescriptor, "sync", params);
    CHECK(r.result_status == YUZU_RESULT_STATUS_OK);
    CHECK(r.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
    CHECK(r.result_provenance.empty());
}

TEST_CASE("asset_tags status: last_persist_error is escaped by safe_output_field",
          "[agent][asset_tags_actions]") {
    yuzu::test::TempDir dir{"yuzu_test_asset_tags_escape_"};
    {
        std::lock_guard<std::mutex> lock(g_mu);
        g_state = {};
        g_store_path = dir.path / "asset_tags.json";
        g_persist_failures = 0;
        g_last_persist_error.clear();
    }
    yuzu::test::ScopeExit reset_globals{[] {
        std::lock_guard<std::mutex> lock(g_mu);
        g_state = {};
        g_store_path.clear();
        g_persist_failures = 0;
        g_last_persist_error.clear();
        g_injected_warning.reset();
    }};

    // Pipe, backslash and CR/LF are the bytes the row grammar cannot carry raw.
    g_injected_warning = WriteWarning{"a|b\\c\r\nd", false, true};
    const std::array<YuzuParam, 1> params{{{"role", "r-esc"}}};
    yuzu::agent::LocalDispatcher dispatcher;
    CHECK(dispatcher.run(&kTuDescriptor, "sync", params).rc == 0);

    auto rows = captured_rows(dispatcher.run(&kTuDescriptor, "status", {}).captured);
    auto err = row_with_prefix(rows, "last_persist_error|");
    REQUIRE(err.has_value());
    // '|' -> "\|", '\' -> '/', CR and LF -> one space each.
    CHECK(*err == "last_persist_error|dir_fsync_failed: a\\|b/c  d");
}

TEST_CASE("asset_tags plugin: shutdown() wakes the check thread at once, not after its sleep",
          "[agent][asset_tags_actions][shutdown]") {
    // The check thread waits out check_interval (default 300s). It used to do that in 5s
    // sleep_for chunks, so shutdown()'s join() cost up to ~5s. 3s is far above a woken join
    // (milliseconds) and below that old floor, so sleep-chunking goes red even on a loaded box.
    auto plugin = load_asset_tags_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::test::TempDir dir{"yuzu_test_asset_tags_shutdown_"};
    // 30s is the interval floor. Pinning it means a lost notify fails the CHECK below after ~30s,
    // instead of hanging for the 300s default until the shard's timeout kills every other case in
    // the shard with it.
    yuzu::agent::StandalonePluginContext ctx(
        "asset_tags", {{"agent.data_dir", dir.path.string()}, {"asset_tags.check_interval", "30"}});
    REQUIRE(plugin->descriptor->init(ctx.get()) == 0);
    // shutdown() joins the check thread, so run it on every exit from here, including an unwound
    // assertion; the timed call below marks it done so the guard does not repeat it.
    bool shut_down = false;
    yuzu::test::ScopeExit shutdown_on_exit{[&] {
        if (!shut_down)
            plugin->descriptor->shutdown(ctx.get());
    }};

    // Give the check thread time to reach its wait, so the notify path and not just the
    // predicate is what runs. This is a head start, not a handshake: if the runner starves the
    // worker past it, shutdown() stores the flag first, the worker skips the wait, and a deleted
    // notify_all() goes unnoticed on that run (a handshake needs a production hook, which the
    // sibling lock-ordering test avoids). shutdown() must return promptly either way.
    std::this_thread::sleep_for(std::chrono::milliseconds{250});

    const auto t0 = std::chrono::steady_clock::now();
    plugin->descriptor->shutdown(ctx.get());
    shut_down = true;
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    CHECK(elapsed < std::chrono::seconds{3});
}

TEST_CASE("asset_tags plugin: init() starts a new lifecycle from the default store path, cache "
          "and interval (#6053)",
          "[agent][asset_tags_actions][lifecycle]") {
    // The plugin's state is process-global, and within ONE loaded image a second init() sees
    // whatever the first lifecycle left behind: nothing here depends on whether a loader keeps
    // the image mapped across dlclose, because both lifecycles run against the same load. So
    // this pins init()'s reset directly, deterministically, in every order and on every
    // platform: it fails if init() stops returning the store path, the cache or the interval to
    // their defaults.
    //
    // It never makes a write fail. The persist-failure counters are process-lifetime by design
    // (the init() recovery case asserts a failure from an earlier cycle is still counted), so a
    // failing write here would leak a count into whichever case runs next.
    auto plugin = load_asset_tags_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    REQUIRE(plugin->descriptor->init != nullptr);
    REQUIRE(plugin->descriptor->shutdown != nullptr);

    yuzu::test::TempDir dir{"yuzu_test_asset_tags_lifecycle_"};
    std::error_code ec;
    const fs::path data_dir = dir.path / "data";
    fs::create_directories(data_dir, ec);
    REQUIRE_FALSE(ec);
    const fs::path store = data_dir / "asset_tags.json";

    // Lifecycle 1: a real data dir, a non-default interval, two syncs.
    std::string store_after_lifecycle_1;
    {
        yuzu::agent::StandalonePluginContext ctx(
            "asset_tags",
            {{"agent.data_dir", data_dir.string()}, {"asset_tags.check_interval", "47"}});
        REQUIRE(plugin->descriptor->init(ctx.get()) == 0);
        yuzu::test::ScopeExit shutdown_on_exit{[&] { plugin->descriptor->shutdown(ctx.get()); }};

        auto first = sync(*plugin, SyncParams{"web", "", "", ""});
        REQUIRE(first.result_status == YUZU_RESULT_STATUS_OK);
        auto second = sync(*plugin, SyncParams{"db", "", "", ""});
        REQUIRE(second.result_status == YUZU_RESULT_STATUS_OK);
        auto rows = captured_rows(run(*plugin, "status").captured);
        REQUIRE(rows.size() == 10);
        REQUIRE(rows[0] == "tag|role|db");
        REQUIRE(rows[6] == "check_interval|47");
        REQUIRE(rows[7] == "change_count|2");

        auto text = read_state_file(store);
        REQUIRE(text.has_value());
        REQUIRE(text->has_value());
        store_after_lifecycle_1 = **text;
    }

    // Lifecycle 2: no data dir and a malformed interval. Every one of lifecycle 1's leftovers
    // must be gone: the interval is the DEFAULT (not 47 -- the #6053 "malformed value: default
    // kept" symptom), the cache is empty, and a sync has no store path to write to.
    {
        yuzu::agent::StandalonePluginContext ctx("asset_tags",
                                                 {{"asset_tags.check_interval", "30x"}});
        REQUIRE(plugin->descriptor->init(ctx.get()) == 0);
        yuzu::test::ScopeExit shutdown_on_exit{[&] { plugin->descriptor->shutdown(ctx.get()); }};

        auto rows = captured_rows(run(*plugin, "status").captured);
        REQUIRE(rows.size() == 10);
        CHECK(rows[0] == "tag|role|");
        CHECK(rows[4] == "last_sync|0");
        CHECK(rows[5] == "stale|true");
        CHECK(rows[6] == "check_interval|300");
        CHECK(rows[7] == "change_count|0");
        const std::string failures = rows[8];
        const std::string error = rows[9];

        auto r = sync(*plugin, SyncParams{"cache", "", "", ""});
        CHECK(r.rc == 0);
        CHECK(r.result_status == YUZU_RESULT_STATUS_OK); // skipped, not attempted and failed
        CHECK(r.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);

        // Nothing reached lifecycle 1's store, and nothing was counted as a failure.
        auto text = read_state_file(store);
        REQUIRE(text.has_value());
        REQUIRE(text->has_value());
        CHECK(**text == store_after_lifecycle_1);
        rows = captured_rows(run(*plugin, "status").captured);
        REQUIRE(rows.size() == 10);
        CHECK(rows[8] == failures);
        CHECK(rows[9] == error);
    }
}

TEST_CASE("asset_tags plugin: a sync after shutdown() still persists to the store (#6053)",
          "[agent][asset_tags_actions][lifecycle]") {
    // The agent shuts plugins down before it drains its command pool when run() exits early, so a
    // sync still queued then runs after shutdown(). shutdown() must therefore leave the store
    // path alone: a reset there would make this sync report OK having written nothing. The
    // on-disk assertion is the load-bearing one -- the sync's own status is OK either way.
    auto plugin = load_asset_tags_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    REQUIRE(plugin->descriptor->init != nullptr);
    REQUIRE(plugin->descriptor->shutdown != nullptr);

    yuzu::test::TempDir dir{"yuzu_test_asset_tags_late_sync_"};
    std::error_code ec;
    const fs::path data_dir = dir.path / "data";
    fs::create_directories(data_dir, ec);
    REQUIRE_FALSE(ec);

    yuzu::agent::StandalonePluginContext ctx(
        "asset_tags", {{"agent.data_dir", data_dir.string()}, {"asset_tags.check_interval", "30"}});
    REQUIRE(plugin->descriptor->init(ctx.get()) == 0);
    // Runs on every exit, so a failed REQUIRE below cannot leave the check thread joinable in a
    // dlclose'd library. shutdown() is idempotent, so the explicit call below makes this a no-op.
    yuzu::test::ScopeExit shutdown_on_exit{[&] { plugin->descriptor->shutdown(ctx.get()); }};
    auto first = sync(*plugin, SyncParams{"web", "", "", ""});
    REQUIRE(first.result_status == YUZU_RESULT_STATUS_OK);
    plugin->descriptor->shutdown(ctx.get());

    auto late = sync(*plugin, SyncParams{"db", "", "", ""});
    CHECK(late.rc == 0);
    CHECK(late.result_status == YUZU_RESULT_STATUS_OK);
    CHECK(late.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);

    auto text = read_state_file(data_dir / "asset_tags.json");
    REQUIRE(text.has_value());
    REQUIRE(text->has_value());
    auto parsed = parse_state(**text);
    REQUIRE(parsed.has_value());
    CHECK(parsed->tags.at("role") == "db");
}
