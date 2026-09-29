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
 *   - UNGUARDED (no init(), so no store path and no background thread):
 *     the S19/S20 wiring through sync/status/get/changes and both error
 *     echoes. Plugin state is process-global inside the loaded library, so
 *     every assertion is relative to state this case itself establishes
 *     (the bounded log makes `change_count|50` exact after 51+ changes).
 *   - StandalonePluginContext-seeded init() lifecycle: a corrupt snapshot
 *     plus a malformed interval fall back to defaults, sync persists, a
 *     persist failure reports CONSTRAINED/PARTIAL `asset_tags:persist_failed`
 *     with truthful rows; then a valid snapshot plus a floored interval load.
 *     Both cycles live in ONE case, in this order, because the interval is a
 *     process-global the second cycle overwrites. Each shutdown() joins the
 *     plugin's 5-second-granularity check thread, so this case costs up to
 *     ~10 s of wall clock and no assertion depends on time.
 *
 * RUNS ON ALL THREE PLATFORMS unconditionally (the plugin has no per-OS leg).
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "asset_tags_parsers.hpp"
#include "asset_tags_store.hpp"
#include "local_dispatcher.hpp"
#include "test_helpers.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::asset_tags;

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
          "escape and the bounded log (unguarded, no init)",
          "[agent][asset_tags_actions]") {
    auto plugin = load_asset_tags_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    // Start from a known cache: all four categories empty.
    REQUIRE(sync(*plugin, SyncParams{"", "", "", ""}).rc == 0);

    const std::string over_cap(kMaxValueBytes + 1, 'a');
    const std::string capped(kMaxValueBytes, 'a');
    const SyncParams first{over_cap, "a\r\nb", "Rack A|3", "x\\y"};
    auto r = sync(*plugin, first);
    CHECK(r.rc == 0);
    // No store path without init(): the write is skipped and reported OK/FULL.
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
    REQUIRE(rows.size() == 8);
    CHECK(rows[0] == "tag|role|" + capped);
    CHECK(rows[1] == "tag|environment|a  b");
    CHECK(rows[2] == "tag|location|Rack A\\|3");
    CHECK(rows[3] == "tag|service|x/y");
    CHECK(rows[4].rfind("last_sync|", 0) == 0);
    CHECK(rows[5] == "stale|false");
    CHECK(rows[6].rfind("check_interval|", 0) == 0);
    CHECK(rows[7].rfind("change_count|", 0) == 0);

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
        REQUIRE(rows.size() == 8);
        CHECK(rows[0] == "tag|role|");
        CHECK(rows[4] == "last_sync|0");
        CHECK(rows[5] == "stale|true");
        CHECK(rows[6] == "check_interval|300"); // malformed value: default kept
        CHECK(rows[7] == "change_count|0");

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
        REQUIRE(rows.size() == 8);
        CHECK(rows[0] == "tag|role|db");
        CHECK(rows[1] == "tag|environment|Production");
        CHECK(rows[2] == "tag|location|");
        CHECK(rows[3] == "tag|service|");
        CHECK(rows[4] == "last_sync|100");
        CHECK(rows[5] == "stale|false");
        CHECK(rows[6] == "check_interval|30"); // floored
        CHECK(rows[7] == "change_count|2");
    }
}
