/**
 * test_echo_local_dispatcher.cpp -- loads the ACTUAL built echo plugin
 * (echo.dylib/.so/.dll) via PluginHandle::load and drives init() + status
 * through LocalDispatcher / StandalonePluginContext (with a real KvStore, so
 * the plugin's heartbeat.* publish is observable).
 *
 * Covers the #1567 chain the pure-part tests cannot: corrupt echo.db at boot ->
 * quarantine -> db_health status line -> reconcile into the heartbeat KV keys
 * (idempotent replay) -> the #1846 status keys. Unguarded on every OS.
 *
 * Also pins the default-on contract at the plugin seam the unit-test exe cannot
 * reach (echo_plugin.cpp is not linked there): no `<src>_enabled` seed at init, the
 * destructive purge refusing an unreadable enable flag, and `snapshot` reporting partial.
 */
#include <catch2/catch_test_macros.hpp>

#include <sqlite3.h>

#include <yuzu/agent/kv_store.hpp>
#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"
#include "test_helpers.hpp"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

fs::path find_echo_plugin() {
    const std::string lib_name = std::string{"echo"} + kPluginExt;
    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT"))
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "echo" / lib_name);
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "echo" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "echo" / lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" / "echo" / lib_name);
    candidates.emplace_back(fs::path{"build-windows"} / "agents" / "plugins" / "echo" / lib_name);
    candidates.emplace_back(fs::path{"build-linux"} / "agents" / "plugins" / "echo" / lib_name);
    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec)
            return fs::absolute(p, ec);
    }
    return {};
}

std::vector<std::string> rows_of(const std::string& captured) {
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

std::optional<std::string> row_with_prefix(const std::vector<std::string>& rows,
                                           const std::string& p) {
    for (const auto& r : rows)
        if (r.rfind(p, 0) == 0)
            return r;
    return std::nullopt;
}

// Registered capture sources: one `<src>_last_status` health line each. The registry source
// is the 17th (Windows-only, but its health lines are emitted on every OS). Not derived from
// capture_sources(): that table lives in a TU this executable does not link.
constexpr std::size_t kEchoSourceCount = 17;

size_t count_containing(const std::vector<std::string>& rows, const std::string& needle) {
    size_t n = 0;
    for (const auto& r : rows)
        if (r.find(needle) != std::string::npos)
            ++n;
    return n;
}

// Count the `<src>_enabled` rows init left in echo_config (raw read, no plugin code).
int enabled_rows_in(const fs::path& db_path) {
    yuzu::test::SqliteHandleOwner<sqlite3> owner;
    REQUIRE(sqlite3_open_v2(db_path.string().c_str(), &owner.db, SQLITE_OPEN_READONLY, nullptr) ==
            SQLITE_OK);
    // sqlite3_exec with a callback: no statement handle to finalize on a failing REQUIRE.
    int n = -1;
    REQUIRE(sqlite3_exec(
                owner.db,
                "SELECT count(*) FROM echo_config WHERE key LIKE '%\\_enabled' ESCAPE '\\'",
                [](void* out, int, char** vals, char**) {
                    *static_cast<int*>(out) = std::atoi(vals[0]);
                    return 0;
                },
                &n, nullptr) == SQLITE_OK);
    return n;
}

// Make ONLY the read of `echo_config.value` for `key` fail (at step), from a second
// connection to the plugin's open echo.db; every other key still reads. `value`
// becomes a VIRTUAL generated column whose expression overflows for that one key; the
// expression is row-dependent, so a stored value is written first (init stores none).
// (Same technique as make_config_key_unreadable in test_echo_aggregator.cpp.)
void make_config_key_unreadable(const fs::path& db_path, const std::string& key) {
    yuzu::test::SqliteHandleOwner<sqlite3> owner;
    REQUIRE(sqlite3_open(db_path.string().c_str(), &owner.db) == SQLITE_OK);
    sqlite3_busy_timeout(owner.db, 5000);
    const auto sql =
        std::format("INSERT INTO echo_config (key, value) VALUES ('{0}', 'true') "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value; "
                    "ALTER TABLE echo_config RENAME COLUMN value TO value_raw; "
                    "ALTER TABLE echo_config ADD COLUMN value TEXT GENERATED ALWAYS AS "
                    "(CASE WHEN key = '{0}' THEN abs(-9223372036854775808 + 0 * length(key)) "
                    "ELSE value_raw END) VIRTUAL;",
                    key);
    REQUIRE(sqlite3_exec(owner.db, sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK);
}

} // namespace

TEST_CASE("echo plugin: corrupt boot quarantines, publishes the fleet signal, status reports it",
          "[echo][local_dispatcher][corruption]") {
    const auto plugin_path = find_echo_plugin();
    if (plugin_path.empty()) {
        if (std::getenv("MESON_BUILD_ROOT") != nullptr)
            FAIL("echo plugin library not found under meson test");
        WARN("echo plugin library not found -- skipping (run from the build root or via meson test)");
        return;
    }
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    REQUIRE(handle.has_value());
    const auto* desc = handle->descriptor();
    REQUIRE(desc != nullptr);
    REQUIRE(desc->init != nullptr);

    yuzu::test::TempDir dir_guard{"yuzu_test_echo_local_"};
    std::error_code ec;
    fs::create_directories(dir_guard.path, ec);
    auto kv = yuzu::agent::KvStore::open(dir_guard.path / "kv_store.db");
    REQUIRE(kv.has_value());

    SECTION("corrupt echo.db -> one quarantine file, db_health, KV publish, idempotent replay") {
        {
            std::ofstream bad(dir_guard.path / "echo.db", std::ios::binary);
            bad << std::string(8192, 'X'); // not a SQLite file
        }
        {
            yuzu::agent::StandalonePluginContext ctx("echo", {{"agent.data_dir", dir_guard.path.string()}},
                                                     &*kv);
            CHECK(desc->init(ctx.get()) == 0);

            size_t quarantined_files = 0;
            std::string quarantine_name;
            for (const auto& e : fs::directory_iterator(dir_guard.path))
                if (e.path().filename().string().rfind("echo.db.corrupt-", 0) == 0) {
                    ++quarantined_files;
                    quarantine_name = e.path().filename().string();
                }
            CHECK(quarantined_files == 1);

            yuzu::agent::LocalDispatcher d;
            const auto rows = rows_of(d.run(desc, "status").captured);
            const auto health = row_with_prefix(rows, "db_health|quarantined|");
            REQUIRE(health.has_value());
            const auto epoch = health->substr(std::string{"db_health|quarantined|"}.size());
            CHECK(row_with_prefix(rows, "config|perf_capture_method|").has_value());
            CHECK(row_with_prefix(rows, "config|procperf_procs_seen|").has_value());
            CHECK(count_containing(rows, "_last_status|") == kEchoSourceCount);
            CHECK(count_containing(rows, "_last_status_at|") == kEchoSourceCount);
            CHECK(count_containing(rows, "_consecutive_failures|") == kEchoSourceCount);

            CHECK(kv->get("echo", "heartbeat.db_corruption_total") == std::optional<std::string>{"1"});
            const auto last = kv->get("echo", "heartbeat.db_quarantine_last");
            REQUIRE(last.has_value());
            CHECK(last == std::optional<std::string>{epoch + ":" + quarantine_name});
            desc->shutdown(ctx.get());

            // Second init on the same data dir: replay is idempotent.
            yuzu::agent::StandalonePluginContext ctx2("echo", {{"agent.data_dir", dir_guard.path.string()}},
                                                      &*kv);
            REQUIRE(desc->init(ctx2.get()) == 0);
            CHECK(kv->get("echo", "heartbeat.db_corruption_total") == std::optional<std::string>{"1"});
            CHECK(kv->get("echo", "heartbeat.db_quarantine_last") == last);
            desc->shutdown(ctx2.get());
        }
    }

    SECTION("failed `last` publish is not re-counted; counter advances once per quarantine") {
        const auto quarantine_basenames = [&] {
            std::vector<std::string> names;
            for (const auto& e : fs::directory_iterator(dir_guard.path)) {
                const auto n = e.path().filename().string();
                if (n.rfind("echo.db.corrupt-", 0) == 0)
                    names.push_back(n);
            }
            // directory_iterator order is unspecified, not creation order. The
            // `.corrupt-<epoch>[-n]` basenames are fixed-width-epoch and sort
            // lexicographically == chronologically (quarantine_corrupt_db's own
            // disambiguator picks '-1', '-2', ... which also sort after the
            // bare epoch), so a plain sort recovers a deterministic oldest-first
            // order for names[0]/names[1] below.
            std::sort(names.begin(), names.end());
            return names;
        };
        const auto corrupt_db = [&] {
            std::ofstream bad(dir_guard.path / "echo.db", std::ios::binary | std::ios::trunc);
            bad << std::string(8192, 'X');
        };
        const auto init_shutdown = [&] {
            yuzu::agent::StandalonePluginContext ctx("echo", {{"agent.data_dir", dir_guard.path.string()}},
                                                     &*kv);
            REQUIRE(desc->init(ctx.get()) == 0);
            desc->shutdown(ctx.get());
        };

        // Block only the `last` key on the kv table (INSERT and UPDATE).
        // Owner declared before the open: sqlite3_open populates the handle even on
        // failure, so a failing REQUIRE still unwinds through a live owner.
        yuzu::test::SqliteHandleOwner<sqlite3> owner;
        REQUIRE(sqlite3_open((dir_guard.path / "kv_store.db").string().c_str(), &owner.db) ==
                SQLITE_OK);
        const auto exec = [&](const char* sql) {
            return sqlite3_exec(owner.db, sql, nullptr, nullptr, nullptr) == SQLITE_OK;
        };
        REQUIRE(exec("CREATE TRIGGER block_last_ins BEFORE INSERT ON kv_store "
                     "WHEN NEW.key = 'heartbeat.db_quarantine_last' "
                     "BEGIN SELECT RAISE(ABORT, 'blocked'); END;"));
        REQUIRE(exec("CREATE TRIGGER block_last_upd BEFORE UPDATE ON kv_store "
                     "WHEN NEW.key = 'heartbeat.db_quarantine_last' "
                     "BEGIN SELECT RAISE(ABORT, 'blocked'); END;"));

        corrupt_db();
        init_shutdown();
        init_shutdown(); // replay with `last` still failing: must not re-increment
        CHECK(kv->get("echo", "heartbeat.db_corruption_total") == std::optional<std::string>{"1"});
        CHECK_FALSE(kv->get("echo", "heartbeat.db_quarantine_last").has_value());

        REQUIRE(exec("DROP TRIGGER block_last_ins"));
        REQUIRE(exec("DROP TRIGGER block_last_upd"));
        init_shutdown();
        auto names = quarantine_basenames();
        REQUIRE(names.size() == 1);
        const auto first_last = kv->get("echo", "heartbeat.db_quarantine_last");
        REQUIRE(first_last.has_value());
        CHECK(first_last->ends_with(":" + names[0]));
        CHECK(kv->get("echo", "heartbeat.db_corruption_total") == std::optional<std::string>{"1"});

        // A second quarantine advances the counter exactly once and `last` names the newer file.
        corrupt_db();
        init_shutdown();
        names = quarantine_basenames();
        CHECK(names.size() == 2);
        CHECK(kv->get("echo", "heartbeat.db_corruption_total") == std::optional<std::string>{"2"});
        const auto second_last = kv->get("echo", "heartbeat.db_quarantine_last");
        REQUIRE(second_last.has_value());
        CHECK(second_last != first_last);
        bool names_a_listed_file = false;
        for (const auto& n : names)
            if (second_last->ends_with(":" + n) &&
                n != first_last->substr(first_last->find(':') + 1))
                names_a_listed_file = true;
        CHECK(names_a_listed_file);

        // Only the two bridged heartbeat keys exist: the private ledger is not
        // `heartbeat.`-prefixed.
        auto hb = kv->list("echo", "heartbeat.");
        std::sort(hb.begin(), hb.end());
        CHECK(hb == std::vector<std::string>{"heartbeat.db_corruption_total",
                                             "heartbeat.db_quarantine_last"});

        // An unreadable ledger is warn-only: never overwritten, count not reset.
        REQUIRE(kv->set("echo", "db_health.ledger", "garbage"));
        init_shutdown();
        CHECK(kv->get("echo", "db_health.ledger") == std::optional<std::string>{"garbage"});
        CHECK(kv->get("echo", "heartbeat.db_corruption_total") == std::optional<std::string>{"2"});
    }

    SECTION("a torn `total` publish withholds the identity: never a stale total with a newer last") {
        const auto quarantine_basenames = [&] {
            std::vector<std::string> names;
            for (const auto& e : fs::directory_iterator(dir_guard.path)) {
                const auto n = e.path().filename().string();
                if (n.rfind("echo.db.corrupt-", 0) == 0)
                    names.push_back(n);
            }
            // directory_iterator order is unspecified, not creation order. The
            // `.corrupt-<epoch>[-n]` basenames are fixed-width-epoch and sort
            // lexicographically == chronologically (quarantine_corrupt_db's own
            // disambiguator picks '-1', '-2', ... which also sort after the
            // bare epoch), so a plain sort recovers a deterministic oldest-first
            // order for names[0]/names[1] below.
            std::sort(names.begin(), names.end());
            return names;
        };
        const auto corrupt_db = [&] {
            std::ofstream bad(dir_guard.path / "echo.db", std::ios::binary | std::ios::trunc);
            bad << std::string(8192, 'X');
        };
        const auto init_shutdown = [&] {
            yuzu::agent::StandalonePluginContext ctx("echo", {{"agent.data_dir", dir_guard.path.string()}},
                                                     &*kv);
            REQUIRE(desc->init(ctx.get()) == 0);
            desc->shutdown(ctx.get());
        };

        // First quarantine publishes cleanly.
        corrupt_db();
        init_shutdown();
        auto names = quarantine_basenames();
        REQUIRE(names.size() == 1);
        const auto first_last = kv->get("echo", "heartbeat.db_quarantine_last");
        REQUIRE(first_last.has_value());
        CHECK(first_last->ends_with(":" + names[0]));
        CHECK(kv->get("echo", "heartbeat.db_corruption_total") == std::optional<std::string>{"1"});

        // Block only the `total` key on the kv table (INSERT and UPDATE).
        yuzu::test::SqliteHandleOwner<sqlite3> owner;
        REQUIRE(sqlite3_open((dir_guard.path / "kv_store.db").string().c_str(), &owner.db) ==
                SQLITE_OK);
        const auto exec = [&](const char* sql) {
            return sqlite3_exec(owner.db, sql, nullptr, nullptr, nullptr) == SQLITE_OK;
        };
        REQUIRE(exec("CREATE TRIGGER block_total_ins BEFORE INSERT ON kv_store "
                     "WHEN NEW.key = 'heartbeat.db_corruption_total' "
                     "BEGIN SELECT RAISE(ABORT, 'blocked'); END;"));
        REQUIRE(exec("CREATE TRIGGER block_total_upd BEFORE UPDATE ON kv_store "
                     "WHEN NEW.key = 'heartbeat.db_corruption_total' "
                     "BEGIN SELECT RAISE(ABORT, 'blocked'); END;"));

        // Second quarantine: the ledger advances but `total` cannot publish, so
        // `last` must be withheld too -- never a stale total paired with a
        // newer identity.
        corrupt_db();
        init_shutdown();
        names = quarantine_basenames();
        REQUIRE(names.size() == 2);
        CHECK(kv->get("echo", "heartbeat.db_corruption_total") == std::optional<std::string>{"1"});
        CHECK(kv->get("echo", "heartbeat.db_quarantine_last") == first_last); // identity withheld

        REQUIRE(exec("DROP TRIGGER block_total_ins"));
        REQUIRE(exec("DROP TRIGGER block_total_upd"));
        init_shutdown();
        CHECK(kv->get("echo", "heartbeat.db_corruption_total") == std::optional<std::string>{"2"});
        const auto second_last = kv->get("echo", "heartbeat.db_quarantine_last");
        REQUIRE(second_last.has_value());
        CHECK(second_last->ends_with(":" + names[1]));
    }

    SECTION("clean boot -> db_health|ok|0") {
        yuzu::agent::StandalonePluginContext ctx("echo", {{"agent.data_dir", dir_guard.path.string()}}, &*kv);
        REQUIRE(desc->init(ctx.get()) == 0);
        yuzu::agent::LocalDispatcher d;
        const auto rows = rows_of(d.run(desc, "status").captured);
        CHECK(row_with_prefix(rows, "db_health|ok|0").has_value());
        CHECK_FALSE(kv->get("echo", "heartbeat.db_corruption_total").has_value());
        desc->shutdown(ctx.get());
    }
}

TEST_CASE("echo plugin: every source is enabled by default with no stored flag; an unreadable flag "
          "refuses a purge and makes a snapshot partial",
          "[echo][local_dispatcher][default-on]") {
    const auto plugin_path = find_echo_plugin();
    if (plugin_path.empty()) {
        if (std::getenv("MESON_BUILD_ROOT") != nullptr)
            FAIL("echo plugin library not found under meson test");
        WARN("echo plugin library not found -- skipping (run from the build root or via meson test)");
        return;
    }
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    REQUIRE(handle.has_value());
    const auto* desc = handle->descriptor();
    REQUIRE(desc != nullptr);
    REQUIRE(desc->init != nullptr);

    yuzu::test::TempDir dir_guard{"yuzu_test_echo_local_"};
    std::error_code ec;
    fs::create_directories(dir_guard.path, ec);
    auto kv = yuzu::agent::KvStore::open(dir_guard.path / "kv_store.db");
    REQUIRE(kv.has_value());
    yuzu::agent::StandalonePluginContext ctx("echo", {{"agent.data_dir", dir_guard.path.string()}},
                                             &*kv);
    REQUIRE(desc->init(ctx.get()) == 0);
    const auto db_path = dir_guard.path / "echo.db";
    yuzu::agent::LocalDispatcher d;

    SECTION("a fresh init seeds no flag; formerly opt-in sources read enabled and run") {
        // init used to write `<src>_enabled=false` for four of these; the registry
        // default now supplies "true", so a fresh data dir stores nothing.
        CHECK(enabled_rows_in(db_path) == 0);

        // `registry` is Windows-only, but status lists every registered source's flag on
        // every OS (unsupported ones record nothing), so it is asserted here everywhere.
        const auto rows = rows_of(d.run(desc, "status").captured);
        for (const char* src :
             {"module", "software", "netconn", "mapdrive", "netqual", "procperf", "registry"}) {
            INFO("source=" << src);
            CHECK(row_with_prefix(rows, std::format("config|{}_enabled|true", src)).has_value());
        }
        CHECK(count_containing(rows, "source_disabled") == 0);

        // The registry source's eleven health keys are always present, at their "not
        // running" defaults before any tick has written them.
        for (const char* kv : {"registry_capture_method|none", "registry_watch_roots|0",
                               "registry_watch_roots_unarmed|0", "registry_roots_unreadable|0",
                               "registry_roots_capped|0", "registry_etw_events|0",
                               "registry_etw_dropped|0", "registry_etw_lost|0",
                               "registry_attr_attributed|0", "registry_attr_ambiguous|0",
                               "registry_attr_none|0"}) {
            INFO("key=" << kv);
            const auto expected = std::format("config|{}", kv);
            CHECK(row_with_prefix(rows, expected) == std::optional<std::string>{expected});
        }

        // The per-app leg of collect_perf is gated on source_enabled("procperf"):
        // with no stored flag it must run (baseline / unsupported_platform /
        // counters_unavailable by OS), never report source_disabled.
        const auto perf = rows_of(d.run(desc, "collect_perf").captured);
        const auto leg = row_with_prefix(perf, "echo|collect_procperf|");
        REQUIRE(leg.has_value());
        CHECK_FALSE(leg->ends_with("|source_disabled"));
    }

    SECTION("purge_source refuses when the enable flag cannot be read") {
        make_config_key_unreadable(db_path, "module_enabled");

        const YuzuParam module_params[] = {{"source", "module"}};
        const auto refused = d.run(desc, "purge_source", module_params);
        CHECK(refused.rc == 1);
        CHECK(refused.captured.find("error|config_unreadable") != std::string::npos);

        // Control: a source whose flag still reads is refused for the OTHER reason
        // (enabled by default), so the first refusal is the unreadable-flag guard.
        const YuzuParam process_params[] = {{"source", "process"}};
        const auto control = d.run(desc, "purge_source", process_params);
        CHECK(control.rc == 1);
        CHECK(control.captured.find("error|source_not_paused") != std::string::npos);
    }

    SECTION("snapshot reports partial, not complete, when an enable flag cannot be read") {
        // An unreadable flag skips its source through skip_token() and never raises
        // IncompleteCaptureError, so only the flag read in do_snapshot can name it.
        make_config_key_unreadable(db_path, "module_enabled");

        const auto snap = d.run(desc, "snapshot");
        CHECK(snap.rc != 0);
        const auto line = row_with_prefix(rows_of(snap.captured), "echo|snapshot|");
        REQUIRE(line.has_value());
        CHECK(line->starts_with("echo|snapshot|partial|"));
        CHECK(line->find("module") != std::string::npos);
    }

    desc->shutdown(ctx.get());
}
